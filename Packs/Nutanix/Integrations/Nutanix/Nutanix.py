from typing import Dict

import dateutil.parser as dp
import pytz
import urllib3
from collections import OrderedDict

from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()
''' CONSTANTS '''
CONTENT_JSON = {'content-type': 'application/json'}

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

    def fetch_incidents(self, auto_resolved: Optional[bool], resolved: Optional[bool], acknowledged: Optional[bool],
                        alert_type_ids: Optional[str], entity_ids: Optional[str], impact_types: Optional[str],
                        classifications: Optional[str], entity_type_ids: Optional[str]):
        return self._http_request(
            method='GET',
            url_suffix='alerts',
            params=assign_params(
                resolved=resolved,
                auto_resolved=auto_resolved,
                acknowledged=acknowledged,
                alert_type_uuid=alert_type_ids,
                entity_ids=entity_ids,
                impact_types=impact_types,
                classification=classifications,
                entity_type_id=entity_type_ids
            )
        )

    def get_nutanix_hypervisor_hosts_list(self, filter_: Optional[str], limit: Optional[int], page: Optional[int]):
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

    def nutanix_hypervisor_vm_power_status_change(self, uuid: str, host_uuid: Optional[str], transition: str):
        return self._http_request(
            method='POST',
            url_suffix=f'vms/{uuid}/set_power_state',
            headers=CONTENT_JSON,
            json_data=assign_params(
                uuid=uuid,
                host_uuid=host_uuid,
                transition=transition
            )
        )

    def nutanix_hypervisor_task_poll(self, completed_tasks: List[str], timeout_interval: Optional[int]):
        return self._http_request(
            method='POST',
            url_suffix='tasks/poll',
            headers=CONTENT_JSON,
            json_data=assign_params(
                completed_tasks=completed_tasks,
                timeout_interval=timeout_interval
            )
        )

    def get_nutanix_alerts_list(self, start_time: Optional[int], end_time: Optional[int], resolved: Optional[bool],
                                auto_resolved: Optional[bool], acknowledged: Optional[bool], severity: Optional[str],
                                alert_type_ids: Optional[str], entity_ids: Optional[str], impact_types: Optional[str],
                                classifications: Optional[str], entity_types: Optional[str], page: Optional[int],
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
                entity_ids=entity_ids,
                impact_types=impact_types,
                classification=classifications,
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
                                                  severity: Optional[str],
                                                  impact_types: Optional[str], classifications: Optional[str],
                                                  entity_types: Optional[str],
                                                  entity_type_ids: Optional[str], limit: Optional[int]):
        return self._http_request(
            method='POST',
            url_suffix='alerts/acknowledge',
            params=assign_params(
                start_time_in_usecs=start_time,
                end_time_in_usecs=end_time,
                severity=severity,
                impact_types=impact_types,
                classification=classifications,
                entity_type=entity_types,
                entity_type_ids=entity_type_ids,
                count=limit
            )
        )

    def post_nutanix_alerts_resolve_by_filter(self, start_time: Optional[int], end_time: Optional[int],
                                              severity: Optional[str], impact_types: Optional[str],
                                              classifications: Optional[str], entity_types: Optional[str],
                                              entity_type_ids: Optional[str], limit: Optional[int]):
        return self._http_request(
            method='POST',
            url_suffix='alerts/resolve',
            params=assign_params(
                start_time_in_usecs=start_time,
                end_time_in_usecs=end_time,
                severity=severity,
                impact_types=impact_types,
                classification=classifications,
                entity_type=entity_types,
                entity_type_ids=entity_type_ids,
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
        - If argument is does not exist, returns None.
        - If argument is exists and is between min to max, returns argument.
        - If argument is exists and is not between min to max, raises DemistoException.

    """
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


def fetch_incidents_command(client: Client, params: Dict, last_run: Dict):
    auto_resolved = get_optional_boolean_param(params, 'auto_resolved')
    resolved = True if auto_resolved else get_optional_boolean_param(params, 'resolved')
    acknowledged = get_optional_boolean_param(params, 'acknowledged')
    alert_type_ids = params.get('alert_type_ids')
    entity_ids = params.get('entity_ids')  # TODO MAYBE DELETE
    impact_types = params.get('impact_types')
    classifications = params.get('classifications')
    entity_type_ids = params.get('entity_type_ids')  # TODO MAYBE DELETE

    response = client.fetch_incidents(auto_resolved, resolved, acknowledged, alert_type_ids, entity_ids, impact_types,
                                      classifications, entity_type_ids)

    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch = last_run.get('last_fetch', None)
    # Handle first fetch time
    if last_fetch is None:
        # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time
    else:
        # otherwise use the stored last fetch
        last_fetch = int(last_fetch)

    # for type checking, making sure that latest_created_time is int
    latest_created_time = cast(int, last_fetch)

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    raise NotImplementedError


def nutanix_hypervisor_hosts_list_command(client: Client, args: Dict):
    """
    Gets a list all physical hosts configured in the cluster by Nutanix service.
    Possible filters:
    - page: The offset page to start retrieving hosts.
    - limit: The number of hosts to retrieve.
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
    limit = get_and_validate_int_argument(args, 'limit', minimum=MINIMUM_LIMIT_VALUE, maximum=MAXIMUM_LIMIT_VALUE)
    page = get_page_argument(args)

    response = client.get_nutanix_hypervisor_hosts_list(filter_, limit, page)

    unprocessed_outputs = response.get('entities')

    if unprocessed_outputs is None:
        raise DemistoException('Unexpected response for nutanix-hypervisor-hosts-list command')

    outputs_processed = []

    for unprocessed_output in unprocessed_outputs:
        unordered_disk_configs = unprocessed_output['disk_hardware_configs']
        ordered_disk_configs = dict(sorted(unordered_disk_configs.items()))
        ordered_disk_list = [disk_config for _, disk_config in ordered_disk_configs.items() if disk_config is not None]
        unprocessed_output['disk_hardware_configs'] = ordered_disk_list

        del(unprocessed_output['stats'])
        del(unprocessed_output['usage_stats'])

        output_processed = {k: v for k, v in unprocessed_output.items() if v is not None}
        outputs_processed.append(output_processed)

    return CommandResults(
        outputs_prefix='NutanixHypervisor.Host',
        outputs_key_field='uuid',
        outputs=response['entities']
    )


def nutanix_hypervisor_vms_list_command(client: Client, args: Dict):
    """
    Gets a list all virtual machines by Nutanix service.
    Possible filters:
    - offset: The offset to start retrieving virtual machines.
    - length: The number of virtual machines to retrieve.
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
    length = get_and_validate_int_argument(args, 'length', minimum=MINIMUM_LENGTH_VALUE)

    response = client.get_nutanix_hypervisor_vms_list(filter_, offset, length)

    if response.get('entities') is None:
        raise DemistoException('No entities were found in response for nutanix-hypervisor-vms-list command')

    return CommandResults(
        outputs_prefix='NutanixHypervisor.VM',
        outputs_key_field='uuid',
        outputs=response['entities']
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

    response = client.nutanix_hypervisor_vm_power_status_change(vm_uuid, host_uuid, transition)

    return CommandResults(
        outputs_prefix='NutanixHypervisor.VMPowerStatus',
        outputs_key_field='task_uuid',
        outputs=response
    )


def nutanix_hypervisor_task_poll_command(client: Client, args: Dict):
    """
    Poll tasks given by task_ids to check if they are ready.
    Returns all the tasks from 'task_ids' list that are ready at the moment
    Nutanix service was polled.
    In case no task is ready, waits until at least one task is ready, unless given
    argument 'timeout_interval' which waits time_interval seconds and in case no task
    had finished, returns a time out response.

    In case response was successful, response will be a dict containing key 'completed_tasks_info'
    which holds details about every completed task returned by Nutanix service.
    In case response timed out, response will be a dict {'timed_out': True}.

    Args:
        client (Client): Client object to perform request.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """

    task_ids = argToList(args.get('task_ids'))
    timeout_interval = arg_to_number(args.get('timeout_interval'), 'timeout_interval')
    if not task_ids:
        raise DemistoException('Task ids for command nutanix_hypervisor_task_poll_command cannot be empty.')

    response = client.nutanix_hypervisor_task_poll(task_ids, timeout_interval)

    maybe_time_out = response.get('timed_out')

    if response.get('completed_tasks_info') is not None:
        outputs_key_field: Optional[str] = 'uuid'
        outputs = response['completed_tasks_info']
    elif maybe_time_out and argToBoolean(maybe_time_out):
        outputs_key_field = None
        outputs = response
    else:
        raise DemistoException('Unexpected response returned by Nutanix for nutanix-hypervisor-task-poll command')

    return CommandResults(
        outputs_prefix='NutanixHypervisor.Task',
        outputs_key_field=outputs_key_field,
        outputs=outputs
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
    - entity_ids: TODO.
    - impact_types: Retrieve alerts that their impact type matches one of the impact_type in impact_types list.
                    Possible impact types: [Availability, Capacity, Configuration, Performance, SystemIndicator]
                    For example, alert 'Incorrect NTP Configuration' has impact type 'SystemIndicator'.
                    Given Impact Types = 'SystemIndicator',only alerts with impact type 'SystemIndicator',
                    such as 'Incorrect NTP Configuration' will be retrieved.
    - classifications: Retrieve alerts that their classifications matches one of the classification in
                      classifications list given.
                      For example, alert 'Pulse cannot connect to REST server endpoint' has classification of Cluster.
                      Given classifications = 'cluster', only alerts with classification of 'cluster', such as
                      'Pulse cannot connect to REST server endpoint' will be retrieved.
    - entity_types: Retrieve alerts that their entity_type matches one of the entity_type in entity_types list.
                   Examples for entity types: [VM, Host, Disk, Storage Container, Cluster].
                   If Nutanix service can't recognize the entity type, it returns 404 response.
    - page: The offset of page number in the query response to start retrieving alerts.
    - limit: Maximum number of alerts to retrieve.

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
    resolved = True if auto_resolved else get_optional_boolean_param(args, 'resolved')
    acknowledged = get_optional_boolean_param(args, 'acknowledged')
    severity = args.get('severity')
    alert_type_ids = args.get('alert_type_ids')
    entity_ids = args.get('entity_ids')
    impact_types = args.get('impact_types')
    classification = args.get('classifications')
    entity_types = args.get('entity_types')
    page = get_page_argument(args)
    limit = get_and_validate_int_argument(args, 'limit', minimum=MINIMUM_LIMIT_VALUE, maximum=MAXIMUM_LIMIT_VALUE)

    response = client.get_nutanix_alerts_list(start_time, end_time, resolved, auto_resolved, acknowledged, severity,
                                              alert_type_ids, entity_ids, impact_types, classification,
                                              entity_types,
                                              page, limit)

    if response.get('entities') is None:
        raise DemistoException('No entities were found in response for nutanix-alerts-list command')

    return CommandResults(
        outputs_prefix='NutanixHypervisor.Alerts',
        outputs_key_field='id',
        outputs=response['entities']
    )


def nutanix_alert_acknowledge_command(client: Client, args: Dict):
    """
    Acknowledge alert with the specified alert_id.

    In case response was successful, response will be a dict
    {'id': str, 'successful': bool, 'message': Optional[str]}
    In case of an invalid alert id, status code 422 - UNPROCESSABLE ENTITY
    will be returned by Nutanix service.

    Args:
        client (Client): Client object to perform request.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    alert_id = args.get('alert_id', '')

    response = client.post_nutanix_alert_acknowledge(alert_id)

    return CommandResults(
        outputs_prefix='NutanixHypervisor.Alert',
        outputs_key_field='id',
        outputs=response
    )


def nutanix_alert_resolve_command(client: Client, args: Dict):
    """
    Resolve alert with the specified alert_id.

    In case response was successful, response will be a dict
    {'id': str, 'successful': bool, 'message': Optional[str]}.
    In case of an invalid alert id, status code 422 - UNPROCESSABLE ENTITY
    will be returned by Nutanix service.

    Args:
        client (Client): Client object to perform request.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    alert_id = args.get('alert_id', '')

    response = client.post_nutanix_alert_resolve(alert_id)

    return CommandResults(
        outputs_prefix='NutanixHypervisor.Alert',
        outputs_key_field='id',
        outputs=response
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
    - classifications: Retrieve alerts that their classifications matches one of the classification in
                      classifications list given.
                      For example, alert 'Pulse cannot connect to REST server endpoint' has classification of Cluster.
                      Given classifications = 'cluster', only alerts with classification of 'cluster', such as
                      'Pulse cannot connect to REST server endpoint' will be acknowledged.
    - entity_types: Acknowledge alerts that their entity_type matches one of the entity_type in entity_types list.
                   Example for entity types: [VM, Host, Disk, Storage Container, Cluster].
                   If Nutanix service can't recognize the entity type, it returns 404 response.
    - entity_type_id: TODO maybe delete
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
    classification = args.get('classifications')
    entity_types = args.get('entity_types')
    entity_type_ids = args.get('entity_type_ids')
    limit = get_and_validate_int_argument(args, 'limit', minimum=MINIMUM_LIMIT_VALUE)

    response = client.post_nutanix_alerts_acknowledge_by_filter(start_time, end_time, severity, impact_types,
                                                                classification, entity_types, entity_type_ids,
                                                                limit)

    return CommandResults(
        outputs_prefix='NutanixHypervisor.Alert',
        outputs=response
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
    - classifications: Resolve alerts that their classifications matches one of the classification in
                      classifications list given.
                      For example, alert 'Pulse cannot connect to REST server endpoint' has classification of Cluster.
                      Given classifications = 'cluster', only alerts with classification of 'cluster', such as
                      'Pulse cannot connect to REST server endpoint' will be resolved.
    - entity_types: Resolve alerts that their entity_type matches one of the entity_type in entity_types list.
                   Example for entity types: [VM, Host, Disk, Storage Container, Cluster].
                   If Nutanix service can't recognize the entity type, it returns 404 response.
    - entity_type_id: TODO maybe delete
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
    classification = args.get('classifications')
    entity_types = args.get('entity_types')
    entity_type_ids = args.get('entity_type_ids')
    limit = get_and_validate_int_argument(args, 'limit', minimum=MINIMUM_LIMIT_VALUE)

    response = client.post_nutanix_alerts_resolve_by_filter(start_time, end_time, severity, impact_types,
                                                            classification, entity_types, entity_type_ids, limit)

    return CommandResults(
        outputs_prefix='NutanixHypervisor.Alert',
        outputs=response
    )


''' MAIN FUNCTION '''


def main() -> None:
    # command = demisto.command()
    command = 'nutanix-hypervisor-hosts-list'
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

        elif command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            incidents, next_run = fetch_incidents_command(client, params, last_run)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

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
    main()
