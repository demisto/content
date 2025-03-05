import copy
from typing import Dict

import pytz
import urllib3

from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
USECS_ENTRIES_MAPPING = {
    "boot_time_in_usecs": "boot_time",
    "create_time_usecs": "create_time",
    "start_time_usecs": "start_time",
    "complete_time_usecs": "complete_time",
    "last_updated_time_usecs": "last_updated",
    "created_time_stamp_in_usecs": "created_time",
    "last_occurrence_time_stamp_in_usecs": "last_occurrence",
    "acknowledged_time_stamp_in_usecs": "acknowledged_time",
    "resolved_time_stamp_in_usecs": "resolved_time",
}

HOST_FIELDS_NOT_VERBOSE = {
    "service_vmid",
    "uuid",
    "name",
    "service_vmexternal_ip",
    "hypervisor_key",
    "hypervisor_address",
    "hypervisor_username",
    "controller_vm_backplane_ip",
    "management_server_name",
    "monitored",
    "serial",
    "state",
    "vzone_name",
    "cpu_model",
    "num_cpu_cores",
    "num_cpu_threads",
    "num_cpu_sockets",
    "hypervisor_full_name",
    "hypervisor_type",
    "num_vms",
    "boot_time_in_usecs",
    "is_degraded",
    "is_secure_booted",
    "is_hardware_virtualized",
    "reboot_pending",
    "cluster_uuid",
    "has_csr",
    "host_type",
    "boot_time",
}

ALERT_FIELDS_NOT_VERBOSE = {
    "id",
    "alert_type_uuid",
    "check_id",
    "resolved",
    "auto_resolved",
    "acknowledged",
    "service_vmid",
    "node_uuid",
    "created_time_stamp_in_usecs",
    "last_occurrence_time_stamp_in_usecs",
    "cluster_uuid",
    "originating_cluster_uuid",
    "severity",
    "impact_types",
    "classifications",
    "acknowledged_by_username",
    "message",
    "detailed_message",
    "alert_title",
    "operation_type",
    "acknowledged_time_stamp_in_usecs",
    "resolved_time_stamp_in_usecs",
    "resolved_by_username",
    "user_defined",
    "affected_entities",
    "created_time",
    "last_occurrence",
}

TIMEOUT_INTERVAL = 1

UTC_TIMEZONE = pytz.timezone("utc")

NUTANIX_HOST_FIELDS_TO_REMOVE = {
    "disk_hardware_configs",
    "cpu_frequency_in_hz",
    "cpu_capacity_in_hz",
    "memory_capacity_in_bytes",
    "stats",
    "usage_stats",
}

BASE_URL_SUFFIX = "/PrismGateway/services/rest/v2.0"
""" CLIENT CLASS """


class Client(BaseClient):
    CONTENT_JSON = {"content-type": "application/json"}

    def __init__(self, base_url, verify, proxy, auth):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=auth, headers=self.CONTENT_JSON)

    def http_request(self, method: str, url_suffix: str, params: Dict = None, json_data: Dict = None):
        """
        Wrapper function for BaseClient http request function to catch errors from http requests,
        and send a human readable exception.
        That is because those exceptions are not human readable and need better description of the
        exception to explain the customer why the http request failed on those requests.
        Args:
            method (str): The http method.
            url_suffix (str): The suffix to be added to base url.
            params (Dict): The params to be sent in the.
            json_data (Dict): The data to be sent

        Returns:

        """
        try:
            return self._http_request(method=method, url_suffix=url_suffix, params=params, json_data=json_data)
        except DemistoException as e:
            if "Invalid filter criteria specified." in str(e):
                raise DemistoException("""Filter criteria given is invalid or is not written in the correct format.
                 Use the 'filter' argument description 'to build your filter correctly.""")

            if "Unrecognized field" in str(e):
                raise DemistoException("Filter criteria given is invalid.")

            if "General error parsing FIQL expression" in str(e):
                raise DemistoException(
                    "Filter criteria given is not written in a valid format. The correct format can be found in the "
                    "argument description."
                )
            raise e

    def fetch_incidents(self, params: Dict, last_run: Dict):
        alert_status_filters = params.get("alert_status_filters")
        auto_resolved = get_alert_status_filter("Auto Resolved", "Not Auto Resolved", alert_status_filters)
        resolved = get_alert_status_filter("Resolved", "Unresolved", alert_status_filters)
        acknowledged = get_alert_status_filter("Acknowledged", "Unacknowledged", alert_status_filters)

        if auto_resolved is not None and resolved is False:
            raise DemistoException(f"""The combination of 'resolved=false' and 'auto_resolved={auto_resolved}' is not allowed.""")
        resolved = True if auto_resolved else resolved

        severity = params.get("severity")
        alert_type_ids = params.get("alert_type_ids")
        impact_types = params.get("impact_types")

        fetch_time = params.get("first_fetch", "5 days").strip()
        # to match the shape of the time returned by Nutanix service.
        first_fetch_time = get_optional_time_parameter_as_epoch(fetch_time)
        last_fetch_epoch_time = last_run.get("last_fetch_epoch_time", first_fetch_time)

        response = self.get_nutanix_hypervisor_alerts_list(
            start_time=last_fetch_epoch_time,
            end_time=None,
            resolved=resolved,
            auto_resolved=auto_resolved,
            acknowledged=acknowledged,
            severity=severity,
            alert_type_ids=alert_type_ids,
            impact_types=impact_types,
            entity_types=None,
            page=None,
            limit=None,
        )

        alerts = sanitize_outputs(response.get("entities"))

        incidents: List[Dict[str, Any]] = []

        for alert in alerts:
            alert_created_time = alert.get("created_time_stamp_in_usecs")

            try:
                occurred = convert_epoch_time_to_datetime(alert_created_time)
            except TypeError:
                demisto.debug(f"The following incident was found invalid and was skipped: {alert}")
                continue

            incident = {
                "name": alert.get("alert_title"),
                "type": "Nutanix Hypervisor Alert",
                "occurred": occurred,
                "rawJSON": json.dumps(remove_empty_elements(alert)),
            }

            incidents.append(incident)

        return incidents, {"last_fetch_epoch_time": int(datetime.utcnow().timestamp() * 1000000)}

    def get_nutanix_hypervisor_hosts_list(self, filter_: Optional[str], limit: Optional[int], page: Optional[int]):
        return self.http_request(
            method="GET", url_suffix="hosts", params=assign_params(filter_criteria=filter_, count=limit, page=page)
        )

    def get_nutanix_hypervisor_vms_list(self, filter_: Optional[str], offset: Optional[int], limit: Optional[int]):
        return self.http_request(
            method="GET", url_suffix="vms", params=assign_params(filter=filter_, offset=offset, length=limit)
        )

    def nutanix_hypervisor_vm_power_status_change(self, uuid: Optional[str], host_uuid: Optional[str], transition: Optional[str]):
        return self.http_request(
            method="POST",
            url_suffix=f"vms/{uuid}/set_power_state",
            json_data=assign_params(uuid=uuid, host_uuid=host_uuid, transition=transition),
        )

    def nutanix_hypervisor_task_results(self, completed_tasks: List[str]):
        return self.http_request(
            method="POST",
            url_suffix="tasks/poll",
            json_data=assign_params(completed_tasks=completed_tasks, timeout_interval=TIMEOUT_INTERVAL),
        )

    def nutanix_hypervisor_task_details(self, task_id: str):
        return self.http_request(method="GET", url_suffix=f"tasks/{task_id}")

    def get_nutanix_hypervisor_alerts_list(
        self,
        start_time: Optional[int],
        end_time: Optional[int],
        resolved: Optional[bool],
        auto_resolved: Optional[bool],
        acknowledged: Optional[bool],
        severity: Optional[str],
        alert_type_ids: Optional[str],
        impact_types: Optional[str],
        entity_types: Optional[str],
        page: Optional[int],
        limit: Optional[int],
    ):
        return self.http_request(
            method="GET",
            url_suffix="alerts",
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
                count=limit,
            ),
        )

    def post_nutanix_hypervisor_alert_acknowledge(self, alert_id: Optional[str]):
        return self.http_request(
            method="POST",
            url_suffix=f"alerts/{alert_id}/acknowledge",
        )

    def post_nutanix_hypervisor_alert_resolve(self, alert_id: Optional[str]):
        return self.http_request(
            method="POST",
            url_suffix=f"alerts/{alert_id}/resolve",
        )

    def post_nutanix_hypervisor_alerts_acknowledge_by_filter(
        self,
        start_time: Optional[int],
        end_time: Optional[int],
        severity: Optional[str],
        impact_types: Optional[str],
        entity_types: Optional[str],
        limit: Optional[int],
    ):
        return self.http_request(
            method="POST",
            url_suffix="alerts/acknowledge",
            params=assign_params(
                start_time_in_usecs=start_time,
                end_time_in_usecs=end_time,
                severity=severity,
                impact_types=impact_types,
                entity_type=entity_types,
                count=limit,
            ),
        )

    def post_nutanix_hypervisor_alerts_resolve_by_filter(
        self,
        start_time: Optional[int],
        end_time: Optional[int],
        severity: Optional[str],
        impact_types: Optional[str],
        entity_types: Optional[str],
        limit: Optional[int],
    ):
        return self.http_request(
            method="POST",
            url_suffix="alerts/resolve",
            params=assign_params(
                start_time_in_usecs=start_time,
                end_time_in_usecs=end_time,
                severity=severity,
                impact_types=impact_types,
                entity_type=entity_types,
                count=limit,
            ),
        )


""" HELPER FUNCTIONS """


def get_optional_time_parameter_as_epoch(arg: Optional[str]) -> Optional[int]:
    """
    Receives arg, expects that the time argument will be either:
    - Epoch time.
    - Iso time.
    Args:
        arg (str): The argument to turn into epoch time.

    Returns:
        - If 'arg' is None, returns None.
        - If 'arg' is exists and is epoch time or iso time, returns the epoch time of the argument.
        - If 'arg' exists and is not epoch or iso, throws DemistoException exception.

    """
    maybe_unaware_date = arg_to_datetime(arg, is_utc=True)
    if not maybe_unaware_date:
        return None

    aware_time_date = maybe_unaware_date if maybe_unaware_date.tzinfo else UTC_TIMEZONE.localize(maybe_unaware_date)
    return int(aware_time_date.timestamp() * 1000000)


def get_optional_boolean_arg(args: Dict, argument_name: str) -> Optional[bool]:
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
    maybe_date_time = arg_to_datetime(epoch_time / 1000.0)
    if not maybe_date_time:
        return None
    return maybe_date_time.isoformat()


def get_alert_status_filter(true_value: str, false_value: str, alert_status_filters: Optional[List[str]]) -> Optional[bool]:
    """
    Receives alert_status filters, which contains all the alert status filters chosen by the user.
    checks if the argument name which corresponds to true value ('true_value') is found, or
    if the argument name which corresponds to false value ('false_value') is found,
    and returns the corresponding value.
    In case user selected both 'true_value' and 'false_value', will raise a DemistoException
    to indicate the user such case is not possible.

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
            f"Invalid alert status filters configurations, only one of {true_value},{false_value} can be chosen."
        )
    result_value = None
    if true_value in alert_status_filters:
        result_value = True
    elif false_value in alert_status_filters:
        result_value = False
    return result_value


def add_iso_entries_to_dict(outputs: List[Dict]) -> None:
    """
    Takes list of outputs, for each output:
    For each field in the output that is contained in 'USECS_ENTRIES_MAPPING' keys,
    adds a new entry of the corresponding value to the key in 'USECS_ENTRIES_MAPPING',
    Value of the new entry will be the iso format corresponding to the timestamp from the 'USECS_ENTRIES_MAPPING' key.
    Args:
        outputs (List[Dict]): List of the outputs to be transformed.

    Returns:
        Modifies the outputs.
    """
    for output in outputs:
        for old_entry_name, new_entry_name in USECS_ENTRIES_MAPPING.items():
            if old_entry_name in output:
                output[new_entry_name] = convert_epoch_time_to_datetime(output.get(old_entry_name))


def get_human_readable_headers(outputs: List[Dict]) -> List[Any]:
    """
    Retrieves all of the keys that their value is not dict recursively
    Args:
        outputs (List[Dict]): Input list of dictionaries.

    Returns:
        List with all of the keys that don't have inner dictionaries.
    """

    def contains_dict(entry: Any) -> bool:
        if isinstance(entry, dict):
            return True
        elif isinstance(entry, list):
            return any(contains_dict(item) for item in entry)
        return False

    human_readable_keys: List[Set] = [{k for k, v in output.items() if not contains_dict(v)} for output in outputs]
    if not human_readable_keys:
        return []
    return list(set.intersection(*human_readable_keys))


def task_exists(client: Client, task_id: str) -> bool:
    """
    Receives task_id, and checks if task exists.
    Check is done by performing an API call to Nutanix service to receive task details.
    If the task is not found by Nutanix, it will return an error indicating the task with
    the ID of 'task_id' is not found.
    Args:
        client (Client): The client to perform the API request to Nutanix service.
        task_id (str): The ID of the task to check if exists.

    Returns:
        - True if task exists.
        - False if task does not exist.
    """
    try:
        client.nutanix_hypervisor_task_details(task_id)
        return True
    except DemistoException as e:
        if e.message and f"{task_id} is not found" in e.message:
            return False
        raise e


def sanitize_outputs(outputs: List[Dict]) -> List[Dict]:
    """
    Sanitizes outputs, adds ISO entries to outputs if needed, and
    removes empty elements.
    Args:
        outputs (List[Dict]): The outputs to sanitize.

    Returns:
        Outputs with additional ISO entries if needed, and all empty elements removed.
    """
    outputs_without_empty_elements = [remove_empty_elements(output) for output in outputs]
    add_iso_entries_to_dict(outputs_without_empty_elements)
    return outputs_without_empty_elements


""" COMMAND FUNCTIONS """


def test_module_command(client: Client, params: Dict) -> str:
    """
    Tests API connectivity, authentication, and ability to fetch incidents.
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): Nutanix client to perform the API calls.
        params (Dict): Demisto params.

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        client.fetch_incidents(params, {})
        return "ok"
    except DemistoException as e:
        if e.message and "Error in API call [401] - UNAUTHORIZED" in e.message:
            raise DemistoException("Unauthorized - make sure you have the right credentials")
        if e.message and "Error in API call [404] - NOT FOUND" in e.message:
            raise DemistoException("""Page not found - make sure 'Server URL' parameter is correct""")
        raise e


def fetch_incidents_command(client: Client, params: Dict):
    """
    Wrapper function that calls client fetch_incidents function with last run and demisto params.
    Updates the new run, and uploads incidents to Demisto.
    Args:
        client (Client): The client to perform Nutanix API request and fetch incidents.
        params (Dict): Demisto params.

    Returns:
        Fetches incidents to Demisto.
    """
    last_run = demisto.getLastRun()
    incidents, next_run = client.fetch_incidents(params, last_run)
    demisto.setLastRun(next_run)
    demisto.incidents(incidents)


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
    filter_ = args.get("filter")
    limit = arg_to_number(args.get("limit", 50))
    page = arg_to_number(args.get("page"))
    verbose = get_optional_boolean_arg(args, "verbose")

    raw_response = client.get_nutanix_hypervisor_hosts_list(filter_, limit, page)
    raw_outputs = raw_response.get("entities")

    # if verbose - remove fields that should be removed always
    if verbose:
        outputs = [{k: v for k, v in raw_output.items() if k not in NUTANIX_HOST_FIELDS_TO_REMOVE} for raw_output in raw_outputs]
    # if not verbose - output only fields that should be outputted.
    else:
        outputs = [{k: v for k, v in raw_output.items() if k in HOST_FIELDS_NOT_VERBOSE} for raw_output in raw_outputs]

    final_outputs = sanitize_outputs(outputs)

    return CommandResults(
        outputs_prefix="NutanixHypervisor.Host",
        outputs_key_field="uuid",
        outputs=final_outputs,
        readable_output=tableToMarkdown("Nutanix Hosts List", final_outputs, get_human_readable_headers(final_outputs)),
        raw_response=raw_response,
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
    filter_ = args.get("filter")
    offset = arg_to_number(args.get("offset"))
    limit = arg_to_number(args.get("limit", 50))

    raw_response = client.get_nutanix_hypervisor_vms_list(filter_, offset, limit)

    outputs = sanitize_outputs(raw_response.get("entities"))

    return CommandResults(
        outputs_prefix="NutanixHypervisor.VM",
        outputs_key_field="uuid",
        outputs=outputs,
        readable_output=tableToMarkdown("Nutanix Virtual Machines List", outputs, get_human_readable_headers(outputs)),
        raw_response=raw_response,
    )


def nutanix_hypervisor_vm_power_status_change_command(client: Client, args: Dict):
    """
    Set power state of the virtual machine matching vm_uuid argument to power state given in transition argument.
    If the virtual machine is being powered on and no host is specified, the scheduler will pick the one with
    the most available CPU and memory that can support the Virtual Machine.
    If the virtual machine is being power cycled, a different host can be specified to start it on.

    This is also an asynchronous operation that results in the creation of a task object.
    The UUID of this task object is returned as the response of this operation.
    This task can be monitored by using the nutanix-hypervisor-task-results-get command

    In case response was successful, response will be a dict {'task_uuid': int}.

    Args:
        client (Client): Client object to perform request.
        args (Dict): Demisto arguments.

    Returns:
        CommandResults.
    """
    vm_uuid = args.get("vm_uuid")
    host_uuid = args.get("host_uuid")
    transition = args.get("transition")

    raw_response = client.nutanix_hypervisor_vm_power_status_change(vm_uuid, host_uuid, transition)

    return CommandResults(
        outputs_prefix="NutanixHypervisor.VMPowerStatus",
        outputs_key_field="task_uuid",
        outputs=raw_response,
        raw_response=raw_response,
    )


def nutanix_hypervisor_task_results_get_command(client: Client, args: Dict):
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
    task_ids_list: List[str] = argToList(args.get("task_ids"))

    raw_response = client.nutanix_hypervisor_task_results(task_ids_list)
    outputs = copy.deepcopy(raw_response.get("completed_tasks_info", []))

    for output in outputs:
        task_id = output.get("uuid")
        task_ids_list.remove(task_id)

    for uncompleted_task_id in task_ids_list:
        progress_status = "In Progress" if task_exists(client, uncompleted_task_id) else "Task Was Not Found"
        outputs.append({"uuid": uncompleted_task_id, "progress_status": progress_status})

    final_outputs = sanitize_outputs(outputs)

    return CommandResults(
        outputs_prefix="NutanixHypervisor.Task",
        outputs_key_field="uuid",
        readable_output=tableToMarkdown("Nutanix Hypervisor Tasks Status", final_outputs),
        outputs=final_outputs,
        raw_response=raw_response,
    )


def nutanix_hpyervisor_alerts_list_command(client: Client, args: Dict):
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
    start_time = get_optional_time_parameter_as_epoch(args.get("start_time"))
    end_time = get_optional_time_parameter_as_epoch(args.get("end_time"))

    auto_resolved = get_optional_boolean_arg(args, "auto_resolved")
    resolved = get_optional_boolean_arg(args, "resolved")

    if auto_resolved is not None and resolved is False:
        raise DemistoException(f"""The combination of 'resolved=false' and 'auto_resolved={auto_resolved}' is not allowed.""")
    resolved = True if auto_resolved else resolved

    acknowledged = get_optional_boolean_arg(args, "acknowledged")
    severity = args.get("severity")
    alert_type_ids = args.get("alert_type_ids")
    impact_types = args.get("impact_types")
    entity_types = args.get("entity_types")
    page = arg_to_number(args.get("page"))
    limit = arg_to_number(args.get("limit", 50))
    verbose = get_optional_boolean_arg(args, "verbose")

    raw_response = client.get_nutanix_hypervisor_alerts_list(
        start_time,
        end_time,
        resolved,
        auto_resolved,
        acknowledged,
        severity,
        alert_type_ids,
        impact_types,
        entity_types,
        page,
        limit,
    )

    outputs = sanitize_outputs(raw_response.get("entities"))

    # if not verbose - output only fields that should be outputted.
    if not verbose:
        outputs = [{k: v for k, v in raw_output.items() if k in ALERT_FIELDS_NOT_VERBOSE} for raw_output in outputs]

    return CommandResults(
        outputs_prefix="NutanixHypervisor.Alerts",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=tableToMarkdown("Nutanix Alert List", outputs, get_human_readable_headers(outputs)),
        raw_response=raw_response,
    )


def nutanix_hypervisor_alert_acknowledge_command(client: Client, args: Dict):
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
    alert_id = args.get("alert_id")

    raw_response = client.post_nutanix_hypervisor_alert_acknowledge(alert_id)

    return CommandResults(
        outputs_prefix="NutanixHypervisor.AcknowledgedAlerts",
        outputs_key_field="id",
        outputs=remove_empty_elements(raw_response),
        raw_response=raw_response,
    )


def nutanix_hypervisor_alert_resolve_command(client: Client, args: Dict):
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
    alert_id = args.get("alert_id")

    raw_response = client.post_nutanix_hypervisor_alert_resolve(alert_id)

    return CommandResults(
        outputs_prefix="NutanixHypervisor.ResolvedAlerts",
        outputs_key_field="id",
        outputs=remove_empty_elements(raw_response),
        raw_response=raw_response,
    )


def nutanix_hypervisor_alerts_acknowledge_by_filter_command(client: Client, args: Dict):
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
    start_time = get_optional_time_parameter_as_epoch(args.get("start_time"))
    end_time = get_optional_time_parameter_as_epoch(args.get("end_time"))
    severity = args.get("severity")
    impact_types = args.get("impact_types")
    entity_types = args.get("entity_types")
    limit = arg_to_number(args.get("limit", 50))

    raw_response = client.post_nutanix_hypervisor_alerts_acknowledge_by_filter(
        start_time, end_time, severity, impact_types, entity_types, limit
    )

    outputs = {
        "num_successful_updates": raw_response.get("num_successful_updates", 0),
        "num_failed_updates": raw_response.get("num_failed_updates", 0),
    }

    return CommandResults(outputs_prefix="NutanixHypervisor.AcknowledgedFilterAlerts", outputs=outputs, raw_response=raw_response)


def nutanix_hypervisor_alerts_resolve_by_filter_command(client: Client, args: Dict):
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
    start_time = get_optional_time_parameter_as_epoch(args.get("start_time"))
    end_time = get_optional_time_parameter_as_epoch(args.get("end_time"))
    severity = args.get("severity")
    impact_types = args.get("impact_types")
    entity_types = args.get("entity_types")
    limit = arg_to_number(args.get("limit", 50))

    raw_response = client.post_nutanix_hypervisor_alerts_resolve_by_filter(
        start_time, end_time, severity, impact_types, entity_types, limit
    )

    outputs = {
        "num_successful_updates": raw_response.get("num_successful_updates", 0),
        "num_failed_updates": raw_response.get("num_failed_updates", 0),
    }

    return CommandResults(outputs_prefix="NutanixHypervisor.ResolvedFilterAlerts", outputs=outputs, raw_response=raw_response)


""" MAIN FUNCTION """


def main() -> None:
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    credentials = params.get("credentials")
    username = credentials.get("identifier")
    password = credentials.get("password")

    base_url = params.get("base_url") + BASE_URL_SUFFIX

    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        client = Client(base_url=base_url, verify=verify_certificate, proxy=proxy, auth=(username, password))

        if command == "test-module":
            return_results(test_module_command(client, params))

        elif command == "fetch-incidents":
            fetch_incidents_command(client, params)

        elif command == "nutanix-hypervisor-hosts-list":
            return_results(nutanix_hypervisor_hosts_list_command(client, args))

        elif command == "nutanix-hypervisor-vms-list":
            return_results(nutanix_hypervisor_vms_list_command(client, args))

        elif command == "nutanix-hypervisor-vm-powerstatus-change":
            return_results(nutanix_hypervisor_vm_power_status_change_command(client, args))

        elif command == "nutanix-hypervisor-task-results-get":
            return_results(nutanix_hypervisor_task_results_get_command(client, args))

        elif command == "nutanix-hypervisor-alerts-list":
            return_results(nutanix_hpyervisor_alerts_list_command(client, args))

        elif command == "nutanix-hypervisor-alert-acknowledge":
            return_results(nutanix_hypervisor_alert_acknowledge_command(client, args))

        elif command == "nutanix-hypervisor-alert-resolve":
            return_results(nutanix_hypervisor_alert_resolve_command(client, args))

        elif command == "nutanix-hypervisor-alerts-acknowledge-by-filter":
            return_results(nutanix_hypervisor_alerts_acknowledge_by_filter_command(client, args))

        elif command == "nutanix-hypervisor-alerts-resolve-by-filter":
            return_results(nutanix_hypervisor_alerts_resolve_by_filter_command(client, args))

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
