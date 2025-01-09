import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json
import re
from collections.abc import Callable
import copy

''' CONSTANTS'''

DEFAULT_LIMIT = '50'
DEFAULT_PAGE = '1'
DEFAULT_PAGE_SIZE = DEFAULT_LIMIT
MAX_FETCH = 200
MAX_EVENTS_FETCH = 50
DEFAULT_FETCH = DEFAULT_LIMIT
DEFAULT_EVENTS_FETCH = '20'
ALL_STATUS_FILTER = 'All'

INCIDENT_STATUS_VALUE_MAPPING = {
    "Active": 0,
    "Auto Cleared": 1,
    "Manually Cleared": 2,
    "System Cleared": 3
}

INCIDENT_STATUS_INT_VERBAL_MAPPING = {
    0: "ACTIVE",
    1: "AUTOMATICALLY CLEARED",
    2: "MANUALLY CLEARED",
    3: "SYSTEM CLEARED"

}

INCIDENT_RESOLUTION_INT_VERBAL_MAPPING = {
    0: "None",
    1: "Open",
    2: "True Positive",
    3: "False Positive",
    4: "In Progress"

}

INCIDENT_CATEGORY_INT_VERBAL_MAPPING = {
    1: "AVAILABILITY",
    2: "PERFORMANCE",
    3: "CHANGE",
    4: "SECURITY",
    5: "OTHER"

}

INCIDENT_EVENT_CATEGORY_MAPPING = {
    'LOW': 1,
    'MEDIUM': 2,
    'HIGH': 3
}

EVENT_GENERIC_ATTRIB = {
    "eventId", "eventName", "reptDevIpAddr",
    "reptDevName"
}

REFORMAT_INCIDENT_FIELDS = {
    "incidentSrc", "incidentTarget", "incidentDetail"
}


class FortiSIEMClient(BaseClient):
    """
    FortiSIEM Rest API Client.
    """

    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=f'{server_url}/phoenix/rest/', verify=verify, proxy=proxy, headers=headers, auth=auth)

    def events_search_init_request(self, payload: str) -> str:
        """
        Initialize search query on events.
        Args:
            payload (str): query in xml format.

        Returns:
            str: API response from FortiSIEM.
        """
        headers = self._headers
        headers['Content-Type'] = 'text/xml'
        response = self._http_request('POST', 'query/eventQuery', headers=headers, data=payload, resp_type='text')
        return response

    def events_search_status_request(self, search_id: str) -> str:
        """
        Get the status of an executed query bu the specified search_id.
        Args:
            search_id (list): search ID.
        Returns:
            str: API response from FortiSIEM.
        """
        response = self._http_request('GET', f'query/progress/{search_id}', resp_type='text')
        return response

    def events_search_results_request(self, search_id: str, start_index: int, limit: int):
        """
        Get the results of an executed query by the specified search_id.
        Args:
            search_id (str): The ID of the search to fetch the results.
            start_index (int): The first record to retrieve.
            limit(int): How many records records to retrieve.
        Returns:
            Dict[str,Any]: API response from FortiSIEM.
        """

        response = self._http_request('GET', f'query/events/{search_id}/{start_index}/{limit}', resp_type='xml')
        return format_resp_xml_to_dict(response.text)

    def cmdb_devices_list_request(self, include_ip_list: list, exclude_ip_list: list, include_ip_range: str,
                                  exclude_ip_rage: str) -> dict[str, Any]:
        """
        List CMDB devices. The request considerate either the ip_list or the ip_range for both:
            include/exclude options.
        Args:
            include_ip_list (list): List of IP addresses to include.
            exclude_ip_list (list): List of IP addresses to exclude.
            include_ip_range (str): Range of IP addresses to include
            exclude_ip_rage (str): Range of IP addresses to exclude.

        Returns:
            Dict[str,Any]: API response from FortiSIEM.
        """
        include_ip_set = build_ip_set([include_ip_list, include_ip_range])  # type: ignore[list-item]
        exclude_ip_set = build_ip_set([exclude_ip_list, exclude_ip_rage])  # type: ignore[list-item]
        params = assign_params(includeIps=include_ip_set,
                               excludeIps=exclude_ip_set)

        response = self._http_request('GET', 'cmdbDeviceInfo/devices', params=params, resp_type='xml')
        return format_resp_xml_to_dict(response.text)

    def cmdb_device_get_request(self, ip_address: str) -> dict[str, Any]:
        """
        Get full information about the specified device.

        Args:
            ip_address (str): The device's IP address.

        Returns:
            Dict[str,Any]: API response from FortiSIEM.
        """
        params = assign_params(ip=ip_address)
        response = self._http_request('GET', 'cmdbDeviceInfo/device', params=params, resp_type='xml')

        return format_resp_xml_to_dict(response.text)

    def monitored_organizations_list_request(self) -> dict[str, Any]:
        """
        List monitored organizations.

        Returns:
            Dict[str,Any]: API response from FortiSIEM.
        """
        response = self._http_request('GET', 'config/Domain', resp_type='xml')

        return format_resp_xml_to_dict(response.text)

    def fetch_incidents_request(self, status: List[int], time_from: int, time_to: int, size: int,
                                start: int = 0) -> dict[str, Any]:
        """
        Fetch incident request. Please note that the API request retrieve all the incidents which occurred in
        the specified time interval.

        Args:
            status (List[int]): Status list to filter by.
            time_from (int): From which 'incidentFirstSeen' to fetch the incidents.
            time_to (int): Until which 'incidentFirstSeen' to fetch the incidents.
            size (int): Maximum incidents to get.
            start (int, optional): From which index to get. Defaults to 0.
        """
        data = {"descending": False, "filters": {"status": status},
                "orderBy": "incidentFirstSeen", "size": size, "start": start, "timeFrom": time_from, "timeTo": time_to}
        demisto.debug(f'Fetch incident request: {str(data)}')
        response = self._http_request('POST', 'pub/incident', json_data=data)
        return response

    def incident_update_request(self, incident_id: str, comments: str, incident_status: str,
                                external_ticket_type: str, external_ticket_id: str, external_ticket_state: str,
                                external_assigned_user: str) -> str:
        """
        Update attributes of the specified Incident. Only not None args will override the incidents attributes.
        Args:
            incident_id (list): The ID of the incident to update.
            comments (list): Update comments regarding the specified incident.
            incident_status (str): The updated status of the incident.
            external_ticket_type (str): External ticket type.
            external_ticket_id (str): External ticket id.
            external_ticket_state (str): External ticket state.
            external_assigned_user(str): External assigned user

        Returns:
            str: API response from FortiSIEM.
        """
        incident_numeric_status = INCIDENT_STATUS_VALUE_MAPPING.get(incident_status)
        data = assign_params(
            incidentId=incident_id, incidentStatus=incident_numeric_status, comments=comments,
            externalAssignedUser=external_assigned_user, externalTicketId=external_ticket_id,
            externalTicketState=external_ticket_state, externalTicketType=external_ticket_type
        )
        response = self._http_request('POST', 'incident/external', json_data=data)
        return response

    def events_list_request(self, size: int, incident_id: str) -> dict[str, Any]:
        """
        List triggered events by the specified incident ID.

        Args:
            size (int): How many events to retrieve.
            incident_id (str): The ID of the incident which the events were triggered by.

        Returns:
            Dict[str,Any]: API response from FortiSIEM.
        """
        params = assign_params(size=size, incidentId=incident_id)

        response = self._http_request('GET', 'pub/incident/triggeringEvents',
                                      params=params, ok_codes=(200, 201, 204, 400))
        return response

    def watchlist_list_by_entry_value_request(self, entry_value: str):
        """
        List Watchlist by the specified entry value.
        Args:
            entry_value (str): The entry value to filter the Watchlists by.

        Returns:
            Dict[str,Any]: API response from FortiSIEM.
        """
        params = assign_params(entryValue=entry_value)

        response = self._http_request('GET', 'watchlist/value', params=params)
        return response

    def watchlist_list_all(self):
        """
        List all Watchlist.

        Returns:
            Dict[str,Any]: API response from FortiSIEM.
        """

        response = self._http_request('GET', 'watchlist/all')

        return response

    def watchlist_get_by_id_request(self, watchlist_id: str) -> dict[str, Any]:
        """
        Get Watchlist by the specified Watchlist ID.
        Args:
            watchlist_id (str): Watchlist ID.

        Returns:
            Dict[str,Any]: API response from FortiSIEM.
        """
        response = self._http_request('GET', f'watchlist/{watchlist_id}')

        return response

    def watchlist_get_by_entry_id_request(self, entry_id: str) -> dict[str, Any]:
        """
        Get Watchlist by the specified entry ID.
        Args:
            entry_id (str): entry ID.

        Returns:
            Dict[str,Any]: API response from FortiSIEM.
        """
        response = self._http_request('GET', f'watchlist/byEntry/{entry_id}')

        return response

    def watchlist_add_request(self, display_name: str, description: str, is_case_sensitive: bool,
                              data_creation_type: str,
                              value_type: str, age_out: str,
                              inclusive: bool, entry_value: str, entry_age_out: str, count: int,
                              first_seen: int, last_seen: int,
                              triggering_rules: list) -> dict[str, Any]:
        """
        Create new Watchlist group with an Entry(optional).
        Args:
            display_name (str): Watchlist display name.
            description (str): Watchlist description.
            is_case_sensitive (bool): Whether or not consider case-sensitive.
            data_creation_type (str): Watchlist Data creation type.
            value_type (str): value type of the entries.
            age_out (str): Expiry time of watchlist.
            inclusive (bool): Whether or not the entry is inclusive.
            entry_value (str): Entry value.
            entry_age_out (int): Entry expiry time.
            count (int): Entry count.
            first_seen (int): The first time the entry was seen.
            last_seen (int): The last time the entry was seen.
            triggering_rules (list): List of triggering rules of the entry.

        Returns:
            Dict[str, Any]: API response from FortiSIEM.
        """
        data = {"ageOut": age_out, "dataCreationType": data_creation_type,
                "description": description, "type": "DyWatchList",
                "displayName": display_name, "isCaseSensitive": is_case_sensitive,
                "valueType": value_type}
        if entry_value:
            data["entries"] = [
                {"ageOut": entry_age_out, "count": count,
                 "dataCreationType": data_creation_type,
                 "entryValue": entry_value, "firstSeen": first_seen, "inclusive": inclusive, "lastSeen": last_seen,
                 "triggeringRules": triggering_rules}]
        response = self._http_request('POST', 'watchlist/save', json_data=data)

        return response

    def watchlist_entry_add_request(self, watchlist_id: str, value: str, inclusive: bool, count: int,
                                    triggering_rules: List[str], age_out: str, last_seen: int, first_seen: int,
                                    data_creation_type: str, description: str,
                                    disable_age_out: bool) -> dict[str, Any]:
        """
        Add new Entry to Watchlist group.

        Args:
            watchlist_id (str): The ID of the watchlist to add the entry to.
            value (str): Entry value.
            inclusive (bool): Whether the entry is inclusive.
            count (int): Entry count.
            triggering_rules (List[str]): List of Triggering rules.
            age_out (str): Expiry time of the entry.
            last_seen (int): Last time the entry was seen.
            first_seen (int): First time the entry was seen.
            data_creation_type (str): Data creation type.
            description (str): Entry description.
            disable_age_out (bool): Whether or not disable age out.
        Returns:
            Dict[str, Any]: API response from FortiSIEM.
        """
        params = assign_params(watchlistId=watchlist_id)
        data = [{"ageOut": age_out, "count": count, "dataCreationType": data_creation_type,
                 "entryValue": value, "firstSeen": first_seen, "inclusive": inclusive, "lastSeen": last_seen,
                 "triggeringRules": triggering_rules, "description": description,
                 "disableAgeout": disable_age_out}]

        response = self._http_request('POST', 'watchlist/addTo', params=params, json_data=data)

        return response

    def watchlist_entry_update_request(self, entry_id: str, value: str, **kwargs) -> dict[str, Any]:
        """
        Update the specified Entry. The request overrides the current attributes of the Entry.

        Args:
            entry_id (str): The ID of the entry to update.
            value (str): Entry value.

        Returns:
            Dict[str, Any]: API response from FortiSIEM.
        """
        data = remove_empty_elements(dict(kwargs.items()))
        data['id'] = entry_id
        data['entryValue'] = value
        response = self._http_request('POST', 'watchlist/entry/save', json_data=data)
        return response

    def watchlist_entry_delete_request(self, entry_id: int) -> dict[str, Any]:
        """
        Delete entry by the specified entry ID.
        Args:
            entry_id (int): The Entry ID to delete.

        Returns:
            Dict[str,Any]: API response from FortiSIEM.
        """
        response = self._http_request('POST', 'watchlist/entry/delete', json_data=[entry_id])

        return response

    def watchlist_delete_request(self, watchlist_id: int) -> dict[str, Any]:
        """
        Delete Watchlist by the specified Watchlist ID.
        Args:
            watchlist_id (int): Watchlist ID to delete.

        Returns:
            Dict[str,Any]: API response from FortiSIEM.
        """

        response = self._http_request('POST', 'watchlist/delete', json_data=[watchlist_id])

        return response

    def watchlist_entry_get_request(self, entry_id: str) -> dict[str, Any]:
        """
        Get Entry by the specified ID.
        Args:
            entry_id (List[int]): Entry ID.

        Returns:
            Dict[str,Any]: API response from FortiSIEM.
        """

        response = self._http_request('GET', f'watchlist/entry/{entry_id}')

        return response


def search_events_with_polling_command(client: FortiSIEMClient, args: dict[str, Any], cmd: str,
                                       search_command: Callable,
                                       status_command: Callable, results_command: Callable) -> CommandResults:
    """
       Initiate events search in FortiSIEM.
       Args:
           client (Client): Azure DevOps API client.
           args (dict): Command arguments from XSOAR.
           cmd (str): scheduled command name.
           search_command (Callable): Search events command.
           status_command (Callable): Status search events command.
           results_command (Callable): Result search events command.

       Returns:
           CommandResults: outputs, readable outputs and raw response for XSOAR.
       """
    ScheduledCommand.raise_error_if_not_supported()
    interval_in_secs = arg_to_number(args.get('interval_in_seconds', '10'))
    if interval_in_secs < 10:  # type: ignore[operator]
        raise ValueError(
            "The minimum time to wait between command execution when 'polling' should be at least 10 seconds.")
    timeout = arg_to_number(args.get('timeout_in_seconds', '60'))
    if 'search_id' not in args:
        command_results = search_command(client, args)
        search_init_outputs = command_results.outputs
        search_id = search_init_outputs.get('search_id')
        polling_args = {
            'search_id': search_id,
            'interval_in_seconds': interval_in_secs,
            'polling': True,
            **args
        }
        # schedule first poll
        scheduled_command = ScheduledCommand(
            command=cmd,
            next_run_in_seconds=interval_in_secs,  # type: ignore[arg-type]
            args=polling_args,
            timeout_in_seconds=timeout)
        command_results.scheduled_command = scheduled_command
        return command_results
    # get search status
    command_results = status_command(client, args)
    status = command_results.outputs['percentage_status']
    if status != "100":
        # schedule next poll
        polling_args = {
            'interval_in_seconds': interval_in_secs,
            'polling': True,
            **args
        }
        scheduled_command = ScheduledCommand(
            command=cmd,
            next_run_in_seconds=interval_in_secs,  # type: ignore[arg-type]
            args=polling_args,
            timeout_in_seconds=timeout)
        command_results = CommandResults(scheduled_command=scheduled_command)
    else:
        command_results = results_command(client, args)
    return command_results


def events_search_init_command(client: FortiSIEMClient, args: dict[str, Any]) -> CommandResults:
    """
    Initiate search query on events.
    Args:
        client (FortiSIEMClient): FortiSIEM client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
       CommandResults: Command results with raw response, outputs and readable outputs.
    """
    from_time = convert_date_to_timestamp(arg_to_datetime(args['from_time']))  # type: ignore[arg-type]
    to_time = convert_date_to_timestamp(arg_to_datetime(args['to_time']))  # type: ignore[arg-type]
    query = args.get('query')
    extend_data = argToBoolean(args.get('extended_data', False))
    events_constraint = query or build_constraint_from_args(copy.deepcopy(args))
    payload = build_query_xml(events_constraint, from_time, to_time, extend_data)  # type: ignore[arg-type]
    response = client.events_search_init_request(payload.decode('utf-8'))  # type: ignore[attr-defined]
    if "<?xml" in response:  # invalid query argument
        raise ValueError("The query argument is invalid. Please use another query.")
    outputs = {"search_id": response}
    readable_output = tableToMarkdown(f"Successfully Initiated search query {response}", outputs, headers=["search_id"],
                                      headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='FortiSIEM.EventsSearchInit',
        outputs_key_field='search_id',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output
    )

    return command_results


def events_search_status_command(client: FortiSIEMClient, args: dict[str, Any]) -> CommandResults:
    """
    Get the status of the search query on events.
    Args:
        client (FortiSIEMClient): FortiSIEM client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
       CommandResults: Command results with raw response, outputs and readable outputs.
    """
    search_id = args['search_id']
    response = client.events_search_status_request(search_id)
    outputs = {"percentage_status": response,
               "search_id": search_id}
    readable_outputs = tableToMarkdown(f"Search query:{search_id} status", outputs, headers=["percentage_status"],
                                       headerTransform=string_to_table_header)
    command_results = CommandResults(
        outputs_prefix='FortiSIEM.EventsSearchStatus',
        outputs_key_field='search_id',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_outputs
    )

    return command_results


def events_search_results_command(client: FortiSIEMClient, args: dict[str, Any]) -> CommandResults:
    """
    Get the search query results.
    Args:
        client (FortiSIEMClient): FortiSIEM client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
       CommandResults: Command results with raw response, outputs and readable outputs.
    """
    search_id = args['search_id']
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    page = arg_to_number(args.get('page'), DEFAULT_PAGE)
    start_index = (page - 1) * limit  # type: ignore[operator]
    response = client.events_search_results_request(search_id, start_index, limit)  # type: ignore[arg-type]
    outputs, total_pages = format_search_events_results(response, limit)  # type: ignore[arg-type]
    header = format_readable_output_header(
        f"Search Query: {search_id} Results", limit, page, total_pages)  # type: ignore[arg-type]
    readable_outputs = tableToMarkdown(header, get_list_events_readable_output(outputs),
                                       headers=["eventID", "eventReceiveTime", "eventType", "message", "sourceIP",
                                                "destinationIP",
                                                "hostName", "hostIp", "user", "fileName", "command", "filePath",
                                                "SHA256Hash", "MD5Hash", "rawEventLog"], headerTransform=pascalToSpace)
    command_results = CommandResults(
        outputs_prefix='FortiSIEM.Event',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_outputs
    )
    return command_results


def cmdb_devices_list_command(client: FortiSIEMClient, args: dict[str, Any]) -> CommandResults:
    """
    List CMDB devices.
    Args:
        client (FortiSIEMClient): FortiSIEM client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
       CommandResults: Command results with raw response, outputs and readable outputs.
    """

    include_ip_list = args.get('include_ip')
    exclude_ip_list = args.get('exclude_ip')
    include_ip_range = args.get('include_ip_range')
    exclude_ip_range = args.get('exclude_ip_range')
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    page = arg_to_number(args.get('page', DEFAULT_PAGE))
    validate_ip_address(include_ip_list, exclude_ip_list)
    validate_ip_ranges(include_ip_range, exclude_ip_range)

    response = client.cmdb_devices_list_request(include_ip_list, exclude_ip_list,  # type: ignore[arg-type]
                                                include_ip_range, exclude_ip_range)  # type: ignore[arg-type]
    outputs, total_pages = format_list_commands_output(response, ['devices', 'device'], page, limit)  # type: ignore[arg-type]
    header = format_readable_output_header('List CMDB devices', limit, page, total_pages)  # type: ignore[arg-type]
    readable_output = tableToMarkdown(header, outputs,
                                      headers=['name', 'accessIp', 'approved', 'unmanaged',
                                               'deviceType'],
                                      headerTransform=pascalToSpace)

    command_results = CommandResults(
        outputs_prefix='FortiSIEM.Device',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output
    )

    return command_results


def cmdb_device_get_command(client: FortiSIEMClient, args: dict[str, Any]) -> List[CommandResults]:
    """
    Get CMDB device.
    Args:
        client (FortiSIEMClient): FortiSIEM client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
       List[CommandResults]: Command results with raw response, outputs and readable outputs.
    """
    ip_address_list = argToList(args['ips'])
    command_results_list: List[CommandResults] = []

    for ip_address in ip_address_list:
        try:
            validate_ip_address(ip_address)
            response = client.cmdb_device_get_request(ip_address)
            outputs = format_outputs_time_attributes_to_iso(copy.deepcopy(response.get('device')))  # type: ignore[arg-type]
            readable_output = tableToMarkdown(f'CMDB device {ip_address}', outputs,
                                              headers=['name', 'accessIp', 'approved', 'unmanaged',
                                                       'deviceType', 'discoverTime', 'discoverMethod'],
                                              headerTransform=pascalToSpace)
            command_results = CommandResults(
                outputs_prefix='FortiSIEM.Device',
                outputs_key_field='name',
                outputs=outputs,
                raw_response=response,
                readable_output=readable_output
            )
            command_results_list.append(command_results)
        except Exception as error:
            error_results = CommandResults(
                readable_output=f"**{error}**"
            )
            command_results_list.append(error_results)
    return command_results_list


def monitored_organizations_list_command(client: FortiSIEMClient, args: dict[str, Any]) -> CommandResults:
    """
    List monitored organizations.
    Args:
        client (FortiSIEMClient): FortiSIEM client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
       CommandResults: Command results with raw response, outputs and readable outputs.
    """
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    page = arg_to_number(args.get('page', DEFAULT_PAGE))
    response = client.monitored_organizations_list_request()
    outputs, total_pages_number = format_organizations_output(response, page, limit)  # type: ignore[arg-type]

    readable_output = tableToMarkdown(
        format_readable_output_header('List Monitored Organizations', limit, page,  # type: ignore[arg-type]
                                      total_pages_number), outputs,  # type: ignore[arg-type]
        headers=['domainId', 'name', 'custId', 'creationTime', 'lastModified', 'disabled'],
        headerTransform=pascalToSpace)
    command_results = CommandResults(
        outputs_prefix='FortiSIEM.Organization',
        outputs_key_field='Id',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output
    )

    return command_results


def incident_update_command(client: FortiSIEMClient, args: dict[str, Any]) -> CommandResults:
    """
    Update the specified Incident.
    Args:
        client (FortiSIEMClient): FortiSIEM client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
       CommandResults: Command results with raw response, outputs and readable outputs.
    """

    incident_id: str = args['incident_id']
    if not incident_id.isdigit():
        return_error('Invalid incident ID. Incident ID should be an integer.')
    comments = args.get('comment')
    incident_status = args.get('status')
    external_ticket_type = args.get('external_ticket_type')
    external_ticket_id = args.get('external_ticket_id')
    external_ticket_state = args.get('external_ticket_state')
    external_assigned_user = args.get('external_assigned_user')

    response = client.incident_update_request(
        incident_id,
        comments,  # type: ignore[arg-type]
        incident_status,  # type: ignore[arg-type]
        external_ticket_type,  # type: ignore[arg-type]
        external_ticket_id,  # type: ignore[arg-type]
        external_ticket_state,  # type: ignore[arg-type]
        external_assigned_user  # type: ignore[arg-type]
    )
    command_results = CommandResults(readable_output=format_update_incident_readable_output(incident_id, response))

    return command_results


def events_list_command(client: FortiSIEMClient, args: dict[str, Any]) -> CommandResults:
    """
    List events by incident.
    Args:
        client (FortiSIEMClient): FortiSIEM client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
       CommandResults: Command results with raw response, outputs and readable outputs.
    """
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    page = arg_to_number(args.get('page', DEFAULT_PAGE))
    incident_id = args['incident_id']
    response = client.events_list_request(limit * page, incident_id)  # type: ignore[operator]
    outputs = format_list_events_output(response, incident_id, page, limit)  # type: ignore[arg-type]
    readable_output = tableToMarkdown(
        format_readable_output_header(f'List Events for incident ID {incident_id}', limit, page),  # type: ignore[arg-type]
        get_list_events_readable_output(outputs),
        headers=["eventID", "eventReceiveTime", "eventType", "message", "sourceIP", "destinationIP",
                 "hostName", "hostIp", "user", "fileName", "command", "filePath", "SHA256Hash", "MD5Hash", "rawEventLog"
                 ],
        headerTransform=pascalToSpace)

    command_results = CommandResults(
        outputs_prefix='FortiSIEM.Event',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=readable_output
    )
    return command_results


def watchlist_list_command(client: FortiSIEMClient, args: dict[str, Any]) -> CommandResults:
    """
    List Watchlists.
    Args:
        client (FortiSIEMClient): FortiSIEM client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
       CommandResults: Command results with raw response, outputs and readable outputs.
    """
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    page = arg_to_number(args.get('page', DEFAULT_PAGE))
    entry_value = args.get('entry_value')
    if entry_value:  # whether or list by entry value.
        response = client.watchlist_list_by_entry_value_request(entry_value)
    else:
        response = client.watchlist_list_all()
    outputs, total_pages = format_watchlist_output(response, page=page, limit=limit)
    readable_outputs = tableToMarkdown(
        format_readable_output_header('List Watchlist Groups', limit, page, total_pages),  # type: ignore[arg-type]
        outputs, headers=['id', 'name', 'displayName', 'description', 'valueType'],
        headerTransform=pascalToSpace)
    command_results = CommandResults(
        outputs_prefix='FortiSIEM.Watchlist',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_outputs
    )

    return command_results


def watchlist_get_command(client: FortiSIEMClient, args: dict[str, Any]) -> List[CommandResults]:
    """
    Get Watchlist.
    Args:
        client (FortiSIEMClient): FortiSIEM client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
       List[CommandResults]: Command results with raw response, outputs and readable outputs.
    """
    watchlist_id_list = argToList(args.get('watchlist_ids'))
    entry_id_list = argToList(args.get('entry_id'))
    command_results_list: List[CommandResults] = []
    for watchlist_id in watchlist_id_list:
        try:
            response = client.watchlist_get_by_id_request(watchlist_id)
            outputs, _ = format_watchlist_output(response,
                                                 f"**Watchlist ID {watchlist_id} doesn't exist.**")
            watchlist_readable_output = tableToMarkdown(f'Watchlist {watchlist_id}', outputs,
                                                        headers=['id', 'name', 'displayName', 'description',
                                                                 'valueType'],
                                                        headerTransform=pascalToSpace)
            entry_readable_output = tableToMarkdown("Watchlist Entries", outputs[0]['entries'],
                                                    headers=['id', 'state', 'entryValue',
                                                             'triggeringRules', 'count', 'firstSeen', 'lastSeen'],
                                                    headerTransform=pascalToSpace)
            readable_output = watchlist_readable_output + "\n" + entry_readable_output
            command_results = CommandResults(
                outputs_prefix='FortiSIEM.Watchlist',
                outputs_key_field='id',
                outputs=outputs,
                raw_response=response,
                readable_output=readable_output
            )
            command_results_list.append(command_results)

        except Exception as error:
            error_results = CommandResults(
                readable_output=f'**{error}**'
            )
            command_results_list.append(error_results)

    for entry_id in entry_id_list:
        try:
            response = client.watchlist_get_by_entry_id_request(entry_id)
            outputs, _ = format_watchlist_output(response,
                                                 f"Watchlist with entry ID of {entry_id} does not exist.")
            watchlist_readable_output = tableToMarkdown(f'Watchlist with entry ID {entry_id}', outputs,
                                                        headers=['id', 'name', 'displayName', 'description',
                                                                 'valueType'],
                                                        headerTransform=pascalToSpace)

            entry_readable_output = tableToMarkdown("Watchlist Entries", outputs[0]['entries'],
                                                    headers=['id', 'state', 'entryValue',
                                                             'triggeringRules', 'count', 'firstSeen', 'lastSeen'],
                                                    headerTransform=pascalToSpace)
            readable_output = watchlist_readable_output + "\n" + entry_readable_output

            command_results = CommandResults(
                outputs_prefix='FortiSIEM.Watchlist',
                outputs_key_field='id',
                outputs=outputs,
                raw_response=response,
                readable_output=readable_output
            )
            command_results_list.append(command_results)
        except Exception as error:
            error_results = CommandResults(
                readable_output=f'**{error}**'
            )
            command_results_list.append(error_results)
    return command_results_list


def watchlist_add_command(client: FortiSIEMClient, args: dict[str, Any]) -> CommandResults:
    """
    Add new Watchlist group.
    Args:
        client (FortiSIEMClient): FortiSIEM client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
       CommandResults: Command results with raw response, outputs and readable outputs.
    """
    display_name = args['display_name']
    description = args.get('description')
    is_case_sensitive = argToBoolean(args.get('is_case_sensitive'))
    data_creation_type = args.get('data_creation_type')
    value_type = args.get('value_type')
    age_out = datetime_to_age_out_in_days(arg_to_datetime(args.get('age_out')))  # type: ignore[arg-type]
    inclusive = argToBoolean(args.get('entry_inclusive'))
    entry_value = args.get('entry_value')
    entry_age_out = datetime_to_age_out_in_days(arg_to_datetime(args.get('entry_age_out')))  # type: ignore[arg-type]
    count = args.get('entry_count')
    first_seen = convert_date_to_timestamp(arg_to_datetime(args.get('entry_first_seen')))  # type: ignore[arg-type]
    last_seen = convert_date_to_timestamp(arg_to_datetime(args.get('entry_last_seen')))  # type: ignore[arg-type]
    triggering_rules = args.get('triggering_rules')

    validate_add_watchlist_args(first_seen, last_seen)  # type: ignore[arg-type]
    response = client.watchlist_add_request(display_name, description, is_case_sensitive,  # type: ignore[arg-type]
                                            data_creation_type,  # type: ignore[arg-type]
                                            value_type, age_out, inclusive,  # type: ignore[arg-type]
                                            entry_value,  # type: ignore[arg-type]
                                            entry_age_out, count, first_seen, last_seen,  # type: ignore[arg-type]
                                            triggering_rules)  # type: ignore[arg-type]

    output, _ = format_watchlist_output(response,
                                        f"The Watchlist group: {display_name} "
                                        f"already exists or one of the argument is invalid.")

    readable_output = tableToMarkdown(f'Added new Watchlist group: {display_name}', output,
                                      headers=['id', 'name', 'displayName', 'description', 'valueType'])
    command_results = CommandResults(
        outputs_prefix='FortiSIEM.Watchlist',
        outputs_key_field='id',
        outputs=output,
        raw_response=response,
        readable_output=readable_output
    )

    return command_results


def watchlist_entry_add_command(client: FortiSIEMClient, args: dict[str, Any]) -> CommandResults:
    """
    Add Entry tp Watchlist group.
    Args:
        client (FortiSIEMClient): FortiSIEM client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
       CommandResults: Command results with raw response, outputs and readable outputs.
    """
    watchlist_id = args['watchlist_id']
    inclusive = argToBoolean(args.get('inclusive'))
    count = arg_to_number(args.get('count'))
    triggering_rules = args.get('triggering_rules')
    value = args.get('value')
    age_out = datetime_to_age_out_in_days(arg_to_datetime(args.get('age_out')))  # type: ignore[arg-type]
    first_seen = convert_date_to_timestamp(arg_to_datetime(args.get('first_seen')))  # type: ignore[arg-type]
    last_seen = convert_date_to_timestamp(arg_to_datetime(args.get('last_seen')))  # type: ignore[arg-type]
    data_creation_type = args.get('data_creation_type')
    description = args.get('description')
    validate_add_watchlist_args(first_seen, last_seen)  # type: ignore[arg-type]
    disable_age_out = not age_out
    response = client.watchlist_entry_add_request(watchlist_id, value, inclusive, count,  # type: ignore[arg-type]
                                                  triggering_rules,  # type: ignore[arg-type]
                                                  age_out, last_seen, first_seen,  # type: ignore[arg-type]
                                                  data_creation_type, description, disable_age_out)  # type: ignore[arg-type]
    command_results = CommandResults(
        readable_output=format_add_watchlist_entry_message(watchlist_id, value, response)  # type: ignore[arg-type]
    )

    return command_results


def watchlist_entry_update_command(client: FortiSIEMClient, args: dict[str, Any]) -> CommandResults:
    """
    Update the specified entry.
    Args:
        client (FortiSIEMClient): FortiSIEM client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
       CommandResults: Command results with raw response, outputs and readable outputs.
    """
    entry_id = args['entry_id']
    inclusive = args.get('inclusive')
    count = arg_to_number(args.get('count'))
    triggering_rules = args.get('triggering_rules')
    value = args.get('value')
    age_out = datetime_to_age_out_in_days(arg_to_datetime(args.get('age_out')))  # type: ignore[arg-type]
    first_seen = convert_date_to_timestamp(arg_to_datetime(args.get('first_seen')))  # type: ignore[arg-type]
    last_seen = convert_date_to_timestamp(arg_to_datetime(args.get('last_seen')))  # type: ignore[arg-type]
    expiry_time = convert_date_to_timestamp(arg_to_datetime(args.get('expired_time')))  # type: ignore[arg-type]
    data_creation_type = args.get('data_creation_type')
    description = args.get('description')
    validate_add_watchlist_args(first_seen, last_seen)  # type: ignore[arg-type]

    response = client.watchlist_entry_update_request(entry_id, value, inclusive=inclusive, count=count,  # type: ignore[arg-type]
                                                     description=description,
                                                     triggeringRules=triggering_rules, ageOut=age_out,
                                                     firstSeen=first_seen, lastSeen=last_seen, expiredTime=expiry_time,
                                                     dataCreationType=data_creation_type)

    outputs, _ = format_watchlist_output(response)
    readable_output = tableToMarkdown(format_update_watchlist_entry_header(entry_id, response), outputs,
                                      headers=['id', 'state', 'entryValue',
                                               'triggeringRules', 'count', 'firstSeen', 'lastSeen'],
                                      headerTransform=pascalToSpace)
    command_results = CommandResults(
        outputs_prefix='FortiSIEM.WatchlistEntry',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output
    )

    return command_results


def watchlist_delete_command(client: FortiSIEMClient, args: dict[str, Any]) -> List[CommandResults]:
    """
    Delete Watchlists.
    Args:
        client (FortiSIEMClient): FortiSIEM client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
       CommandResults: Command results with raw response, outputs and readable outputs.
    """
    watchlist_id_list = list(map(int, argToList(args['watchlist_id'])))
    command_results_list: List[CommandResults] = []
    for watchlist_id in watchlist_id_list:
        try:
            response = client.watchlist_delete_request(watchlist_id)

            command_results = CommandResults(
                readable_output=format_message_delete_watchlist(watchlist_id, response)
            )
            command_results_list.append(command_results)
        except Exception as error:
            error_results = CommandResults(
                readable_output=f'**{error}**'
            )
            command_results_list.append(error_results)
    return command_results_list


def watchlist_entry_delete_command(client: FortiSIEMClient, args: dict[str, Any]) -> List[CommandResults]:
    """
    Delete Entries.
    Args:
        client (FortiSIEMClient): FortiSIEM client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        List[CommandResults]: List of Command results with raw response, outputs and readable outputs.
    """
    entry_id_list = list(map(int, argToList(args['entry_ids'])))
    command_results_list: List[CommandResults] = []
    for entry_id in entry_id_list:
        try:
            response = client.watchlist_entry_delete_request(entry_id)
            command_results = CommandResults(
                readable_output=format_message_delete_entry(entry_id, response))
            command_results_list.append(command_results)
        except Exception as error:
            error_results = CommandResults(
                readable_output=f'**{error}**'
            )
            command_results_list.append(error_results)
    return command_results_list


def get_incident_name(incident: dict) -> str:
    """
    Gets the incident name.
    Args:
        incident (dict): FortiSIEM incident.
    Returns:
       str: The incident name.
    """
    if incident_title := incident.get('incidentTitle'):
        return incident_title
    elif incident_id := incident.get('incidentId'):
        return f"FortiSIEM incident: {incident_id}"
    return "FortiSIEM incident"


def fetch_incidents(client: FortiSIEMClient, max_fetch: int, first_fetch: str, status_list: List[str],
                    fetch_with_events: bool, max_events_fetch: int, last_run: dict[str, Any]) -> tuple:
    """
    Fetch incidents. May fetch also the triggered events of each incident if requested.
    Args:
        client (FortiSIEMClient): FortiSIEM client.
        max_fetch (int): Maximum number of incidents to fetch.
        first_fetch (str): The timestamp to fetch the incidents from.
        status_list (list): List of incidents' status to filter incidents.
        fetch_with_events (bool): Whether or not fetch the incidents with their events.
        max_events_fetch (int): Maximum number of events to fetch per incident.
        last_run (Dict[str,Any]): Last run object.
    Returns:
       tuple: Fetched incidents & updated last_run.
    """
    validate_fetch_params(max_fetch, max_events_fetch, fetch_with_events, first_fetch, status_list)
    numeric_status_list = convert_verbal_status_filtering_to_numeric(status_list)

    first_fetch_epoch = date_to_timestamp(arg_to_datetime(first_fetch)) if not last_run else None
    last_incident_create_time = last_run.get('create_time')
    time_from = last_incident_create_time or first_fetch_epoch

    relevant_incidents = fetch_relevant_incidents(client, numeric_status_list, time_from,  # type: ignore[arg-type]
                                                  date_to_timestamp(datetime.now()), last_run, max_fetch)
    formatted_incidents = format_incidents(relevant_incidents)  # for Layout

    incidents = []
    for incident in formatted_incidents:
        if fetch_with_events:
            events = get_related_events_for_fetch_command(incident['incidentId'], max_events_fetch, client)
        else:
            events = []
        incident['events'] = events

        incidents.append({
            'name': get_incident_name(incident),
            'occurred': timestamp_to_datestring(incident['incidentFirstSeen']),
            'rawJSON': json.dumps(incident)})
    if incidents:
        last_run = update_last_run_obj(last_run, formatted_incidents)
        demisto.debug(f'Update last run to: {str(last_run)}.')
    return incidents, last_run


def get_related_events_for_fetch_command(incident_id: str, max_events_fetch: int,
                                         client: FortiSIEMClient) -> List[dict]:
    """
    Get triggered events of the specified incident ID, in a convenient format for fetch layout.
    Args:
        client (FortiSIEMClient): FortiSIEM client.
        incident_id (int): The incident ID of the related event.
        max_events_fetch (str): The Maximum number of events to retrieve.
    Returns:
       None
    """
    events_list_response = client.events_list_request(max_events_fetch, incident_id)

    if isinstance(events_list_response, dict):
        data = events_list_response.get('data')
        if not data:
            return []
    else:
        data = events_list_response
    formatted_events = format_outputs_time_attributes_to_iso([event.get('attributes') for event in data])
    for event in formatted_events:
        event['Event ID'] = str(event['Event ID'])  # To avoid overridden by XSOAR since it's a huge number.
    return formatted_events


def watchlist_entry_get_command(client: FortiSIEMClient, args: dict[str, Any]) -> List[CommandResults]:
    """
    Update the specified entry.
    Args:
        client (FortiSIEMClient): FortiSIEM client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
       List[CommandResults] : Command results with raw response, outputs and readable outputs.
    """
    entry_id_list = argToList(args['entry_ids'])
    command_results_list: List[CommandResults] = []
    for entry_id in entry_id_list:
        try:
            response = client.watchlist_entry_get_request(entry_id)
            outputs, _ = format_watchlist_output(response, f"**Watchlist Entry ID {entry_id} doesn't exist.**")
            readable_output = tableToMarkdown(f"Watchlist Entry {entry_id}", outputs,
                                              headers=['id', 'state', 'entryValue',
                                                       'triggeringRules', 'count', 'firstSeen', 'lastSeen'],
                                              headerTransform=pascalToSpace)
            command_results = CommandResults(
                outputs_prefix='FortiSIEM.WatchlistEntry',
                outputs_key_field='id',
                outputs=outputs,
                raw_response=response,
                readable_output=readable_output
            )
            command_results_list.append(command_results)
        except Exception as error:
            error = CommandResults(  # type: ignore[assignment]
                readable_output=f'**{error}**'
            )
            command_results_list.append(error)  # type: ignore[arg-type]
    return command_results_list


def test_module(client: FortiSIEMClient, max_fetch, fetch_with_events, max_events_fetch, first_fetch,
                status_filter_list) -> None:
    validate_fetch_params(max_fetch, max_events_fetch, fetch_with_events, first_fetch, status_filter_list)
    client.monitored_organizations_list_request()
    return_results('ok')


''' HELPER METHODS'''


def build_query_xml(constraint: str, from_time: int, to_time: int, extend_data: bool) -> str:
    """ Build a query in XML format. - NOTICE: this is not a final implementation, waiting for customers use case.

    Args:
        constraint (str): A constraint on the returned events.
        from_time (str): From which event receive time filter the events.
        to_time (str): Until which event receive time  filter the events.
        extend_data (bool): Whether or not to extend the retrieved data.
    Returns:
       str: Query in XML format.
    """
    attributes_list = "phRecvTime,reptDevIpAddr,eventType,eventName,rawEventMsg" if not extend_data else None
    from_time_epoch = str(from_time // 1000)
    to_time_epoch = str(to_time // 1000)

    payload = {
        "Reports": {
            "Report": {
                "SelectClause": {  # check how to implement extended data
                    "AttrList": attributes_list
                },
                "ReportInterval": {
                    "Low": from_time_epoch,
                    "High": to_time_epoch,
                },
                "PatternClause": {
                    "SubPattern": {
                        "@displayName": "events",
                        "@name": "events",
                        "SingleEvtConstr": constraint  # query/filter
                    }
                }
            }
        }
    }
    return json2xml(json.dumps(payload))


def build_constraint_from_args(args: dict[str, Any]):
    keys_to_remove = {
        "query", "from_time", "to_time", "limit", "page", "polling", "interval_in_seconds", "timeout_in_seconds",
        "extended_data"
    }
    for key in keys_to_remove:
        if key in args:
            del args[key]

    res_list = []
    for key in args:
        if 'IpAddr' not in key:
            res_list.append(f'{key} = "{args[key]}"')
        else:
            res_list.append(f"{key} = {args[key]}")
    return " AND ".join(res_list)


def format_search_events_results(response: dict[str, Any], limit: int) -> tuple:
    """
    Format the output of the search events results command.
    Args:
        response (Dict[str,Any]): API response from FortiSIEM.
        limit (int):Maximum number of results to retrieve.
    Returns:
       str: Formatted command output.
    """
    outputs = []
    events = dict_safe_get(response, ['queryResult', 'events', 'event'])
    if isinstance(events, dict):
        events = [events]
    total_count = arg_to_number(dict_safe_get(response, ['queryResult', '@totalCount']))
    total_pages = total_count // limit + (total_count % limit != 0) if total_count else 0
    if events:
        for event in events:
            formatted_event = copy.deepcopy(event)
            formatted_attributes = {}
            attributes = dict_safe_get(event, ['attributes', 'attribute'])
            formatted_event['receiveTime'] = FormatIso8601(arg_to_datetime(event['receiveTime']))
            for attribute in attributes:
                formatted_attributes[attribute['@name']] = attribute['#text']
            formatted_event['attributes'] = formatted_attributes
            outputs.append(formatted_event)
    return outputs, total_pages


def format_readable_output_header(base_header: str, limit: int, page: int = None, total_pages: int = None) -> str:
    """
    Format the header for readable output of query results command.
    Args:
        base_header (str): The prefix of the formatted header.
        total_pages (int): The total number of pages that returned in the response.
        limit(int): Maximum number of records to return.
        page(int): page number.

    Returns:
       str: Formatted header.
    """
    if total_pages:
        if total_pages > 0:
            base_header += f' \nShowing page {page} out of {total_pages} total pages.' \
                           f' Current page size: {limit}.'
    else:
        base_header += f' \nShowing page {page} out of others that may exist.' \
                       f' Current page size: {limit}.'

    return base_header


def format_resp_xml_to_dict(xml_resp_str: str) -> dict[str, Any]:
    """
    Format XML response to python dict object.
    Args:
        xml_resp_str (str): Response from FortiSIEM API in XML format.

    Returns:
       bool: True if all the specified ip addresses are valid.
    """
    json_response = xml2json(xml_resp_str)
    return json.loads(json_response)


def validate_ip_address(*ip_addresses_lists) -> None:
    """
    IP addresses validation.
    Args:
        ip_addresses_lists (list): List of IP addresses to validate.

    Returns:
       None
    """
    for ip_list in ip_addresses_lists:
        if ip_list:
            for ip_address in argToList(ip_list):  # ip_list os an comma separated list argument of a command.
                if not (re.match(ipv4Regex, ip_address)) or (re.match(ipv6Regex, ip_address)):
                    raise ValueError(
                        "IP address should be in the format of: X.X.X.X where x is a number between 0 to 255.")


def validate_ip_ranges(*ip_addresses_ranges) -> None:
    """
    IP addresses range validation.
    Args:
         ip_addresses_ranges (list): List of IP addresses ranges to validate.

     Returns:
        None
     """
    for ip_range in ip_addresses_ranges:
        if ip_range:
            ip_interval = ip_range.split('-')
            if len(ip_interval) != 2:
                raise ValueError(
                    "The argument of IP address range should be in the format of:"
                    " 'X.X.X.X'-'Y.Y.Y.Y' where X and Y are numbers between zero to 255.")
            for ip_address in ip_interval:
                if not (re.match(ipv4Regex, ip_address)) or (re.match(ipv6Regex, ip_address)):
                    raise ValueError(
                        "IP address should be in the format of: 'X.X.X.X' where x is a number between 0 to 255.")


def build_ip_set(ip_addresses: List[str]) -> str:
    """
    Build ip set input for list-cmdb-devices command.
    The input wil be a combination of ip-addresses list and ranges. For example,
    if ip_address = ['1.1.1.1','3.3.3.3','2.2.2.0-2.2.2.254'], the output will be:
    '1.1.1.1,3.3.3.3,2.2.2.0-2.2.2.254'

     Args:
         ip_addresses (list): List of IP addresses ranges/list.

     Returns:
        str: Formatted IP addresses for list-cmdb-devices command.
     """
    return ','.join(filter(None, ip_addresses))


def format_list_commands_output(response: dict[str, Any], default_dict_keys: List[str],
                                page_number: int, limit: int) -> tuple[list, int]:
    """
    Formatting list commands outputs.
    Args:
        response (Dict[str,Any): The response from the API call.
        default_dict_keys (List[str]): List of keys for safe get.
        limit (int): Maximum number of results to return.
        page_number (int): Which page to retrieve.
    Returns:
        Tuple[list,int]: Formatted command output and total results.
    """
    output_entities = dict_safe_get(response, default_dict_keys, default_return_value=[])
    if isinstance(output_entities, dict):  # Only when only element returns.
        output_entities = [output_entities]
    total_entities_number = len(output_entities)
    total_pages = total_entities_number // limit + (total_entities_number % limit != 0)
    format_outputs_time_attributes_to_iso(output_entities)
    from_index = min((page_number - 1) * limit, total_entities_number)
    to_index = min(from_index + limit, total_entities_number)
    return output_entities[from_index:to_index], total_pages


def format_organizations_output(response: dict[str, Any], page_number: int, limit: int) -> tuple[list, int]:
    """
    Formatting list organizations command outputs.
    Args:
        response (Dict[str,Any): The response from the API call.
        limit (int): Maximum number of results to return.
        page_number(int): The Page number to retrieve.
    Returns:
        Tuple[list,int]: Formatted command output and total results.
     """
    formatted_organizations = []
    relevant_output_entities, total_page_number = format_list_commands_output(response,
                                                                              ['response', 'result', 'domains',
                                                                               'domain'], page_number, limit)
    for organization in relevant_output_entities:
        formatted_organization = {}
        for key, value in organization.items():
            if key.startswith('@'):
                formatted_organization[key[1:]] = value
            else:
                formatted_organization[key] = value

        formatted_organizations.append(formatted_organization)
    return formatted_organizations, total_page_number


def format_outputs_time_attributes_to_iso(outputs: List[dict]) -> List[dict]:
    """
    Formatting time attributes in command outputs to ISO format.
    Args:
         outputs (List[dict]): The command output we want to format their time attributes.
     Returns:
        List[dict]: Formatted command output.
     """
    if not outputs:
        return []
    if not isinstance(outputs, list):
        outputs = [outputs]
    time_keys = ['lastModified', 'creationTime', 'receiveTime', 'discoverTime', 'firstSeen', 'lastSeen', 'expiredTime',
                 'Time']
    for entity in outputs:
        for key, value in entity.items():
            if any(time_key in key for time_key in time_keys) and value:
                entity[key] = FormatIso8601(datetime.fromtimestamp(int(float(value)) / 1000))

    return outputs


def format_update_incident_readable_output(incident_id: str, response: str) -> str:
    """
    Format output message of update incident command.
    Args:
         incident_id (str): The ID of the updated incident.
         response (str): API response from FortiSIEM.
    Returns:
        str: Formatted message.
    """
    if response == 'OK':
        return f"Incident ID {incident_id} was successfully updated."
    return f"Failed to update The incident: {incident_id}."


def format_watchlist_output(response: dict[str, Any], failure_message: str = None, page: int = None, limit: int = None):
    """
    Format output for Watchlists commands.
    Args:
         response (str): Watchlist ID.
         failure_message (str): Entry ID.
         limit(int): Maximum of records to return (relevant only in list commands).
     Returns:
        Dict[str,Any]: Formatted output.
     """
    status = response.get('status')
    response_content = response.get('response')
    if status == "Failed":
        if limit:  # list command
            return [], 0
        else:
            message = failure_message or response_content
            raise ValueError(message)

    outputs, total_results = format_list_commands_output(response_content, [], page or 1, limit or 1)  # type: ignore[arg-type]
    for watchlist in outputs:
        if watchlist.get('entries'):
            watchlist['entries'] = format_outputs_time_attributes_to_iso(watchlist['entries'])
    return outputs, total_results


def format_message_delete_watchlist(watchlist_id: int, response: dict[str, Any]) -> str:
    """
    Format readable output message for watchlist delete command.
    Args:
         watchlist_id (int): Watchlist ID.
         response (str): API response from FortiSIEM.
    Returns:
        str: Formatted message.
    """
    status = response.get('status')
    message = response.get('response')
    if status == 'Success':
        deleted_count = int(message.split(": ")[1])  # type: ignore[union-attr]
        if deleted_count >= 1:
            return f'The watchlist {watchlist_id} was deleted successfully.'
    raise ValueError(f'Failed to delete Watchlist group: {watchlist_id}.')


def format_message_delete_entry(entry_id: int, response: dict[str, Any]) -> str:
    """
    Format readable output message for entry delete command.
    Args:
         entry_id (int): Entry ID.
         response (str): API response from FortiSIEM.
    Returns:
        str: Formatted message.
    """
    status = response.get('status')
    message = response.get('response')
    if status == 'Success':
        deleted_count = int(message.split("- ")[1])  # type: ignore[union-attr]
        if deleted_count >= 1:
            return f'The entry {entry_id} were deleted successfully.'
    raise ValueError(f'Failed to delete entry {entry_id}.')


def validate_add_watchlist_args(first_seen: int, last_seen: int) -> None:
    """
    Validate add watchlist command argument.

    Args:
         first_seen (int): First time seen.
         last_seen (int): last time seen.
    Returns:
        None
    """

    if first_seen and last_seen and first_seen > last_seen:
        raise ValueError('first seen argument cannot be after last seen argument.')


def convert_date_to_timestamp(date_arg: datetime) -> int | None:
    """
    convert datetime object to timestamp.

    Args:
         date_arg (datetime): datetime object to convert.
    Returns:
        int: timestamp.
    """
    if date_arg:
        return date_to_timestamp(date_arg)
    return None


def format_add_watchlist_entry_message(watchlist_id: str, entry_id: str, response: dict[str, Any]) -> str:
    """
    Format readable output message for add entry command.

    Args:
         watchlist_id:(str): Watchlist ID.
         entry_id:str (str): Entry ID to add.
         response (str): API response from FortiSIEM.
    Returns:
        str: Formatted message.
    """
    status = response.get('status')
    if status == 'Failed':
        return_error(response.get('response'))
    return f"Successfully added Entry: {entry_id} to Watchlist: {watchlist_id}."


def format_update_watchlist_entry_header(entry_id: str, response: dict[str, Any]) -> str:
    """
    Format readable output header for update entry command.
    Args:
         entry_id:str (str): Entry ID to update.
         response (str): API response from FortiSIEM.
    Returns:
        str: Formatted header.
    """
    status = response.get('status')
    if status == 'Failed':
        return_error(response.get('response'))
    return f"Successfully Updated Entry: {entry_id}."


def fetch_relevant_incidents(client: FortiSIEMClient,
                             status: List[int], time_from: int, time_to: int,
                             last_run: dict[str, Any], max_fetch: int) -> List[dict]:
    """
    Fetch relevant incidents. The API retrieves the incidents which occurred during the given time interval.
    Since we are interested in create time, a pagination mechanism is implemented here. inorder to retreive the
     relevant incidents only.

     Args:
         client(FortiSIEMClient): FortiSIEM client.
         status (List[int]): status lists to filter the incidents by.
         time_from (int): from which time to fetch.
         time_to (int): Until which time to fetch.
         last_run (Dict[str, Any]): LastRun object.
         max_fetch (int): The number of incidents to fetch.
    Returns:
        List[dict]: Relevant incidents.
    """
    demisto.debug(f'Fetch incident from: {str(time_from)} to {str(time_to)}')
    filtered_incidents = []  # type: ignore[var-annotated]
    start_index = last_run.get('start_index') or 0
    last_incident_create_time = last_run.get('create_time') or time_from
    last_fetch_incidents: List[int] = last_run.get('last_incidents') or []
    page_size: int = 2 * max_fetch
    # first API call
    response = client.fetch_incidents_request(status, time_from, time_to, page_size, start_index)
    incidents = response.get('data')
    total = response.get('total')
    demisto.debug(f'Got: {total} total incidents.')
    # filtering & pagination
    while len(filtered_incidents) < max_fetch and start_index < total:  # type: ignore[operator]
        for incident in incidents:  # type: ignore[union-attr]
            if incident.get('incidentId') not in last_fetch_incidents and \
                    len(filtered_incidents) < max_fetch and \
                    incident.get('incidentFirstSeen') >= last_incident_create_time:
                filtered_incidents.append(incident)
        if len(incidents) < page_size:  # type: ignore[arg-type]
            break

        start_index += page_size
        response = client.fetch_incidents_request(status, time_from, time_to, page_size, start_index)
        incidents = response.get('data')
    demisto.debug(f'Got: {len(filtered_incidents)} incidents after filtering.')
    return filtered_incidents


def format_incidents(relevant_incidents: List[dict]) -> List[dict]:
    """
    Format incidents' content to be more readable for the user:
    Decomposing nested attributes, normalizing severity according to XSOAR scale and
    mapping several integer fields to verbal.
    Args:
         relevant_incidents (List[dict]): The incidents to format.
    Returns:
        List[dict]: Formatted incidents.
    """
    for incident in relevant_incidents:
        incident['normalizedEventSeverity'] = INCIDENT_EVENT_CATEGORY_MAPPING.get(
            incident.get('eventSeverityCat'), 0.5)  # type: ignore[arg-type]
        format_integer_field_to_verbal(incident)  # formatting integer attributes.

        for attribute_name in REFORMAT_INCIDENT_FIELDS:  # formatting nested attributes.
            attribute_value_to_decompose = incident.get(attribute_name)
            if attribute_value_to_decompose:
                nested_attributes = attribute_value_to_decompose.split(',')
                for index, attrib in enumerate(nested_attributes):
                    if attrib:
                        nested_attributes[index] = attrib.lstrip()
                        key, value = format_nested_incident_attribute(nested_attributes[index])
                        if key:
                            formatted_key = build_readable_attribute_key(key, attribute_name)
                            incident[formatted_key] = value
    return relevant_incidents


def format_nested_incident_attribute(attribute_value: str | None) -> tuple:  # type: ignore[return]
    """
    Format nested attributes to be readable. For example:
    for the attribute_value "srcIpAddr:192.168.1.1,",
    The formatted attribute will be: "srcIpAddr", and it's value is: "192.168.1.1".

    Args:
         attribute_value:str (str): The attribute cotent
    Returns:
        tuple: attribute key & value.
    """
    if not attribute_value:
        return None, None

    try:
        if attribute_value:
            attribute_parts = attribute_value.split(":")
            return attribute_parts[0], attribute_parts[1]
    except Exception:
        return None, None


def format_integer_field_to_verbal(incident: dict[str, Any]) -> dict[str, Any]:
    """
    Format some of the ENUM fields of incident to verbal.
    Args:
         incident: (Dict[str,Any]): Incident.
    Returns:
       Dict[str,Any]: updated incident.
    """
    fields_to_format = ['incidentStatus', 'incidentReso', 'phIncidentCategory']
    for field in fields_to_format:
        incident[field + 'Verbal'] = get_verbal_of_integer_field(field, incident.get(field))
    return incident


def get_verbal_of_integer_field(field_name: str, field_value: Any) -> str:
    """
    Retrieve a verbal value of the field.
    Args:
         field_name: (str): The field name to format.
         field_value: (Any): The current value of the field.
    Returns:
      str: Verbal value of the field.
    """
    mapper, default_value = get_mapping_for_verbal_incident_attrib(field_name)
    return mapper.get(field_value) or default_value


def get_mapping_for_verbal_incident_attrib(field_name: str) -> tuple:
    """
    Retrieve a The right mapping and default value based on the field name.
    Args:
         field_name: (str): The field name to retrieve it's matched mapping.
    Returns:
      tuple: Mapping dict & default value.
    """
    routing = {
        'incidentStatus': (INCIDENT_STATUS_INT_VERBAL_MAPPING, 'ACTIVE'),
        'incidentReso': (INCIDENT_RESOLUTION_INT_VERBAL_MAPPING, 'None'),
        'phIncidentCategory': (INCIDENT_CATEGORY_INT_VERBAL_MAPPING, 'AVAILABILITY')
    }
    return routing.get(field_name)  # type: ignore[return-value]


def build_readable_attribute_key(key: str, attribute_name: str):
    """
    Formatting nested attribute name to be more readable, and convenient to display in fetch incident command.
    For the input of "srcIpAddr", "incidentSrc" the formatted key will be: "source_ipAddr".
    Args:
         key: (str): The that was extracted from the original incident attribute vale.
         attribute_name (str): The original incident attribute.
    Returns:
        str: Formatted key.
    """
    key_prefix = ''  # for better readable layout in the incident source&target.
    key_suffix = ''
    if 'Src' in attribute_name:
        key_prefix = 'source_'
    elif 'Target' in attribute_name:
        key_prefix = 'target_'

    if key_prefix:
        if 'ipaddr' in key.lower():
            key_suffix = 'ipAddr'
        elif 'hostname' in key.lower():
            key_suffix = 'hostName'
        else:
            key_suffix = key
    else:
        key_suffix = key  # prefix is empty
    return key_prefix + key_suffix


def validate_fetch_params(max_fetch: int, max_events_fetch: int, fetch_events: bool, first_fetch: str,
                          status_filter_list: list) -> None:
    """
    Validate the parameters for fetch incident command.
    Args:
         max_fetch: (int): The maximum number of incidents for one fetch.
         max_events_fetch(int) The maximum number of events per incident for one fetch.
         fetch_events(bool): Whether or not fetch events when fetching incident.
        first_fetch: (str): First fetch time in words.
        status_filter_list (list): list of status filters for incidents.
    """
    if not first_fetch:
        return_error("Please provide First fetch timestamp.")
    else:
        arg_to_datetime(first_fetch)  # verify that it is a date.

    if max_fetch > MAX_FETCH:
        return_error(f"The Maximum number of incidents per fetch should not exceed {MAX_FETCH}.")
    if fetch_events and max_events_fetch > MAX_EVENTS_FETCH:
        return_error(
            f"The Maximum number of events for each incident per fetch should not exceed {MAX_EVENTS_FETCH}.")
    if not status_filter_list:
        return_error("Status filtering for fetch incidents should be provided.")


def convert_verbal_status_filtering_to_numeric(verbal_status_list: List[str]) -> List[int]:
    """
    Convert verbal status list to numeric status for filtering incidents in fetch incidents command.
    Args:
         verbal_status_list: (List[str]): Status list to filter incidents with.
    Returns:
      List[int]: Numeric status list to filter incidents with.
    """
    status_set = set(verbal_status_list)
    if ALL_STATUS_FILTER in status_set:
        return list(INCIDENT_STATUS_INT_VERBAL_MAPPING.keys())
    return [INCIDENT_STATUS_VALUE_MAPPING[verbal_status] for verbal_status in verbal_status_list]


def format_list_events_output(response: dict[str, Any], incident_id: str, page: int, limit: int) -> list:
    """
    Format event list command output.
    Args:
        response (Dict[str,Any]): FortiSIEM API response.
        incident_id (str): The ID of the incident to connect to the event.
        page (int): Which page to retrieve.
        limit (int): The maximum number of records to retrieve in a page.
    Returns:
      list: Formatted list events command outputs.
    """
    formatted_events, _ = format_list_commands_output(response, [], page, limit)
    for event in formatted_events:
        event['incidentId'] = incident_id
        # To avoid overridden by XSOAR since it's a huge number.
        event['id'] = str(event['id'])
        event['attributes']['Event ID'] = str(dict_safe_get(event, ['attributes', 'Event ID']))
    return formatted_events


def get_list_events_readable_output(outputs: List[dict]) -> List[dict]:
    """
    Get the human readable of event list command.
    Args:
        outputs (Dict[str,Any]): command outputs.
    Returns:
      List[dict]: Human readable table.
    """
    readable_outputs = []
    for event in outputs:
        attributes = event.get('attributes')
        readable_outputs.append({
            "eventReceiveTime": event.get('receiveTime'),
            "eventID": event.get('id'),
            "eventType": event.get('eventType'),
            "message": attributes.get('rawMessage') or event.get('msg'),  # type: ignore[union-attr]
            "sourceIP": attributes.get("Source IP") or attributes.get('srcIpAddr'),  # type: ignore[union-attr]
            "destinationIP": attributes.get("Destination IP") or attributes.get('destIpAddr'),  # type: ignore[union-attr]
            "hostName": attributes.get("Host Name") or attributes.get('hostName'),  # type: ignore[union-attr]
            "hostIp": attributes.get("Host IP") or attributes.get('hostIpAddr'),  # type: ignore[union-attr]
            "user": attributes.get("User") or attributes.get('user'),  # type: ignore[union-attr]
            "fileName": attributes.get("File Name") or attributes.get('fileName'),  # type: ignore[union-attr]
            "command": attributes.get("Command") or attributes.get('command'),  # type: ignore[union-attr]
            "filePath": attributes.get("File Path") or attributes.get('filePath'),  # type: ignore[union-attr]
            "SHA256Hash": attributes.get("SHA256 Hash") or attributes.get('hashSHA256'),  # type: ignore[union-attr]
            "MD5Hash": attributes.get("MD5 Hash") or attributes.get('hashMD5'),  # type: ignore[union-attr]
            "rawEventLog": attributes.get("Raw Event Log") or attributes.get('rawEventMsg'),  # type: ignore[union-attr]
        })
    return readable_outputs


def datetime_to_age_out_in_days(age_out_date: datetime) -> str:
    """
    Convert age out parameter from datetime value to the the required format in FortiSIEM API.
    Args:
        age_out_date (Dict[str,Any]): datetime.
    Returns:
      str: age out in FortiISEM required format.
    """
    if age_out_date:
        now = datetime.utcnow()
        delta = now - age_out_date
        days = delta.days  # interested in interval only.
        return f'{days}d'
    return None  # type: ignore[return-value]


def update_last_run_obj(last_run: dict[str, Any], formatted_incidents: List[dict]):
    cur_last_incident: dict = formatted_incidents[-1]
    cur_last_incident_create_time = cur_last_incident.get('incidentFirstSeen')
    cur_incidents_id: list = [incident.get('incidentId') for incident in formatted_incidents]
    prev_last_incident_create_time = last_run.get('create_time')
    if cur_last_incident_create_time == prev_last_incident_create_time and prev_last_incident_create_time:
        # stack the incidents ID.
        last_run['last_incidents'] += cur_incidents_id
        last_run['start_index'] += len(cur_incidents_id)
    else:  # flush old incidents ID
        last_run = {
            'create_time': cur_last_incident_create_time,
            'last_incidents': cur_incidents_id,
            'start_index': 0
        }
    return last_run


def main() -> None:
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    url = params.get('url')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    username = params['credentials']['identifier']
    password = params['credentials']['password']
    max_fetch = arg_to_number(params.get('max_fetch', DEFAULT_FETCH))
    first_fetch = params.get('first_fetch')
    fetch_with_events = params.get('fetch_mode') == 'Fetch With Events'
    max_events_fetch = arg_to_number(params.get('max_events_fetch', DEFAULT_EVENTS_FETCH))
    status_filter_list = argToList(params.get('status'))
    headers = {}  # type: ignore[var-annotated]

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        client: FortiSIEMClient = FortiSIEMClient(urljoin(url, ''), verify_certificate, proxy, headers=headers,
                                                  auth=(f'super/{username}', password))

        commands = {
            'fortisiem-event-search-status': events_search_status_command,
            'fortisiem-event-search-results': events_search_results_command,
            'fortisiem-cmdb-devices-list': cmdb_devices_list_command,

            'fortisiem-cmdb-device-get': cmdb_device_get_command,

            'fortisiem-monitored-organizations-list': monitored_organizations_list_command,

            'fortisiem-event-list-by-incident': events_list_command,

            'fortisiem-incident-update': incident_update_command,

            'fortisiem-watchlist-list': watchlist_list_command,

            'fortisiem-watchlist-get': watchlist_get_command,

            'fortisiem-watchlist-add': watchlist_add_command,

            'fortisiem-watchlist-entry-add': watchlist_entry_add_command,

            'fortisiem-watchlist-entry-update': watchlist_entry_update_command,

            'fortisiem-watchlist-delete': watchlist_delete_command,

            'fortisiem-watchlist-entry-delete': watchlist_entry_delete_command,
            'fortisiem-watchlist-entry-get': watchlist_entry_get_command

        }

        if command == 'test-module':
            test_module(client, max_fetch, fetch_with_events, max_events_fetch, params.get('first_fetch'),
                        status_filter_list)
        elif command == 'fetch-incidents':

            incidents, last_run = fetch_incidents(client, max_fetch,  # type: ignore[arg-type]
                                                  first_fetch,  # type: ignore[arg-type]
                                                  status_filter_list, fetch_with_events,
                                                  max_events_fetch, demisto.getLastRun())  # type: ignore[arg-type]

            demisto.setLastRun(last_run)
            demisto.incidents(incidents)

        elif command == 'fortisiem-event-search':
            if argToBoolean(args.get('polling')):
                return_results(search_events_with_polling_command(client, args, 'fortisiem-event-search',
                                                                  events_search_init_command,
                                                                  events_search_status_command,
                                                                  events_search_results_command))
            else:
                return_results(events_search_init_command(client, args))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        err_message = str(e)
        if 'Not authorized' in err_message:
            return_error(f"You are not authorized to use FortiSIEM. Please validate your username and password."
                         f"{err_message}")
        if 'HTTP Status 500 - Request failed' in err_message:
            return_error(f"Failed to execute the command. Please validate command arguments.{err_message}")
        return_error(err_message)


if __name__ in ['__main__', 'builtin', 'builtins', "__builtin__"]:
    main()
