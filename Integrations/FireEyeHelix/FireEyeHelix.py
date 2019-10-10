import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from typing import Dict, Tuple, List, Optional, Union, Any
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

"""GLOBALS/PARAMS
Attributes:
    INTEGRATION_NAME:
        Name of the integration as shown in the integration UI, for example: Microsoft Graph User.

    INTEGRATION_COMMAND_NAME:
        Command names should be written in all lower-case letters,
        and each word separated with a hyphen, for example: msgraph-user.

    INTEGRATION_CONTEXT_NAME:
        Context output names should be written in camel case, for example: MSGraphUser.

    ALERTS_TRANS
        Transformation map for alerts to be used with build_transformed_dict
"""
INTEGRATION_NAME = 'FireEye Helix'
INTEGRATION_COMMAND_NAME = 'fireeye-helix'
INTEGRATION_CONTEXT_NAME = 'FireEye'
ALERTS_TRANS = {
    'id': 'ID',
    'alert_type.id': 'AlertTypeID',
    'alert_type.name': 'Name',
    'assigned_to.id': 'AssigneeID',
    'assigned_to.name': 'AssigneeName',
    'created_by.id': 'CreatorID',
    'created_by.name': 'CreatorName',
    'updated_by.id': 'UpdaterID',
    'updated_by.name': 'UpdaterName',
    'created_at': 'CreatedTime',
    'updated_at': 'ModifiedTime',
    'alert_type_details.detail.processpath': 'ProcessPath',
    'alert_type_details.detail.process': 'Process',
    'alert_type_details.detail.pprocess': 'ParentProcess',
    'alert_type_details.detail.confidence': 'Confidence',
    'alert_type_details.detail.sha1': 'SHA1',
    'alert_type_details.detail.md5': 'MD5',
    'alert_type_details.detail.hostname': 'Hostname',
    'alert_type_details.detail.pid': 'PID',
    'alert_type_details.detail.byte': 'Size',
    'alert_type_details.detail.virus': 'Virus',
    'alert_type_details.detail.result': 'Result',
    'alert_type_details.detail.malwaretype': 'MalwareType',
    'alert_type_details.detail.filename': 'FileName',
    'alert_type_details.detail.regpath': 'RegPath',
    'alert_type_details.detail.eventtime': 'EventTime',
    'alert_type_details.detail.iocnames': 'IOCNames',
    'alert_type_details.detail.srcipv4': 'SourceIPv4',
    'alert_type_details.detail.srcipv6': 'SourceIPv6',
    'alert_type_details.detail.dstipv4': 'DestinationIPv4',
    'alert_type_details.detail.dstipv6': 'DestinationIPv6',
    'alert_type_details.detail.dstport': 'DestinationPort',
    'alert_type_details.detail.uri': 'URI',
    'alert_type_details.detail.domain': 'Domain',
    'alert_type_details.detail.useragent': 'UserAgent',
    'alert_type_details.detail.httpmethod': 'HttpMethod',
    'events_count': 'EventsCount',
    'notes_count': 'NotesCount',
    'closed_state': 'ClosedState',
    'closed_reason': 'ClosedReason',
    'description': 'Description',
    'first_event_at': 'FirstEventTime',
    'last_event_at': 'LastEventTime',
    'external_ips': 'ExternalIP',
    'internal_ips': 'InternalIP',
    'message': 'Message',
    'products': 'Products',
    'risk': 'Risk',
    'severity': 'Severity',
    'state': 'State',
    'tags': 'Tag',
    'type': 'Type',
}


class Client(BaseClient):
    def test_module(self) -> Dict:
        """Performs basic GET request to check if the API is reachable and authentication is successful.

        Returns:
            Response content
        """
        return self._http_request('GET', '/healthcheck', resp_type='content')

    def list_alerts(self, limit: Union[int, str] = None, offset: Union[int, str] = None) -> Dict:
        """Returns all alerts by sending a GET request.

        Args:
            limit: The maximum number of alerts to return.
            offset: The initial index from which to return the results.

        Returns:
            Response from API.
        """
        suffix = '/api/v3/alerts'
        # Dictionary of params for the request
        params = assign_params(
            limit=limit,
            offset=offset
        )
        # Send a request using our http_request wrapper
        return self._http_request('GET', suffix, params=params)

    def get_alert_by_id(self, _id: Optional[Any]) -> Dict:
        """Return a single alert by sending a GET request.

        Args:
            _id: ID  of the alert to get.

        Returns:
            Response from API.
        """
        suffix = f'/api/v3/alerts/{_id}'
        return self._http_request('GET', suffix)

    def update_alert_by_id(self, body: Dict) -> Dict:
        """Updates a single alert by sending a POST request.

        Args:
            body: Request body to update dictionary.

        Returns:
            Response from API.
        """
        suffix = f'/api/v3/alerts'
        return self._http_request('POST', suffix, json_data=body)

    def create_alert_note(self, _id: Optional[Any], note: Optional[Any]) -> Dict:
        """Creates a single note for an alert by sending a POST request.

        Args:
            _id: Alert ID to create note for.
            note: Note to add to alert.

        Returns:
            Response from API.
        """
        suffix = f'/api/v3/alerts/{_id}/notes'
        body = assign_params(note=note)
        return self._http_request('POST', suffix, json_data=body)

    def create_alert_case(self, alert_id: Optional[Any], name: str, status: str = None,
                          severity: Union[int, str] = None, tags: str = None, priority: str = None, state: str = None,
                          info_links: str = None, assigned_to: str = None, total_days_unresolved: str = None,
                          description: str = None, **kwargs) -> Dict:
        """Creates a single case for an alert by sending a POST request.

        Args:
            alert_id: Alert ID to create case for.
            name: Name of the case.
            status: Status of the case.
            severity: Severity of the case.
            tags: Tags of the case.
            priority: Priority of the case.
            state: State of the case.
            info_links: Info links of the case.
            assigned_to: Assignee list.
            total_days_unresolved: Total days the case is unresolved.
            description: Description of the case.

        Returns:
            Response from API.
        """
        suffix = f'/api/v3/alerts/{alert_id}/cases'
        body = assign_params(
            status=status,
            severity=severity,
            tags=tags,
            name=name,
            priority=priority,
            state=state,
            info_links=info_links,
            assigned_to=assigned_to,
            total_days_unresolved=total_days_unresolved,
            description=description
        )
        return self._http_request('POST', suffix, json_data=body)

    def get_events_by_alert(self, alert_id: Optional[Any]) -> Dict:
        """Fetches events for an alert by sending a GET request.

        Args:
            alert_id: Alert ID to get events for.

        Returns:
            Response from API.
        """
        suffix = f'/api/v3/alerts/{alert_id}/events'
        return self._http_request('GET', suffix)

    def get_endpoints_by_alert(self, alert_id: Optional[Any]) -> Dict:
        """Fetches endpoints for an alert by sending a GET request.

        Args:
            alert_id: Alert ID to get endpoints for.

        Returns:
            Response from API.
        """
        suffix = f'/api/v3/alerts/{alert_id}/endpoints'
        return self._http_request('GET', suffix)

    def get_cases_by_alert(self, alert_id: Optional[Any], limit: Optional[Any], offset: Optional[Any],
                           order_by: Optional[Any]) -> Dict:
        """Fetches cases for an alert by sending a GET request.

        Args:
            alert_id: Alert ID to get endpoints for.
            limit: Number of results to return per page.
            offset: The initial index from which to return the results.
            order_by: Which field to use when ordering the results.

        Returns:
            Response from API.
        """
        suffix = f'/api/v3/alerts/{alert_id}/cases'
        body = assign_params(
            limit=limit,
            offset=offset,
            order_by=order_by
        )
        return self._http_request('GET', suffix, json_data=body)

    def update_case(self, case_id: Optional[Any], assigned_to: List, status: Optional[Any]) -> Dict:
        """Updates a case by send a PATCH request.

        Args:
            case_id: ID of the case.
            assigned_to: List of case assignees.
            status: Status of the case.

        Returns:
            Response from API.
        """
        suffix = f'/api/v3/cases/{case_id}'
        params = assign_params(
            assigned_to=assigned_to,
            status=status
        )
        return self._http_request('PATCH', suffix, params=params)

    def get_event_by_id(self, event_id: Optional[Any]) -> Dict:
        """Fetches an event by id via a GET request.

        Args:
            event_id: ID of an event.

        Returns:
            Response from API.
        """
        suffix = f'/api/v1/events/{event_id}'
        return self._http_request('GET', suffix)

    def get_lists(self, limit: Union[int, str], offset: Union[int, str], created_at: str, description: str,
                  is_active: Union[str, bool], is_internal: Union[str, bool], is_protected: Union[str, bool], name: str,
                  short_name: str, type: str, updated_at: str, usage: str, order_by: str, **kwargs) -> Dict:
        """Fetches lists by a GET request

        Args:
            limit: Number of results to return per page.
            offset: The initial index from which to return the results.
            created_at: Creation date of the list.
            description: Description of the list.
            is_active: Set to true if the list is active.
            is_internal: Set to true if the list is internal.
            is_protected: Set to true if list is protected.
            name: Name of the list.
            short_name: Short name of the list.
            type: Type of the list.
            updated_at: The time the list was last updated at.
            usage: Multiple values may be separated by commas.
            order_by: Which field to use when ordering the results.

        Returns:
            Response from API.
        """
        suffix = '/api/v3/lists'
        params = assign_params(
            limit=limit,
            offset=offset,
            created_at=created_at,
            description=description,
            is_active=is_active and is_active != 'false',
            is_internal=is_internal and is_internal != 'false',
            is_protected=is_protected and is_protected != 'false',
            name=name,
            short_name=short_name,
            type=type,
            updated_at=updated_at,
            usage=usage,
            order_by=order_by
        )
        return self._http_request('GET', suffix, params=params)

    def get_list_by_id(self, list_id: Optional[Any]) -> Dict:
        """Get a list by id via a GET request

        Args:
            list_id: ID of the list

        Returns:
            Response from API.
        """
        suffix = f'/api/v3/lists/{list_id}'
        return self._http_request('GET', suffix)

    def create_list(self, name: str, short_name: str, is_internal: Union[str, bool], is_active: Union[str, bool],
                    is_protected: Union[str, bool], is_hidden: Union[str, bool], usage: str, type: str,
                    description: str, **kwargs) -> Dict:
        """Creates a list using a POST request

        Args:
            name: Name of the list.
            short_name: Short name of the list.
            is_internal: Boolean flag for is internal.
            is_active: Boolean flag for is active.
            is_protected: Boolean flag for is protected.
            is_hidden: Boolean flag for is hiddden.
            usage: Usage of the list.
            type: Type of the list.
            description: Description of the list.

        Returns:
            Response from API.
        """
        suffix = '/api/v3/lists'
        body = assign_params(
            name=name,
            short_name=short_name,
            is_internal=is_internal and is_internal != 'false',
            is_active=is_active and is_active != 'false',
            is_protected=is_protected and is_protected != 'false',
            is_hidden=is_hidden and is_hidden,
            usage=usage,
            type=type,
            description=description
        )
        return self._http_request('POST', suffix, json_data=body)

    def update_list(self, list_id: Union[str, int], name: str, short_name: str, is_internal: Union[str, bool],
                    is_active: Union[str, bool], is_protected: Union[str, bool], is_hidden: Union[str, bool],
                    usage: str, type: str, description: str, **kwargs) -> Dict:
        """Creates a list using a POST request

        Args:
            list_id: ID of the list.
            name: Name of the list.
            short_name: Short name of the list.
            is_internal: Boolean flag for is internal.
            is_active: Boolean flag for is active.
            is_protected: Boolean flag for is protected.
            is_hidden: Boolean flag for is hiddden.
            usage: Usage of the list.
            type: Type of the list.
            description: Description of the list.

        Returns:
            Response from API.
        """
        suffix = f'/api/v3/lists/{list_id}'
        body = assign_params(
            name=name,
            short_name=short_name,
            is_internal=is_internal and is_internal != 'false',
            is_active=is_active and is_active != 'false',
            is_protected=is_protected and is_protected != 'false',
            is_hidden=is_hidden and is_hidden,
            usage=usage,
            type=type,
            description=description
        )
        return self._http_request('PATCH', suffix, json_data=body)

    def delete_list(self, list_id: Optional[Any]) -> Dict:
        """Deletes a list using DELETE request

        Args:
            list_id: ID of a list.

        Returns:
            Response from API
        """
        suffix = f'/api/v3/lists/{list_id}'
        return self._http_request('DELETE', suffix)

    def list_sensors(self, limit: Union[int, str], offset: Union[int, str], hostname: str, status: str) -> Dict:
        """Fetches sensors using GET request

        Args:
            limit: Number of results to return per page.
            offset: The initial index from which to return the results.
            hostname: Host name of the sensor.
            status: Status of the sensor.

        Returns:
            Response from API
        """
        suffix = '/api/v3/sensors'
        params = assign_params(
            limit=limit,
            offset=offset,
            hostname=hostname,
            status=status
        )
        return self._http_request('GET', suffix, params=params)

    def list_rules(self, limit: Union[int, str], offset: Union[int, str], sort: str, **kwargs) -> Dict:
        """Fetches rules using GET request

        Args:
            limit: Number of results to return per page.
            offset: The initial index from which to return the results.
            sort: Comma-separated list of field names to sort the results by.

        Returns:
            Response from API
        """
        suffix = '/api/v1/rules'
        params = assign_params(
            limit=limit,
            offset=offset,
            sort=sort
        )
        return self._http_request('GET', suffix, params=params)

    def edit_rule(self, rule_id: Optional[Any], enabled: Union[str, bool]) -> Dict:
        """Edit a single rule using PATCH request

        Args:
            rule_id: ID of the rule.
            enabled: Is the rule enabled.

        Returns:
            Response from API
        """
        suffix = f'/api/v1/rules/{rule_id}'
        body = assign_params(enabled=enabled and enabled != 'false')
        return self._http_request('PATCH', suffix, json_data=body)


''' HELPER FUNCTIONS '''


def build_transformed_dict(src: Union[Dict, List], trans_dict: Dict) -> Union[Dict, List]:
    """Builds a dictionary according to a conversion map

    Args:
        src (dict): original dictionary to build from
        trans_dict (dict): dict in the format { 'OldKey': 'NewKey', ...}

    Returns: src copy with changed keys
    """
    if isinstance(src, list):
        return [build_transformed_dict(x, trans_dict) for x in src]
    res: Dict[str, Any] = {}
    for key, val in trans_dict.items():
        if isinstance(val, dict):
            # handle nested list
            sub_res = res
            item_val = [build_transformed_dict(item, val) for item in (demisto.get(src, key) or [])]
            key = underscoreToCamelCase(key)
            for sub_key in key.split('.')[:-1]:
                if sub_key not in sub_res:
                    sub_res[sub_key] = {}
                sub_res = sub_res[sub_key]
            sub_res[key.split('.')[-1]] = item_val
        elif '.' in val:
            # handle nested vals
            update_nested_value(res, val, to_val=demisto.get(src, key))
        else:
            res[val] = demisto.get(src, key)
    return res


def update_nested_value(src_dict: Dict[str, Any], to_key: str, to_val: Any):
    """
    Updates nested value according to transformation dict structure where 'a.b' key will create {'a': {'b': val}}
    Args:
        src_dict (dict): The original dict
        to_key (str): Key to transform to (expected to contain '.' to mark nested)
        to_val (any): The value that'll be put under the nested key
    """
    sub_res = src_dict
    to_key_lst = to_key.split('.')
    for sub_to_key in to_key_lst[:-1]:
        if sub_to_key not in sub_res:
            sub_res[sub_to_key] = {}
        sub_res = sub_res[sub_to_key]
    sub_res[to_key_lst[-1]] = to_val


''' COMMANDS '''


def test_module(client: Client, *_) -> Tuple[str, Dict, Dict]:
    """Performs a basic GET request to check if the API is reachable and authentication is successful.

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        'ok' if test successful.

    Raises:
        DemistoException: If test failed.
    """
    client.test_module()
    return 'ok', {}, {}


def fetch_incidents(
        client: Client,
        fetch_time: str,
        last_run: Optional[datetime] = None) -> Tuple[List, datetime]:
    """Uses to fetch incidents into Demisto
    Documentation: https://github.com/demisto/content/tree/master/docs/fetching_incidents

    Args:
        client: Client object with request
        fetch_time: From when to fetch if first time, e.g. `3 days`
        last_run: Last fetch object occurs.

    Returns:
        incidents, new last_run

    Examples:
        >>> client = Client('https://example.net/v1')
        >>> fetch_incidents(client, '3 days', datetime(2010, 1, 1, 0, 0))
    """
    timestamp_format = '%Y-%m-%dT%H:%M:%S'
    # Get incidents from API
    if not last_run:  # if first time running
        new_last_run, _ = parse_date_range(fetch_time)
        new_last_run = new_last_run.strftime(timestamp_format)
    else:
        new_last_run = last_run
    incidents: List = list()
    # raw_response = client.list_alerts(event_created_date_after=new_last_run)  # TODO: Adjust this
    raw_response = client.list_alerts()  # TODO: Adjust this
    events = raw_response.get('event')
    if events:
        # Creates incident entry
        incidents = [{
            'name': f"{INTEGRATION_NAME}: {event.get('eventId')}",
            'occurred': event.get('createdAt'),
            'rawJSON': json.dumps(event)
        } for event in events]

        last_incident_timestamp = incidents[-1].get('occurred')
        new_last_run = datetime.strptime(last_incident_timestamp, timestamp_format)
    # Return results
    return incidents, new_last_run


def list_alerts_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Lists all alerts and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    limit = args.get('limit')
    offset = args.get('offset')
    raw_response = client.list_alerts(limit=limit, offset=offset)
    alerts = raw_response.get('results')
    if alerts:
        title = f'{INTEGRATION_NAME} - List alerts:'
        context_entry = build_transformed_dict(alerts, ALERTS_TRANS)
        count = demisto.get(raw_response, 'meta.count')
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Alert(val.ID && val.ID === obj.ID)': context_entry,
            f'{INTEGRATION_CONTEXT_NAME}.Alert(val.Count).Count': count
        }
        human_readable = tableToMarkdown(title, context_entry, ['ID', 'Name', 'Description', 'State', 'Severity'])
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any alerts.', {}, {}


def get_alert_by_id_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Get alert by id and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    _id = args.get('id')
    raw_response = client.get_alert_by_id(_id=_id)
    if raw_response:
        title = f'{INTEGRATION_NAME} - Alert {_id}:'
        context_entry = build_transformed_dict(raw_response, ALERTS_TRANS)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Alert(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry, ['ID', 'Name', 'Description', 'State', 'Severity'])
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any alerts.', {}, {}


def update_alert_by_id_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Lists all events and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    _id = args.get('id')
    raw_response = client.update_alert_by_id(body=args)
    if raw_response:
        title = f'{INTEGRATION_NAME} - Updated Alert {_id}:'
        context_entry = build_transformed_dict(raw_response, {})  # TODO: edit this
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Alert(val.ID && val.ID === obj.ID)': context_entry  # TODO: Edit this
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any alerts.', {}, {}


def create_alert_note_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Create a note for an alert

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    _id = args.get('id')
    note = args.get('note')
    raw_response = client.create_alert_note(_id=_id, note=note)
    if raw_response:
        title = f'{INTEGRATION_NAME} - Created Note for Alert {_id}:'
        context_entry = build_transformed_dict(raw_response, {})  # TODO: edit this
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Note(val.ID && val.ID === obj.ID)': context_entry  # TODO: Edit this
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not create a note.', {}, {}


def create_alert_case_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Create a case for an alert

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    alert_id = args.get('id')
    raw_response = client.create_alert_case(**args)
    if raw_response:
        title = f'{INTEGRATION_NAME} - Updated Alert {alert_id}:'
        context_entry = build_transformed_dict(raw_response, {})  # TODO: edit this
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Note(val.ID && val.ID === obj.ID)': context_entry  # TODO: Edit this
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any cases.', {}, {}


def get_events_by_alert_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Get events for a specific alert

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    alert_id = args.get('id')
    raw_response = client.get_events_by_alert(alert_id=alert_id)
    events = raw_response.get('results')
    if events:
        title = f'{INTEGRATION_NAME} - Events for alert {alert_id}:'
        context_entry = build_transformed_dict(events, {})  # TODO: edit this
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Event(val.ID && val.ID === obj.ID)': context_entry  # TODO: Edit this
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any events.', {}, {}


def get_endpoints_by_alert_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Fetch endpoints of a specific alert

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    alert_id = args.get('id')
    raw_response = client.get_endpoints_by_alert(alert_id=alert_id)
    endpoints = demisto.get(raw_response, 'results.endpoints')
    if endpoints:
        title = f'{INTEGRATION_NAME} - Endpoints for alert {alert_id}:'
        context_entry = build_transformed_dict(endpoints, {})  # TODO: edit this
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Endpoint(val.ID && val.ID === obj.ID)': context_entry  # TODO: Edit this
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any endpoints.', {}, {}


def get_cases_by_alert_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Fetch cases of a specific alert

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    alert_id = args.get('id')
    raw_response = client.get_cases_by_alert(alert_id=alert_id, limit=args.get('limit'), offset=args.get('offset'),
                                             order_by=args.get('order_by'))
    cases = raw_response.get('results.endpoints')
    if cases:
        title = f'{INTEGRATION_NAME} - Cases for alert {alert_id}:'
        context_entry = build_transformed_dict(cases, {})  # TODO: edit this
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Case(val.ID && val.ID === obj.ID)': context_entry  # TODO: Edit this
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any cases.', {}, {}


def update_case_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Update a case

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    case_id = args.get('id')
    raw_response = client.update_case(case_id=case_id, assigned_to=argToList(args.get('assigned_to')),
                                      status=args.get('status'))
    return f'{INTEGRATION_NAME} - Created case successfully.', {}, raw_response


def get_event_by_id_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Get event by id and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    _id = args.get('id')
    raw_response = client.get_event_by_id(event_id=_id)
    event = raw_response.get('events')
    if event:
        title = f'{INTEGRATION_NAME} - Event {_id}:'
        context_entry = build_transformed_dict(event, {})  # TODO: edit this
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Event(val.ID && val.ID === obj.ID)': context_entry  # TODO: Edit this
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any events.', {}, {}


def get_lists_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Get lists return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    raw_response = client.get_lists(**args)
    event = raw_response.get('events')
    if event:
        title = f'{INTEGRATION_NAME} - Lists:'
        context_entry = build_transformed_dict(event, {})  # TODO: edit this
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.List(val.ID && val.ID === obj.ID)': context_entry  # TODO: Edit this
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any lists.', {}, {}


def get_list_by_id_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Get a list by ID return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    list_id = args.get('id')
    raw_response = client.get_list_by_id(list_id)
    if raw_response:
        title = f'{INTEGRATION_NAME} - List {list_id}:'
        context_entry = build_transformed_dict(raw_response, {})  # TODO: edit this
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.List(val.ID && val.ID === obj.ID)': context_entry  # TODO: Edit this
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find the list.', {}, {}


def create_list_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Create a list. return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    raw_response = client.create_list(**args)
    return f'{INTEGRATION_NAME} - Created list successfully.', {}, raw_response


def update_list_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Update a list. return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    raw_response = client.update_list(**args)
    return f'{INTEGRATION_NAME} - Updated list successfully.', {}, raw_response


def delete_list_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Update a list. return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    list_id = args.get('list_id')
    raw_response = client.delete_list(list_id)
    return f'{INTEGRATION_NAME} - Deleted list successfully.', {}, raw_response


def list_sensors_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Lists all sensors and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    raw_response = client.list_sensors(**args)
    sensors = raw_response.get('results')
    if sensors:
        title = f'{INTEGRATION_NAME} - List sensors:'
        context_entry = build_transformed_dict(sensors, {})  # TODO: edit this
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Sensor(val.ID && val.ID === obj.ID)': context_entry  # TODO: Edit this
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any sensors.', {}, {}


def list_rules_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Lists all rules and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    raw_response = client.list_rules(**args)
    rules = raw_response.get('rules')
    if rules:
        title = f'{INTEGRATION_NAME} - List rules:'
        context_entry = build_transformed_dict(rules, {})  # TODO: edit this
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Rule(val.ID && val.ID === obj.ID)': context_entry  # TODO: Edit this
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any rules.', {}, {}


def edit_rule_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Edit a single rule and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs
    """
    rule_id = args.get('rule_id')
    raw_response = client.edit_rule(**args)
    rules = raw_response.get('rules')
    if rules:
        title = f'{INTEGRATION_NAME} - Successfully updated rule {rule_id}:'
        context_entry = build_transformed_dict(rules, {})  # TODO: edit this
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Rule(val.ID && val.ID === obj.ID)': context_entry  # TODO: Edit this
        }
        # Creating human readable for War room
        human_readable = tableToMarkdown(title, context_entry)
        # Return data to Demisto
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find matching rule.', {}, {}


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():  # pragma: no cover
    params = demisto.params()
    base_url = f"{params.get('url', '').rstrip('/')}"
    if not base_url.endswith('/helix/id'):
        base_url += '/helix/id'
    base_url += f"/{params.get('h_id')}"
    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy')
    headers = {
        'accept': 'application/json',
        'x-fireeye-api-key': params.get('token')
    }
    client = Client(base_url=base_url, verify=verify_ssl, proxy=proxy, headers=headers)
    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    # Switch case
    commands = {
        'test-module': test_module,
        'fetch-incidents': fetch_incidents,
        f'{INTEGRATION_COMMAND_NAME}-list-alerts': list_alerts_command,
        f'{INTEGRATION_COMMAND_NAME}-get-alert-by-id': get_alert_by_id_command,
        f'{INTEGRATION_COMMAND_NAME}-update-alert': update_alert_by_id_command,
        f'{INTEGRATION_COMMAND_NAME}-alert-create-note': create_alert_note_command,
        f'{INTEGRATION_COMMAND_NAME}-alert-create-case': create_alert_case_command,
        f'{INTEGRATION_COMMAND_NAME}-get-events-by-alert': get_events_by_alert_command,
        f'{INTEGRATION_COMMAND_NAME}-get-endpoints-by-alert': get_endpoints_by_alert_command,
        f'{INTEGRATION_COMMAND_NAME}-get-cases-by-alert ': get_cases_by_alert_command,
        f'{INTEGRATION_COMMAND_NAME}-update-case': update_case_command,
        f'{INTEGRATION_COMMAND_NAME}-get-event-by-id': get_event_by_id_command,
        f'{INTEGRATION_COMMAND_NAME}-get-lists': get_lists_command,
        f'{INTEGRATION_COMMAND_NAME}-get-list-by-id': get_list_by_id_command,
        f'{INTEGRATION_COMMAND_NAME}-create-list': create_list_command,
        f'{INTEGRATION_COMMAND_NAME}-update-list': update_list_command,
        f'{INTEGRATION_COMMAND_NAME}-delete-list': delete_list_command,
        f'{INTEGRATION_COMMAND_NAME}-list-sensors': list_sensors_command,
        f'{INTEGRATION_COMMAND_NAME}-list-rules': list_rules_command,
        f'{INTEGRATION_COMMAND_NAME}-edit-rule': edit_rule_command,
    }
    try:
        if command == 'fetch-incidents':
            incidents, new_last_run = commands[command](client, last_run=demisto.getLastRun())  # type: ignore
            demisto.incidents(incidents)
            demisto.setLastRun(new_last_run)
        elif command in commands:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())  # type: ignore
            return_outputs(readable_output, outputs, raw_response)
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == 'builtins':  # pragma: no cover
    main()
