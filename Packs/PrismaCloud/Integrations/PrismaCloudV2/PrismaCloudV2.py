from copy import deepcopy

import urllib3

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

MAX_INCIDENTS_TO_FETCH = 200
FETCH_DEFAULT_TIME = '3 days'
FETCH_LOOK_BACK_TIME = 20

''' CONSTANTS '''

HEADERS = {'Content-Type': 'application/json'}
ACCEPT_HEADER_VALUE = 'application/json; charset=UTF-8'
RESPONSE_STATUS_HEADER = 'x-redlock-status'

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

RELATIVE_TIME_UNIT_OPTIONS = ('hour',
                              'day',
                              'week',
                              'month',
                              'year',
                              )
TO_NOW_TIME_UNIT_OPTIONS = ('day',
                            'week',
                            'month',
                            'year',
                            'epoch',  # account on-boarding
                            'login',  # last login
                            )
TIME_FILTER_BASE_CASE = {'type': 'to_now', 'value': 'epoch'}
ALERT_SEARCH_BASE_TIME_FILTER = {'type': 'relative', 'value': {'amount': 7, 'unit': 'day'}}

PAGE_NUMBER_DEFAULT_VALUE = 1
PAGE_SIZE_DEFAULT_VALUE = 50
PAGE_SIZE_MAX_VALUE = 10000

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, username, password):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers)
        self.generate_auth_token(username, password)

    def generate_auth_token(self, username: str, password: str):
        """
        Logins and generates a JSON Web Token (JWT) for authorization.
        The token is valid for 10 minutes.
        """
        data = {'username': username, 'password': password}
        headers = self._headers
        headers['accept'] = ACCEPT_HEADER_VALUE

        response = self._http_request('POST', 'login', json_data=data, headers=headers)
        try:
            token = response.get('token')
            if not token:
                raise DemistoException(f'Could not retrieve token from server: {response.get("message")}', res=response)
        except ValueError as exception:
            raise DemistoException('Could not parse API response.', exception=exception)

        self._headers['x-redlock-auth'] = token

    def alert_dismiss_request(self, alert_ids, policy_ids, dismissal_note, dismissal_time_range, time_range, filters):
        data = remove_empty_values_from_dict({'alerts': alert_ids,
                                              'policies': policy_ids,
                                              'dismissalNote': dismissal_note,
                                              'dismissalTimeRange': dismissal_time_range,
                                              'filter': {
                                                  'timeRange': time_range,
                                                  'filters': handle_filters(filters),
                                              }})

        self._http_request('POST', 'alert/dismiss', json_data=data, resp_type='response')

    def alert_get_details_request(self, alert_id: str, detailed: str):
        params = assign_params(detailed=detailed)

        response = self._http_request('GET', f'alert/{alert_id}', params=params)

        return response

    def alert_filter_list_request(self):
        response = self._http_request('GET', 'filter/alert/suggest')

        return response

    def remediation_command_list_request(self, time_filter: Dict[str, Any], alert_ids: List[str] = None,
                                         policy_ids: List[str] = None):
        data = remove_empty_values_from_dict({'alerts': alert_ids,
                                              'filter': {'timeRange': time_filter},  # all other filters are ignored by API
                                              'policies': policy_ids})

        response = self._http_request('POST', 'alert/remediation', json_data=data)

        return response

    def alert_remediate_request(self, alert_id: str):
        headers = self._headers
        headers['Accept'] = ACCEPT_HEADER_VALUE

        self._http_request('PATCH', f'alert/remediation/{alert_id}', headers=headers, resp_type='response')

    def alert_reopen_request(self, alert_ids, policy_ids, time_range, filters):
        data = remove_empty_values_from_dict({'alerts': alert_ids,
                                              'policies': policy_ids,
                                              'dismissalTimeRange': time_range,  # todo from postman seems like can be removed
                                              'filter': {
                                                  'timeRange': time_range,
                                                  'filters': handle_filters(filters),
                                              }})

        headers = self._headers
        headers['Accept'] = ACCEPT_HEADER_VALUE  # todo check if needed (with resp_type)

        self._http_request('POST', 'alert/reopen', json_data=data, headers=headers, resp_type='response')

    def alert_search_request(self, time_range, filters: List[str], limit=None, offset=None, detailed=None,
                             sort_by=None, page_token=None):
        params = assign_params(detailed=detailed)
        data = remove_empty_values_from_dict({'limit': limit,
                                              'offset': offset,
                                              'filters': handle_filters(filters),
                                              'timeRange': time_range,
                                              'sortBy': sort_by,
                                              'pageToken': page_token
                                              })
        demisto.info(f'Executing Prisma Cloud alert search with payload: {data}')

        headers = self._headers
        headers['Accept'] = 'application/json; charset=UTF-8'  # todo check if needed

        response = self._http_request('POST', 'v2/alert', params=params, json_data=data, headers=headers)

        return response

    def config_search_request(self, time_range, query, limit, search_id, sort_direction, sort_field):
        data = remove_empty_values_from_dict({'id': search_id,
                                              'limit': limit,
                                              'query': query,
                                              'sort': [{'direction': sort_direction, 'field': sort_field}],
                                              'timeRange': time_range,
                                              })

        headers = self._headers
        headers['Accept'] = 'application/json; charset=UTF-8'

        response = self._http_request('POST', 'search/config', json_data=data, headers=headers)

        return response

    def event_search_request(self, time_range, filters: List[str], query, limit, alert_id, search_id, sort_direction, sort_field):
        data = remove_empty_values_from_dict({'alertId': alert_id,
                                              'id': search_id,
                                              'limit': limit,
                                              'query': query,
                                              'sort': [{'direction': sort_direction, 'field': sort_field}],
                                              'filters': handle_filters(filters),
                                              'timeRange': time_range,
                                              })

        headers = self._headers
        headers['Accept'] = 'application/json; charset=UTF-8'

        response = self._http_request('POST', 'search/event', json_data=data, headers=headers)

        return response

    def trigger_scan_request(self):
        response = self._http_request('POST', 'code/api/v1/scans/integrations')

        return response


''' HELPER FUNCTIONS '''


def format_url(url: str):
    return urljoin(url.replace('https://app', 'https://api'), '')


def extract_nested_values(readable_response: dict, nested_headers: Dict[str, str]):
    for nested_name, new_name in nested_headers.items():
        nested_name_parts = nested_name.split('.')

        nested_value = readable_response
        for index, part in enumerate(nested_name_parts):
            nested_value = nested_value.get(part)
            if index == (len(nested_name_parts) - 1):
                readable_response[new_name] = nested_value
            elif not nested_value:
                break


def change_timestamp_to_datestring_in_dict(readable_response: dict):
    time_fields = ['firstSeen', 'lastSeen', 'alertTime', 'eventOccurred', 'lastUpdated', 'insertTs', 'createdTs']
    for field in time_fields:
        if epoch_value := readable_response.get(field):
            readable_response[field] = timestamp_to_datestring(epoch_value, DATE_FORMAT)


def convert_date_to_unix(date_str: str) -> int:
    """
    Convert the given string to milliseconds since epoch.
    """
    date = dateparser.parse(date_str, settings={"TIMEZONE": "UTC"})
    return int((date - datetime.utcfromtimestamp(0)).total_seconds() * 1000)


def handle_time_filter(base_case: Dict[str, Any] = None, unit_value: str = None, amount_value: int = None, time_from: str = None,
                       time_to: str = None) -> Optional[Dict[str, Any]]:
    """
    Create the relevant time filter to be sent in the POST request body, under "timeRange".
    This doesn't deal with the way it should be sent in the GET request parameters.
    """
    if (time_from or time_to) and (unit_value or amount_value):
        raise DemistoException('Too many arguments provided. You cannot specify absolute times ("time_range_date_from", '
                               '"time_range_date_to") with relative times ("time_range_unit", "time_range_value").')

    if unit_value:
        if amount_value:
            # amount is only for relative time - defines a window of time from a given point of time in the past until now
            if unit_value not in RELATIVE_TIME_UNIT_OPTIONS:
                raise DemistoException(
                    f'Time unit for relative time must be one of the following: {",".join(RELATIVE_TIME_UNIT_OPTIONS)}.')
            return {'type': 'relative', 'value': {'amount': arg_to_number(amount_value), 'unit': unit_value}}

        else:
            # using to_now time - represents a window of time from the start of the time unit given until now
            if unit_value not in TO_NOW_TIME_UNIT_OPTIONS:
                raise DemistoException(
                    f'Time unit for to_now time must be one of the following: {",".join(TO_NOW_TIME_UNIT_OPTIONS)}')
            return {'type': 'to_now', 'value': unit_value}

    elif time_to:
        # using absolute time
        if time_from:
            return {'type': 'absolute', 'value': {'startTime': convert_date_to_unix(time_from),
                                                  'endTime': convert_date_to_unix(time_to)}}
        else:
            # alert dismissal requires only an end time in the future
            return {'type': 'absolute', 'value': {'endTime': convert_date_to_unix(time_to)}}

    return base_case


def handle_filters(filters: List[str]):
    filters_to_send = []
    for filter_ in filters:
        split_filter = filter_.split('=')
        filters_to_send.append({'name': split_filter[0],
                                'operator': '=',
                                'value': split_filter[1]})
    return filters_to_send


def remove_empty_values_from_dict(dict_to_reduce: Dict[str, Any]):
    """
    Removes empty values from given dict and from the nested dicts in it.
    """
    reduced_dict = {}
    for key, value in dict_to_reduce.items():
        if value:
            if isinstance(value, dict):
                reduced_nested_dict = remove_empty_values_from_dict(value)
                if reduced_nested_dict:
                    reduced_dict[key] = reduced_nested_dict
            elif isinstance(value, list):
                reduced_list = []
                for item in value:
                    if isinstance(item, dict):
                        reduced_nested_dict = remove_empty_values_from_dict(item)
                        if reduced_nested_dict:
                            reduced_list.append(reduced_nested_dict)
                    elif item:
                        reduced_list.append(item)
                if reduced_list:
                    reduced_dict[key] = reduced_list
            else:
                reduced_dict[key] = value

    return reduced_dict


def get_response_status_header(response):
    if hasattr(response, 'headers'):
        return response.headers.get(RESPONSE_STATUS_HEADER, '')
    return ''


def calculate_offset(page_size: int, page_number: int) -> tuple[int, int]:
    """
    Prisma Cloud receives offset and limit arguments. To follow our convention, we receive page_size and page_number arguments and
    calculate the offset from them.
    The offset is the start point from which to retrieve values, zero based. It starts at 0.

    :param page_size: The number of results to show in one page.
    :param page_number: The page number to show, starts at 1.
    """
    if page_size > PAGE_SIZE_MAX_VALUE:
        raise DemistoException(f'Maximum value of "page_size" is {PAGE_SIZE_MAX_VALUE}.')

    return page_size, page_size * (page_number - 1)


''' FETCH HELPER FUNCTIONS '''


def get_filters(params: Dict[str, Any]) -> List[str]:
    filters = argToList(params.get('filters'))

    if rule_name := params.get('rule_name'):
        filters.append(f'alertRule.name={rule_name}')
    if policy_severity := params.get('policy_severity'):
        filters.append(f'policy.severity={policy_severity}')
    if policy_name := params.get('policy_name'):
        filters.append(f'policy.name={policy_name}')

    return filters


def translate_severity(alert):
    """
    Translate alert severity to demisto
    Might take risk grade into account in the future
    """
    severity = demisto.get(alert, 'policy.severity')
    if severity == 'high':
        return 3
    if severity == 'medium':
        return 2
    if severity == 'low':
        return 1
    return 0


def expire_stored_ids(fetched_ids: Dict[str, int], updated_last_run_time: int, look_back: int):
    """
    Expires stored ids when their alert time will not be fetched in the next fetch.

    Args:
        fetched_ids: Dict from fetched ids to the epoch alert time from Prisma Cloud.
        updated_last_run_time: epoch time for next fetch
        look_back: minutes to add to the next fetch time

    Returns:
        The dict of fetched ids that their time is after the next fetch time.
    """
    if not fetched_ids:
        return {}
    cleaned_cache = {}

    next_fetch_epoch = add_look_back(updated_last_run_time, look_back * 3)  # in case look_back will be increased

    for fetched_id, alert_time in fetched_ids.items():
        if alert_time > next_fetch_epoch:  # keep if it is later
            cleaned_cache[fetched_id] = alert_time
    return cleaned_cache


def calculate_fetch_time_range(now: int, first_fetch: str, look_back: int, last_run_time: int = None):
    if last_run_time:
        last_run_time = add_look_back(int(last_run_time), look_back)
    else:  # first fetch
        last_run_time = convert_date_to_unix(first_fetch)

    return {'type': 'absolute',
            'value': {
                'startTime': last_run_time,
                'endTime': now
            }}


def add_look_back(last_run_epoch_time: int, look_back_minutes: int):
    look_back_epoch = look_back_minutes * 60 * 1000
    return last_run_epoch_time - look_back_epoch


def fetch_request(client, fetched_ids, filters, limit, now, time_range):
    response = client.alert_search_request(time_range=time_range, filters=filters, detailed='true',
                                           sort_by=['alertTime:asc'])  # adding sort by 'id:asc' doesn't work
    response_items = response.get('items', [])
    updated_last_run_time = response_items[-1].get('alertTime') if response_items else now  # in epoch
    incidents = filter_alerts(fetched_ids, response.get('items'), limit)

    while len(incidents) < limit and response.get('nextPageToken') and response.get('items'):
        response = client.alert_search_request(time_range=time_range, filters=filters, detailed='true',
                                               sort_by=['alertTime:asc'], page_token=response.get('nextPageToken'))
        response_items = response.get('items', [])
        updated_last_run_time = response_items[-1].get('alertTime') if response_items else updated_last_run_time
        incidents.extend(filter_alerts(fetched_ids, response_items, limit))

    return incidents, fetched_ids, updated_last_run_time


def filter_alerts(fetched_ids: Dict[str, int], response_items: List, limit: int):
    incidents = []

    for alert in response_items:
        if alert.get('id') in fetched_ids:
            demisto.debug(f'Fetched {alert.get("id")} already. Skipping it now.')
            continue

        demisto.debug(f'{alert.get("id")} has not been fetched yet. Processing it now.')
        incidents.append(alert_to_incident_context(alert))
        fetched_ids[alert.get('id')] = alert.get('alertTime')

        if len(incidents) == limit:
            break

    return incidents


def alert_to_incident_context(alert):
    incident_context = {
        'name': alert.get('policy.name', 'No policy') + ' - ' + alert.get('id'),
        'occurred': timestamp_to_datestring(alert.get('alertTime'), DATE_FORMAT),
        'severity': translate_severity(alert),
        'rawJSON': json.dumps(alert)
    }
    demisto.debug(f'New PrismaCloud incident is: name: {incident_context["name"]}, occurred: '
                  f'{incident_context["occurred"]}, severity: {incident_context["severity"]}.')
    return incident_context


''' COMMAND FUNCTIONS '''


def alert_dismiss_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alert_ids = argToList(args.get('alert_ids'))
    policy_ids = argToList(args.get('policy_ids'))
    if not alert_ids and not policy_ids:
        raise DemistoException('You must provide either "alert_ids" or "policy_ids" for dismissing alerts.')

    dismissal_note = args.get('dismissal_note')
    filters = argToList(args.get('filters'))

    snooze_value = arg_to_number(args.get('snooze_value'))
    snooze_unit = args.get('snooze_unit')
    dismissal_time_filter = handle_time_filter(unit_value=snooze_unit, amount_value=snooze_value) \
        if snooze_value and snooze_unit else None
    time_filter = handle_time_filter(base_case=dismissal_time_filter or TIME_FILTER_BASE_CASE,
                                     unit_value=args.get('time_range_unit'),
                                     amount_value=arg_to_number(args.get('time_range_value')),
                                     time_from=args.get('time_range_date_from'),
                                     time_to=args.get('time_range_date_to'))

    client.alert_dismiss_request(alert_ids, policy_ids, dismissal_note, dismissal_time_filter, time_filter, filters)

    command_results = CommandResults(
        readable_output=(f'### Alerts snoozed successfully.\nSnooze note: {dismissal_note}.'
                         if dismissal_time_filter
                         else f'### Alerts dismissed successfully.\nDismissal note: {dismissal_note}.')
    )
    return command_results


def alert_get_details_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alert_id = args.get('alert_id')
    detailed = args.get('detailed', 'true')

    response = client.alert_get_details_request(alert_id, detailed)
    change_timestamp_to_datestring_in_dict(response)

    readable_response = deepcopy(response)
    nested_headers = {'id': 'Alert ID',
                      'policy.policyId': 'Policy ID',
                      'policy.policyType': 'Policy Type',
                      'policy.systemDefault': 'Is Policy System Default',
                      'policy.remediable': 'Is Policy Remediable',
                      'policy.name': 'Policy Name',
                      'policy.recommendation': 'Policy Recommendation',
                      'policy.description': 'Policy Description',
                      'policy.severity': 'Policy Severity',
                      'policy.remediation.description': 'Policy Remediation Description',
                      'policy.remediation.cliScriptTemplate': 'Policy Remediation CLI Script',
                      'policy.labels': 'Policy Labels',
                      'resource.resourceType': 'Resource Type',
                      'resource.account': 'Resource Account',
                      'resource.cloudType': 'Resource Cloud Type',
                      'resource.rrn': 'Resource RRN',
                      'resource.id': 'Resource ID',
                      'resource.accountId': 'Resource Account ID',
                      'resource.regionId': 'Resource Region ID',
                      'resource.resourceApiName': 'Resource Api Name',
                      'resource.url': 'Resource Url',
                      }
    headers = ['Alert ID', 'reason', 'status', 'alertTime', 'firstSeen', 'lastSeen', 'lastUpdated', 'eventOccurred'] \
              + list(nested_headers.values())[1:]
    extract_nested_values(readable_response, nested_headers)

    command_results = CommandResults(
        outputs_prefix='PrismaCloud.Alert',
        outputs_key_field='id',
        readable_output=tableToMarkdown(f'Alert {alert_id} Details:',
                                        readable_response,
                                        headers=headers,
                                        removeNull=True,
                                        url_keys=['Resource Url'],
                                        headerTransform=pascalToSpace),
        outputs=response,
        raw_response=response
    )
    return command_results


def alert_filter_list_command(client: Client) -> CommandResults:
    response = client.alert_filter_list_request()
    readable_response = [{'filterName': filter_name,
                          'options': filter_values.get('options'),
                          'staticFilter': filter_values.get('staticFilter')}
                         for filter_name, filter_values in response.items()]

    command_results = CommandResults(
        outputs_prefix='PrismaCloud.AlertFilters',
        outputs_key_field='filterName',
        readable_output=tableToMarkdown('Filter Options:',
                                        readable_response,
                                        removeNull=True,
                                        headerTransform=pascalToSpace),
        outputs=readable_response,
        raw_response=readable_response
    )
    return command_results


def remediation_command_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alert_ids = argToList(args.get('alert_ids'))
    policy_ids = argToList(args.get('policy_ids'))
    if not alert_ids and not policy_ids:
        raise DemistoException('You must provide either "alert_ids" or "policy_ids".')

    time_filter = handle_time_filter(base_case=TIME_FILTER_BASE_CASE,
                                     unit_value=args.get('time_range_unit'),
                                     amount_value=arg_to_number(args.get('time_range_value')),
                                     time_from=args.get('time_range_date_from'),
                                     time_to=args.get('time_range_date_to'))

    try:
        response = client.remediation_command_list_request(time_filter, alert_ids, policy_ids)
        description = response.get('cliDescription')
        script_impact = response.get('scriptImpact')
        readable_response = [{'description': description,
                              'scriptImpact': script_impact,
                              'alertId': alert_id,
                              'CLIScript': cli_script}
                             for alert_id, cli_script in response.get('alertIdVsCliScript', {}).item()]

    except DemistoException as de:
        if de.res.status_code == 405:
            raise DemistoException('Remediation unavailable.', exception=de)
        raise

    command_results = CommandResults(
        outputs_prefix='PrismaCloud.Alert.Remediation',
        outputs_key_field='id',
        readable_output=tableToMarkdown('Remediation Command List:',
                                        readable_response,
                                        removeNull=True,
                                        headerTransform=pascalToSpace),
        outputs=readable_response,
        raw_response=readable_response
    )
    return command_results


def alert_remediate_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alert_id = args.get('alert_id')

    try:
        client.alert_remediate_request(alert_id)

    except DemistoException as de:
        if de.res.status_code == 405:
            raise DemistoException(f'Remediation unavailable for alert {alert_id}.', exception=de)
        elif de.res.status_code == 404:
            raise DemistoException(f'Alert {alert_id} is not found.', exception=de)
        raise

    command_results = CommandResults(
        readable_output=f'Alert {alert_id} remediated successfully.',
    )
    return command_results


def alert_reopen_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alert_ids = argToList(args.get('alert_ids'))
    policy_ids = argToList(args.get('policy_ids'))
    if not alert_ids and not policy_ids:
        raise DemistoException('You must provide either "alert_ids" or "policy_ids" for re-opening alerts.')

    filters = argToList(args.get('filters'))
    time_filter = handle_time_filter(base_case=TIME_FILTER_BASE_CASE,
                                     unit_value=args.get('time_range_unit'),
                                     amount_value=arg_to_number(args.get('time_range_value')),
                                     time_from=args.get('time_range_date_from'),
                                     time_to=args.get('time_range_date_to'))

    client.alert_reopen_request(alert_ids, policy_ids, time_filter, filters)

    command_results = CommandResults(
        readable_output='### Alerts re-opened successfully.'
    )
    return command_results


def alert_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    filters = argToList(args.get('filters'))
    detailed = args.get('detailed', 'true')
    limit, offset = calculate_offset(page_size=arg_to_number(args.get('page_size')) or PAGE_SIZE_DEFAULT_VALUE,
                                     page_number=arg_to_number(args.get('page')) or PAGE_NUMBER_DEFAULT_VALUE)
    time_filter = handle_time_filter(base_case=ALERT_SEARCH_BASE_TIME_FILTER,
                                     unit_value=args.get('time_range_unit'),
                                     amount_value=arg_to_number(args.get('time_range_value')),
                                     time_from=args.get('time_range_date_from'),
                                     time_to=args.get('time_range_date_to'))

    response = client.alert_search_request(time_filter, filters, limit, offset, detailed)
    response_items = response.get('items', [])
    for response_item in response_items:
        change_timestamp_to_datestring_in_dict(response_item)

    readable_responses = deepcopy(response_items)
    nested_headers = {'id': 'Alert ID',
                      'policy.policyId': 'Policy ID',
                      'policy.policyType': 'Policy Type',
                      'policy.systemDefault': 'Is Policy System Default',
                      'policy.remediable': 'Is Policy Remediable',
                      'policy.name': 'Policy Name',
                      'policy.deleted': 'Is Policy Deleted',
                      'policy.recommendation': 'Policy Recommendation',
                      'policy.description': 'Policy Description',
                      'policy.severity': 'Policy Severity',
                      'policy.remediation.description': 'Policy Remediation Description',
                      'policy.remediation.cliScriptTemplate': 'Policy Remediation CLI Script',
                      'resource.resourceType': 'Resource Type',
                      'resource.name': 'Resource Name',
                      'resource.account': 'Resource Account',
                      'resource.cloudType': 'Resource Cloud Type',
                      'resource.rrn': 'Resource RRN',
                      }
    headers = ['Alert ID', 'reason', 'status', 'alertTime', 'firstSeen', 'lastSeen', 'lastUpdated'] \
              + list(nested_headers.values())[1:]
    for readable_response in readable_responses:
        extract_nested_values(readable_response, nested_headers)

    command_results = CommandResults(
        outputs_prefix='PrismaCloud.Alert',
        outputs_key_field='id',
        readable_output=tableToMarkdown('Alerts Details:',
                                        readable_responses,
                                        headers=headers,
                                        removeNull=True,
                                        headerTransform=pascalToSpace),
        outputs=response_items,
        raw_response=response_items
    )
    return command_results


def config_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    query = args.get('query')
    limit = arg_to_number(args.get('limit', '100'))
    time_filter = handle_time_filter(base_case=ALERT_SEARCH_BASE_TIME_FILTER,
                                     unit_value=args.get('time_range_unit'),
                                     amount_value=arg_to_number(args.get('time_range_value')),
                                     time_from=args.get('time_range_date_from'),
                                     time_to=args.get('time_range_date_to'))
    search_id = args.get('search_id')
    sort_direction = args.get('sort_direction', 'desc')
    sort_field = args.get('sort_field', 'insertTs')
    if any([sort_direction, sort_field]) and not all([sort_direction, sort_field]):
        raise DemistoException('Both sort direction and field must be specified if sorting.')

    response = client.config_search_request(time_filter, query, limit, search_id, sort_direction, sort_field)
    response_items = response.get('data', {}).get('items', [])
    for response_item in response_items:
        change_timestamp_to_datestring_in_dict(response_item)

    headers = ['name', 'id', 'cloudType', 'service', 'accountName', 'regionName', 'deleted', 'accountId', 'assetId', 'createdTs',
               'insertTs', 'regionId', 'resourceType', 'rrn']
    command_results = CommandResults(
        outputs_prefix='PrismaCloud.Config',
        outputs_key_field='id',
        readable_output=tableToMarkdown('Configuration Details:',
                                        response_items,
                                        headers=headers,
                                        removeNull=True,
                                        headerTransform=pascalToSpace),
        outputs=response_items,
        raw_response=response_items
    )
    return command_results


def event_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    query = args.get('query')
    limit = arg_to_number(args.get('limit', '100'))
    filters = argToList(args.get('filters'))
    time_filter = handle_time_filter(base_case=ALERT_SEARCH_BASE_TIME_FILTER,
                                     unit_value=args.get('time_range_unit'),
                                     amount_value=arg_to_number(args.get('time_range_value')),
                                     time_from=args.get('time_range_date_from'),
                                     time_to=args.get('time_range_date_to'))
    alert_id = args.get('alert_id')
    search_id = args.get('search_id')
    sort_direction = args.get('sort_direction', 'desc')
    sort_field = args.get('sort_field', 'insertTs')
    if any([sort_direction, sort_field]) and not all([sort_direction, sort_field]):
        raise DemistoException('Both sort direction and field must be specified if sorting.')

    response = client.event_search_request(time_filter, filters, query, limit, alert_id, search_id, sort_direction, sort_field)
    response_items = response.get('data', {}).get('items', [])
    for response_item in response_items:
        change_timestamp_to_datestring_in_dict(response_item)

    headers = ['subject', 'accountName', 'regionName', 'name', 'source', 'ip', 'eventTs', 'countryName', 'stateName', 'cityName',
               'location', 'anomalyId']
    # more fields not it UI: 'account', 'regionId', 'type', 'id', 'accessKeyUsed', 'role', 'flaggedFeature', 'success', 'internal'

    command_results = CommandResults(
        outputs_prefix='PrismaCloud.Event',
        outputs_key_field='id',
        readable_output=tableToMarkdown('Event Details:',
                                        response_items,
                                        headers=headers,
                                        removeNull=True,
                                        headerTransform=pascalToSpace),
        outputs=response_items,
        raw_response=response_items
    )
    return command_results


def trigger_scan_command(client: Client) -> CommandResults:
    response = client.trigger_scan_request()

    command_results = CommandResults(
        readable_output=tableToMarkdown('Trigger Scan Results:',
                                        response,
                                        removeNull=False,
                                        headerTransform=pascalToSpace),
    )
    return command_results


def test_module(client: Client) -> str:
    # Authorization is done in client.generate_auth_token
    return 'ok'


''' MAIN FUNCTION '''


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = format_url(params.get('url'))
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    username = params['credentials']['identifier']
    password = params['credentials']['password']

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        urllib3.disable_warnings()
        client: Client = Client(url, verify_certificate, proxy, headers=HEADERS, username=username, password=password)
        commands_without_args = {
            'test-module': test_module,
            'prisma-cloud-alert-filter-list': alert_filter_list_command,  # redlock-list-alert-filters
            'prisma-cloud-trigger-scan': trigger_scan_command,
        }
        commands_with_args = {
            'prisma-cloud-alert-dismiss': alert_dismiss_command,  # redlock-dismiss-alerts
            'prisma-cloud-alert-get-details': alert_get_details_command,  # redlock-get-alert-details
            'prisma-cloud-remediation-command-list': remediation_command_list_command,  # redlock-get-remediation-details
            'prisma-cloud-alert-remediate': alert_remediate_command,
            'prisma-cloud-alert-reopen': alert_reopen_command,  # redlock-reopen-alerts
            'prisma-cloud-alert-search': alert_search_command,  # redlock-search-alerts
            'prisma-cloud-config-search': config_search_command,  # redlock-get-rql-response, redlock-search-config
            'prisma-cloud-event-search': event_search_command,  # redlock-search-event
            'prisma-cloud-network-search': '',  # redlock-search-network
            # redlock-get-scan-status (deprecated)
            # redlock-list-scans (deprecated)

            'prisma-cloud-error-file-list': '',  # similar to redlock-get-scan-results (deprecated)
            'prisma-cloud-resource-get': '',
            'prisma-cloud-account-list': '',
            'prisma-cloud-account-status-get': '',
            'prisma-cloud-account-owner-list': '',
        }

        if command in commands_without_args:
            return_results(commands_without_args[command](client))
        elif command in commands_with_args:
            return_results(commands_with_args[command](client, args))
        elif command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            incidents, fetched_ids, last_run_time = fetch_incidents(client, last_run, params)
            demisto.incidents(incidents)
            demisto.setLastRun({
                'fetched_ids': fetched_ids,
                'time': last_run_time
            })
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        error_msg = str(e)
        if hasattr(e, 'res'):
            error_msg += get_response_status_header(e.res)
        return_error(error_msg, error=e)


''' ENTRY POINT '''

if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
