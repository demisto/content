import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from copy import deepcopy

import urllib3


''' CONSTANTS '''

HEADERS = {'Content-Type': 'application/json; charset=UTF-8', 'Accept': 'application/json; charset=UTF-8'}
REQUEST_CSPM_AUTH_HEADER = 'x-redlock-auth'  # Prisma Cloud Security Posture Management
REQUEST_CCS_AUTH_HEADER = 'authorization'  # Prisma Cloud Code Security
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
ERROR_TOO_MANY_ARGS = 'Too many arguments provided. You cannot specify absolute times ("time_range_date_from", ' \
                      '"time_range_date_to") with relative times ("time_range_unit", "time_range_value").'
ERROR_NOT_ENOUGH_ARGS = 'Not enough arguments provided. You cannot specify "time_range_date_from" without ' \
                        '"time_range_date_to", or "time_range_value" without "time_range_unit".'
ERROR_RELATIVE_TIME_UNIT = f'Time unit for relative time must be one of the following: {", ".join(RELATIVE_TIME_UNIT_OPTIONS)}.'
ERROR_TO_NOW_TIME_UNIT = f'Time unit for to_now time must be one of the following: {", ".join(TO_NOW_TIME_UNIT_OPTIONS)}'

MAX_INCIDENTS_TO_FETCH = 200
FETCH_DEFAULT_TIME = '3 days'
FETCH_LOOK_BACK_TIME = 20

MIRROR_DIRECTION_MAPPING = {
    "None": None,
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}

INCIDENT_INCOMING_MIRROR_ARGS = ['status', 'dismissalNote', 'reason', 'policy.name']
INCIDENT_INCOMING_MIRROR_CLOSING_STATUSES = ['dismissed', 'resolved', 'snoozed']
INCIDENT_INCOMING_MIRROR_REOPENING_STATUS = 'open'
INCIDENT_OUTGOING_MIRROR_DISMISSAL_NOTE = 'Closed by XSOAR'

PAGE_NUMBER_DEFAULT_VALUE = 1
PAGE_SIZE_DEFAULT_VALUE = 50
PAGE_SIZE_MAX_VALUE = 10000

DEFAULT_LIMIT = '50'

PRISMA_TO_XSOAR_SEVERITY = {
    'critical': IncidentSeverity.CRITICAL,
    'high': IncidentSeverity.HIGH,
    'medium': IncidentSeverity.MEDIUM,
    'low': IncidentSeverity.LOW,
    'informational': IncidentSeverity.INFO
}

FINDING_TYPES_OPTIONS = ['guard_duty_host', 'guard_duty_iam', 'inspector_sbp', 'compliance_cis', 'host_vulnerability_cve']
RISK_FACTORS_OPTIONS = ['CRITICAL_SEVERITY', 'HIGH_SEVERITY', 'MEDIUM_SEVERITY', 'HAS_FIX', 'REMOTE_EXECUTION', 'DOS',
                        'RECENT_VULNERABILITY', 'EXPLOIT_EXISTS', 'ATTACK_COMPLEXITY_LOW', 'ATTACK_VECTOR_NETWORK',
                        'REACHABLE_FROM_THE_INTERNET', 'LISTENING_PORTS', 'CONTAINER_IS_RUNNING_AS_ROOT',
                        'NO_MANDATORY_SECURITY_PROFILE_APPLIED', 'RUNNING_AS_PRIVILEGED_CONTAINER', 'PACKAGE_IN_USE']

CATEGORIES_OPTIONS = ['IAM', 'Compute', 'Monitoring', 'Networking', 'Kubernetes', 'General', 'Storage', 'Secrets', 'Public',
                      'Vulnerabilities', 'Drift', 'BuildIntegrity', 'Licenses']
FILE_TYPES_OPTIONS = ['tf', 'json', 'yml', 'yaml', 'template', '.checkov.baseline', 'hcl', 'Dockerfile', 'package.json',
                      'package-lock.json', 'bower.json', 'pom.xml', 'build.gradle', 'build.gradle.kts', 'gradle.properties',
                      'gradle-wrapper.properties', 'go.sum', 'go.mod', 'requirements.txt', 'METADATA', 'bicep', 'Pipfile.lock',
                      'Pipfile', 'yarn.lock', 'Gemfile', 'Gemfile.lock', 'gemspec', 'env', 'settings.py', 'main.py',
                      'application.py', 'config.py', 'app.js', 'config.js', 'dev.js', 'db.properties', 'application.properties',
                      'private.pem', 'privatekey.pem', 'index.php', 'config.php', 'config.xml', 'strings.xml', 'app.module.ts',
                      'environment.ts', 'tpl', 'tfvars', 'unknown']
SEARCH_OPTIONS_OPTIONS = ['path', 'code']
SEARCH_TITLE_OPTIONS = ['title', 'constructive_title', 'descriptive_title']
SEVERITIES_OPTIONS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
SOURCE_TYPES_OPTIONS = ['Github', 'Bitbucket', 'Gitlab', 'AzureRepos', 'cli', 'AWS', 'Azure', 'GCP', 'Docker',
                        'githubEnterprise', 'gitlabEnterprise', 'bitbucketEnterprise', 'terraformCloud', 'githubActions',
                        'circleci', 'codebuild', 'jenkins', 'tfcRunTasks', 'admissionController', 'terraformEnterprise']
STATUSES_OPTIONS = ['Errors', 'Suppressed', 'Passed', 'Fixed']

TIME_FIELDS = ['firstSeen', 'lastSeen', 'alertTime', 'eventOccurred', 'lastUpdated', 'insertTs', 'createdTs', 'lastModifiedTs',
               'addedOn', 'eventTs', 'createdOn', 'updatedOn', 'rlUpdatedOn']

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, server_url: str, verify: bool, proxy: bool, headers: Dict[str, str], username: str, password: str,
                 mirror_direction: str | None, close_incident: bool, close_alert: bool):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers)
        self.mirror_direction = mirror_direction
        self.close_incident = close_incident
        self.close_alert = close_alert
        self.generate_auth_token(username, password)

    def generate_auth_token(self, username: str, password: str) -> None:
        """
        Logins and generates a JSON Web Token (JWT) for authorization.
        The token is valid for 10 minutes.
        """
        data = {'username': username, 'password': password}

        response = self._http_request('POST', 'login', json_data=data)
        try:
            token = response.get('token')
            if not token:
                raise DemistoException(f'Could not retrieve token from server: {response.get("message")}', res=response)
        except ValueError as exception:
            raise DemistoException('Could not parse API response.', exception=exception) from exception

        self._headers[REQUEST_CSPM_AUTH_HEADER] = token

    def alert_filter_list_request(self):
        return self._http_request('GET', 'filter/alert/suggest')

    def alert_search_request(self, time_range: Dict[str, Any], filters: List[str], limit: Optional[int] = None,
                             detailed: Optional[str] = None, page_token: Optional[str] = None,
                             sort_by: Optional[List[str]] = None):
        params = assign_params(detailed=detailed)
        data = remove_empty_values({'limit': limit,
                                    'filters': handle_filters(filters),
                                    'timeRange': time_range,
                                    'sortBy': sort_by,
                                    'pageToken': page_token
                                    })
        demisto.info(f'Executing Prisma Cloud alert search with payload: {data}')

        return self._http_request('POST', 'v2/alert', params=params, json_data=data)

    def alert_get_details_request(self, alert_id: str, detailed: Optional[str] = None):
        params = assign_params(detailed=detailed)

        response = self._http_request('GET', f'alert/{alert_id}', params=params)
        self._concatenate_url(response, 'resource.url')

        return response

    def _concatenate_url(self, response: Dict[str, Any], url_field: str = 'url') -> None:
        """
        Concatenates a url suffix with the base url for the places where only a suffix is returned, so urls we display will be
        clickable and lead to a real place.
        Updates the dict given.
        """
        split_url_field = url_field.split('.')
        if len(split_url_field) > 1:
            self._concatenate_url(response.get(split_url_field[0], {}), '.'.join(split_url_field[1:]))

        elif url_field in response:
            url = urljoin(self._base_url, response[url_field]).replace('https://api', 'https://app')
            response[url_field] = url

    def alert_dismiss_request(self, dismissal_note: str, time_range: Dict[str, Any], alert_ids: Optional[List[str]] = None,
                              policy_ids: Optional[List[str]] = None, dismissal_time_range: Optional[Dict[str, Any]] = None,
                              filters: Optional[List[str]] = None):
        data = remove_empty_values({'alerts': alert_ids,
                                    'policies': policy_ids,
                                    'dismissalNote': dismissal_note,
                                    'dismissalTimeRange': dismissal_time_range,
                                    'filter': {
                                        'timeRange': time_range,
                                        'filters': handle_filters(filters),
                                    }})

        self._http_request('POST', 'alert/dismiss', json_data=data, resp_type='response')

    def alert_reopen_request(self, time_range: Dict[str, Any], alert_ids: Optional[List[str]] = None,
                             policy_ids: Optional[List[str]] = None, filters: Optional[List[str]] = None):
        data = remove_empty_values({'alerts': alert_ids,
                                    'policies': policy_ids,
                                    'dismissalTimeRange': time_range,
                                    'filter': {
                                        'timeRange': time_range,
                                        'filters': handle_filters(filters),
                                    }})

        self._http_request('POST', 'alert/reopen', json_data=data, resp_type='response')

    def remediation_command_list_request(self, time_range: Dict[str, Any], alert_ids: Optional[List[str]] = None,
                                         policy_id: Optional[str] = None):
        data = remove_empty_values({'alerts': alert_ids,
                                    'filter': {'timeRange': time_range},  # all other filters are ignored by API
                                    'policies': [policy_id]})

        return self._http_request('POST', 'alert/remediation', json_data=data)

    def alert_remediate_request(self, alert_id: str):
        self._http_request('PATCH', f'alert/remediation/{alert_id}', resp_type='response')

    def config_search_request(self, time_range: Dict[str, Any], query: str, limit: Optional[int] = None,
                              search_id: Optional[str] = None, sort_direction: Optional[str] = None,
                              sort_field: Optional[str] = None):
        data = remove_empty_values({'id': search_id,
                                    'limit': limit,
                                    'query': query,
                                    'sort': [{'direction': sort_direction, 'field': sort_field}],
                                    'timeRange': time_range,
                                    })

        return self._http_request('POST', 'search/config', json_data=data)

    def event_search_request(self,
                             time_range: Dict[str, Any],
                             query: str,
                             limit: Optional[int] = None,
                             sort_by: Optional[List[Dict[str, str]]] = None):
        data = remove_empty_values({'limit': limit,
                                    'query': query,
                                    'timeRange': time_range,
                                    'sort': sort_by,
                                    })

        return self._http_request('POST', 'search/event', json_data=data)

    def network_search_request(self, query: str, time_range: Dict[str, Any], search_id: Optional[str] = None,
                               cloud_type: Optional[str] = None):
        data = remove_empty_values({'cloudType': cloud_type,
                                    'id': search_id,
                                    'query': query,
                                    'timeRange': time_range,
                                    })

        return self._http_request('POST', 'search', json_data=data)

    def resource_get_request(self, rrn: str):
        data = remove_empty_values({'rrn': rrn})

        return self._http_request('POST', 'resource', json_data=data)

    def account_list_request(self, exclude_account_group_details: str):
        data = remove_empty_values({'excludeAccountGroupDetails': exclude_account_group_details})

        return self._http_request('GET', 'cloud', json_data=data)

    def account_status_get_request(self, account_id: str):
        return self._http_request('GET', f'account/{account_id}/config/status')

    def account_owner_list_request(self, account_id: str):
        return self._http_request('GET', f'cloud/{account_id}/owners')

    def host_finding_list_request(self, rrn: str, finding_types: Optional[List[str]] = None,
                                  risk_factors: Optional[List[str]] = None):
        data = remove_empty_values({'rrn': rrn,
                                    'findingType': finding_types,
                                    'riskFactors': risk_factors})

        return self._http_request('POST', 'resource/external_finding', json_data=data)

    def permission_list_request(self, query: str, limit: int, user_id: Optional[str] = None):
        data = remove_empty_values({'id': user_id,
                                    'limit': limit,
                                    'query': query})

        return self._http_request('POST', 'api/v1/permission', json_data=data)

    def permission_list_next_page_request(self, next_token: str, limit: int):
        data = remove_empty_values({'limit': limit,
                                    'pageToken': next_token})

        return self._http_request('POST', 'api/v1/permission/page', json_data=data)

    # Prisma Cloud Code Security module requests

    def trigger_scan_request(self):
        headers = self._headers
        headers[REQUEST_CCS_AUTH_HEADER] = headers.pop(REQUEST_CSPM_AUTH_HEADER)

        return self._http_request('POST', 'code/api/v1/scans/integrations', headers=headers)

    def error_file_list_request(self, repository: str, source_types: List[str], cicd_run_id: Optional[float] = None,
                                authors: Optional[List[str]] = None, branch: Optional[str] = None,
                                categories: Optional[List[str]] = None, code_status: Optional[str] = None,
                                file_types: Optional[List[str]] = None, repository_id: Optional[str] = None,
                                search_options: Optional[List[str]] = None, search_text: Optional[str] = None,
                                search_title: Optional[str] = None, severities: Optional[List[str]] = None,
                                tags: Optional[List[str]] = None, statuses: Optional[List[str]] = None):
        data = remove_empty_values({'CICDRunId': cicd_run_id,
                                    'authors': authors,
                                    'branch': branch,
                                    'categories': categories,
                                    'codeStatus': [code_status],
                                    'fileTypes': file_types,
                                    'repository': repository,
                                    'repositoryId': repository_id,
                                    'severities': severities,
                                    'sourceTypes': source_types,
                                    'tags': handle_tags(tags),
                                    'types': statuses
                                    })
        if search_title:
            data['search'] = {'options': search_options,
                              'text': search_text,
                              'title': search_title}
        elif search_options or search_text:
            data['search'] = {'options': search_options,
                              'text': search_text}

        headers = self._headers
        headers[REQUEST_CCS_AUTH_HEADER] = headers.pop(REQUEST_CSPM_AUTH_HEADER)

        return self._http_request('POST', 'code/api/v1/errors/files', json_data=data, headers=headers)


''' HELPER FUNCTIONS '''


def format_url(url: str) -> str:
    """
    Formats the URL from the regular one (with 'app') to the API one (with 'api'), in order to support providing both options.
    """
    return urljoin(url.replace('https://app', 'https://api'), '')


def extract_nested_values(readable_response: dict, nested_headers: Dict[str, str]) -> None:
    """
    Extracts nested fields from readable_response according to nested_headers keys,
    and names them according to nested_headers values.
    Updates readable_response in place.
    """
    for nested_name, new_name in nested_headers.items():
        nested_name_parts = nested_name.split('.')

        nested_value = readable_response
        for index, part in enumerate(nested_name_parts):
            nested_value = nested_value.get(part)  # type: ignore[assignment]
            if index == (len(nested_name_parts) - 1):
                readable_response[new_name] = nested_value
            elif not nested_value:
                break


def change_timestamp_to_datestring_in_dict(readable_response: dict) -> None:
    """
    Changes the values of the time fields in the given response from epoch timestamp to human readable date format.
    """
    for field in TIME_FIELDS:
        if epoch_value := readable_response.get(field):
            readable_response[field] = timestamp_to_datestring(epoch_value, DATE_FORMAT)


def convert_date_to_unix(date_str: str) -> int:
    """
    Convert the given string to milliseconds since epoch.
    """
    if not (date := dateparser.parse(date_str, settings={'TIMEZONE': 'UTC'})):
        raise DemistoException(f'The date "{date_str}" given is not valid.')
    return int(date.timestamp() * 1000)


def handle_time_filter(base_case: Optional[Dict[str, Any]] = None, unit_value: Optional[str] = None,
                       amount_value: Optional[int] = None, time_from: Optional[str] = None,
                       time_to: Optional[str] = None) -> Dict[str, Any]:
    """
    Create the relevant time filter to be sent in the POST request body, under "timeRange".
    This doesn't deal with the way the time range should be sent in the GET request parameters.
    """
    if (time_from or time_to) and (unit_value or amount_value):
        raise DemistoException(ERROR_TOO_MANY_ARGS)
    elif (time_from and not time_to) or (amount_value and not unit_value):
        raise DemistoException(ERROR_NOT_ENOUGH_ARGS)

    if unit_value:
        if amount_value:
            # amount is only for relative time - defines a window of time from a given point of time in the past until now
            if unit_value not in RELATIVE_TIME_UNIT_OPTIONS:
                raise DemistoException(ERROR_RELATIVE_TIME_UNIT)
            return {'type': 'relative', 'value': {'amount': arg_to_number(amount_value), 'unit': unit_value}}

        else:
            # using to_now time - represents a window of time from the start of the time unit given until now
            if unit_value not in TO_NOW_TIME_UNIT_OPTIONS:
                raise DemistoException(ERROR_TO_NOW_TIME_UNIT)
            return {'type': 'to_now', 'value': unit_value}

    elif time_to:
        # using absolute time
        if time_from:
            return {'type': 'absolute', 'value': {'startTime': convert_date_to_unix(time_from),
                                                  'endTime': convert_date_to_unix(time_to)}}
        else:
            # alert dismissal requires only an end time in the future
            return {'type': 'absolute', 'value': {'endTime': convert_date_to_unix(time_to)}}

    return base_case or TIME_FILTER_BASE_CASE


def handle_filters(filters: Optional[List[str]]) -> List[Dict[str, Any]]:
    """
    Creates the list of filters in the format that the request expects.
    The filters are given from the user as a comma-separated list, in the format of filtername=filtervalue.
    """
    filters_to_send = []
    for filter_ in filters or []:
        split_filter = filter_.split('=')
        if len(split_filter) != 2 or not split_filter[0] or not split_filter[1]:
            raise DemistoException('Filters should be in the format of "filtername1=filtervalue1,filtername2=filtervalue2". '
                                   f'The filter "{filter_}" doesn\'t meet this requirement.')
        filters_to_send.append({'name': split_filter[0],
                                'operator': '=',
                                'value': split_filter[1]})
    return filters_to_send


def handle_tags(tags: Optional[List[str]]) -> List[Dict[str, Any]]:
    """
    Creates the list of tags in the format that the request expects.
    The tags are given from the user as a comma-separated list, in the format of tagkey=tagvalue.
    """
    tags_to_send = []
    if tags:
        for tag in tags:
            split_tag = tag.split('=')
            if len(split_tag) != 2 or not split_tag[0] or not split_tag[1]:
                raise DemistoException('Tags should be in the format of "tagkey1=tagvalue1,tagkey2=tagvalue2". '
                                       f'The tag "{tag}" doesn\'t meet this requirement.')
            tags_to_send.append({'key': split_tag[0],
                                 'value': split_tag[1]})
    return tags_to_send


def validate_array_arg(array_arg: List[str], arg_name: str, arg_options: List[str]) -> None:
    """
    Validates that all comma-separated provided arg values are in the available options.
    """
    if not set(array_arg).issubset(arg_options):
        raise DemistoException(f'{arg_name} values are unexpected, must be of the following: {", ".join(arg_options)}.')


def error_file_list_command_args_validation(source_types: List[str], categories: List[str], statuses: List[str],
                                            file_types: List[str], search_options: List[str], severities: List[str]) -> None:
    """
    Validates values for all multi-select args in 'prisma-cloud-error-file-list' command.
    """
    validate_array_arg(categories, 'Categories', CATEGORIES_OPTIONS)
    validate_array_arg(file_types, 'File types', FILE_TYPES_OPTIONS)
    validate_array_arg(search_options, 'Search options', SEARCH_OPTIONS_OPTIONS)
    validate_array_arg(severities, 'Severities', SEVERITIES_OPTIONS)
    validate_array_arg(source_types, 'Source types', SOURCE_TYPES_OPTIONS)
    validate_array_arg(statuses, 'Statuses', STATUSES_OPTIONS)


def remove_empty_values(value_to_reduce: Union[Dict[str, Any], List, Any]):
    """
    Removes empty values from given dict or list and from the nested dicts and lists in it.
    """
    if isinstance(value_to_reduce, dict):
        reduced_dict = {}
        for key, value in value_to_reduce.items():
            if reduced_nested_value := remove_empty_values(value):
                reduced_dict[key] = reduced_nested_value
        return reduced_dict

    elif isinstance(value_to_reduce, list):
        reduced_list = []
        for item in value_to_reduce:
            if reduced_nested_value := remove_empty_values(item):
                reduced_list.append(reduced_nested_value)
        return reduced_list

    return value_to_reduce


def get_response_status_header(response: requests.Response) -> str:
    """
    The status of the error raised from Prisma Cloud appears in the response header.
    This function returns the status header from the response got from Prisma Cloud.
    """
    if hasattr(response, 'headers'):
        return response.headers.get(RESPONSE_STATUS_HEADER, '')
    return ''


def calculate_offset(page_size: int, page_number: int) -> tuple[int, int]:
    """
    Prisma Cloud receives offset and limit arguments. To follow our convention, we receive page_size and page_number arguments and
    calculate the offset from them.
    The offset is the start point from which to retrieve values, zero based. It starts at 0.
    NOTICE: Currently the offset argument is not working in the API, so this is not used until further update by Prisma Cloud.

    :param page_size: The number of results to show in one page.
    :param page_number: The page number to show, starts at 1.
    """
    if page_size > PAGE_SIZE_MAX_VALUE:
        raise DemistoException(f'Maximum "page_size" value is {PAGE_SIZE_MAX_VALUE} (got {page_size}).')

    return page_size, page_size * (page_number - 1)


''' FETCH AND MIRRORING HELPER FUNCTIONS '''


def translate_severity(alert: Dict[str, Any]) -> float:
    """
    Translate alert severity to XSOAR
    """
    severity = alert.get('policy', {}).get('severity')
    return PRISMA_TO_XSOAR_SEVERITY.get(severity, IncidentSeverity.UNKNOWN)


def expire_stored_ids(fetched_ids: Dict[str, int], updated_last_run_time: int, look_back: int) -> Dict[str, int]:
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

    next_fetch_epoch = add_look_back(updated_last_run_time, look_back * 3)  # in case look_back needs to be increased
    # to avoid duplicate incidents, make sure that when increasing this value, to increase it up to a multiplier of 3 each time

    for fetched_id, alert_time in fetched_ids.items():
        if alert_time >= next_fetch_epoch:  # keep if it is later
            cleaned_cache[fetched_id] = alert_time
    return cleaned_cache


def calculate_fetch_time_range(now: int, first_fetch: str, look_back: int = 0, last_run_time: Optional[int] = None) -> \
        Dict[str, Any]:
    if last_run_time:
        last_run_time = add_look_back(int(last_run_time), look_back)
    else:  # first fetch
        last_run_time = convert_date_to_unix(first_fetch)

    return {'type': 'absolute',
            'value': {
                'startTime': last_run_time,
                'endTime': now
            }}


def add_look_back(last_run_epoch_time: int, look_back_minutes: int) -> int:
    look_back_epoch = look_back_minutes * 60 * 1000
    return last_run_epoch_time - look_back_epoch


def fetch_request(client: Client, fetched_ids: Dict[str, int], filters: List[str], limit: int, now: int,
                  time_range: Dict[str, Any]) -> tuple[List[Dict[str, Any]], Dict[str, int], int]:
    response = client.alert_search_request(time_range=time_range,
                                           filters=filters,
                                           detailed='true',
                                           sort_by=['alertTime:asc'],  # adding sort by 'id:asc' doesn't work
                                           limit=limit + len(fetched_ids),
                                           )
    response_items = response.get('items', [])
    updated_last_run_time_epoch = response_items[-1].get('alertTime') if response_items else now
    incidents = filter_alerts(client, fetched_ids, response_items, limit)

    # there is a 'nextPageToken' value even if we already got all the results
    while len(incidents) < limit and response.get('nextPageToken') and response.get('items'):
        # only page_token is being used, also sending other arguments because it is not stated clearly in the
        # API documentation
        response = client.alert_search_request(time_range=time_range,
                                               filters=filters,
                                               detailed='true',
                                               sort_by=['alertTime:asc'],
                                               limit=limit + len(fetched_ids),
                                               page_token=response.get('nextPageToken'),
                                               )
        response_items = response.get('items', [])
        updated_last_run_time_epoch = \
            response_items[-1].get('alertTime') if response_items else updated_last_run_time_epoch
        incidents.extend(filter_alerts(client, fetched_ids, response_items, limit, len(incidents)))

    return incidents, fetched_ids, updated_last_run_time_epoch


def filter_alerts(client: Client, fetched_ids: Dict[str, int], response_items: List[Dict[str, Any]], limit: int,
                  num_of_prev_incidents: int = 0) -> List[Dict[str, Any]]:
    incidents = []

    for alert in response_items:
        if alert.get('id') in fetched_ids:
            demisto.debug(f'Fetched {alert.get("id")} already. Skipping it now.')
            continue

        demisto.debug(f'Processing new fetched alert {alert.get("id")}.')
        add_mirroring_fields(client, alert)
        incidents.append(alert_to_incident_context(alert))
        fetched_ids[str(alert['id'])] = int(alert['alertTime'])

        if len(incidents) + num_of_prev_incidents >= limit:
            break

    return incidents


def add_mirroring_fields(client: Client, alert: Dict):
    """
    Updates the given Prisma Cloud fetched alert to hold the needed mirroring fields.

    Args:
        client: Demisto client.
        alert: The Prisma Cloud fetched alert.
    """
    alert['mirror_direction'] = client.mirror_direction
    alert['mirror_instance'] = demisto.integrationInstance()


def alert_to_incident_context(alert: Dict[str, Any]) -> Dict[str, Any]:
    incident_context = {
        'name': alert.get('policy', {}).get('name', 'No policy') + ' - ' + alert.get('id'),
        'occurred': timestamp_to_datestring(alert.get('alertTime'), DATE_FORMAT),
        'severity': translate_severity(alert),
        'rawJSON': json.dumps(alert)
    }
    demisto.debug(f'New PrismaCloud incident is: name: {incident_context["name"]}, occurred: '
                  f'{incident_context["occurred"]}, severity: {incident_context["severity"]}.')
    return incident_context


def get_remote_alert_data(client: Client, remote_alert_id: str) -> tuple[Dict, Dict]:
    """
    Called every time get-remote-data command runs on an alert.
    Gets the details of the relevant alert entity from the remote system (Prisma Cloud).
    Takes from the entity only the relevant incoming mirroring fields, and returns the updated_object for the incident
    selected to mirror in.

    Args:
        client: Demisto client.
        remote_alert_id: The id of the mirrored Prisma Cloud alert.

    Returns: The raw alert's details, and a dictionary contains only the mirrored fields and their values.
    """
    alert_details = client.alert_get_details_request(alert_id=remote_alert_id, detailed='true')

    updated_object: Dict[str, Any] = {}
    for field in INCIDENT_INCOMING_MIRROR_ARGS:
        mirrored_field_value = demisto.get(alert_details, field, '')
        if '.' in field:  # field is nested (currently it is only the policy.name field)
            # policy.name field was added to the mirrored fields cause this is the field that is used in the default classifier to
            # classify incident types. Without it, all mirrored alerts will be changed to the default incident type which is
            # 'Prisma Cloud'.
            split_field = field.split('.')
            updated_object[split_field[0]] = {split_field[1]: mirrored_field_value}
        else:
            updated_object[field] = mirrored_field_value
    return alert_details, updated_object


def close_incident_in_xsoar(remote_alert_id: str, mirrored_status: str, mirrored_dismissal_note: str) -> Dict:
    """
    Closes an XSOAR incident.

    Args:
        remote_alert_id: The id of the mirrored Prisma Cloud alert to be closed.
        mirrored_status: The status of the mirrored Prisma alert.
        mirrored_dismissal_note: The dismissal note of the mirrored Prisma alert.

    Returns: An entry object with relevant data for closing an XSOAR incident.
    """
    demisto.debug(f'Prisma Alert {remote_alert_id} was closed. Closing the mirrored incident in XSOAR')
    if mirrored_status == 'resolved' and mirrored_dismissal_note == '':
        mirrored_dismissal_note = 'resolved'

    closing_time = datetime.now()
    parsed_closing_time = closing_time.strftime(DATE_FORMAT)

    entry = {
        'Type': EntryType.NOTE,
        'Contents': {
            'dbotIncidentClose': True,
            'rawCloseReason': mirrored_status,
            'closeReason': f'Alert was {mirrored_status} on Prisma Cloud.',
            'closeNotes': mirrored_dismissal_note,
            'closed': parsed_closing_time
        },
        'ContentsFormat': EntryFormat.JSON
    }
    return entry


def reopen_incident_in_xsoar(remote_alert_id: str):
    """
    Reopens an XSOAR incident.

    Args:
        remote_alert_id:  The id of the mirrored Prisma Cloud alert to be reopened.

    Returns: An entry object with relevant data for reopening an XSOAR incident.
    """
    demisto.debug(f'Prisma Alert {remote_alert_id} was reopened. Reopening the incident on XSOAR.')
    entry = {
        'Type': EntryType.NOTE,
        'Contents': {
            'dbotIncidentReopen': True
        },
        'ContentsFormat': EntryFormat.JSON
    }
    return entry


def set_xsoar_incident_entries(updated_object: Dict[str, Any], remote_alert_id: str) -> Dict | None:
    """
    Extracts the status of the mirrored Prisma alert, and close/reopen the matched XSOAR incident in accordance.
    Args:
        updated_object: A dictionary contains the mirrored relevant fields.
        remote_alert_id: The id of the mirrored Prisma Cloud alert.

    Returns: An entry object with relevant data for closing or reopening an XSOAR incident.
    """
    mirrored_status = updated_object.get('status')
    if mirrored_status in set(INCIDENT_INCOMING_MIRROR_CLOSING_STATUSES):  # closing incident
        mirrored_dismissal_note = updated_object.get('dismissalNote', '')
        entry = close_incident_in_xsoar(remote_alert_id, mirrored_status, mirrored_dismissal_note)
        return entry
    elif mirrored_status == INCIDENT_INCOMING_MIRROR_REOPENING_STATUS:  # re-opening incident
        entry = reopen_incident_in_xsoar(remote_alert_id)
        return entry
    return None


def close_alert_in_prisma_cloud(client: Client, ids: List[str], delta: Dict[str, Any]):
    """
    Close (Dismiss) an alert in Prisma Cloud.

    Args:
        client: Demisto client.
        ids: The IDs of the alerts to be dismissed.
        delta: A dictionary of fields that changed from the last update - containing only the changed fields.

    Returns: None.

    """
    close_notes = delta.get('closeNotes')
    close_reason = delta.get('closeReason')
    dismissal_note = f'{INCIDENT_OUTGOING_MIRROR_DISMISSAL_NOTE} - Closing Reason: {close_reason}, ' \
                     f'Closing Notes: {close_notes}.'
    time_filter = handle_time_filter(base_case=TIME_FILTER_BASE_CASE)

    client.alert_dismiss_request(dismissal_note=dismissal_note, time_range=time_filter, alert_ids=ids)


def reopen_alert_in_prisma_cloud(client: Client, ids: List[str]):
    """
    Re-open an alert in Prisma Cloud.

    Args:
        client: Demisto client.
        ids: The IDs of the alerts to be re-opened.

    Returns: None.

    """
    time_filter = handle_time_filter(base_case=TIME_FILTER_BASE_CASE)
    client.alert_reopen_request(time_range=time_filter, alert_ids=ids)


def whether_to_close_in_prisma_cloud(user_selection: bool, delta: Dict[str, Any]) -> bool:
    """
    Closing in the remote system should happen only when both:
        1. The user asked for it.
        2. One of the closing fields appears in the delta.

    The second condition is mandatory so we will not send a closing request at all of the mirroring requests that happen
    after closing an incident (in case where the incident is updated so there is a delta, but it is not the status
    that was changed).

    Args:
        user_selection: True if the user wants to mirror out closing of an incident ('close_alert' integration parameter),
                        otherwise - False.
        delta: A dictionary of fields that changed from the last update - containing only the changed fields.

    Returns: True - if closing the prisma alert is needed, False - otherwise.

    """
    closing_fields = {'closeReason', 'closingUserId', 'closeNotes'}
    return user_selection and any(field in delta for field in closing_fields)


def whether_to_reopen_in_prisma_cloud(user_selection: bool, delta: Dict[str, Any]) -> bool:
    """
    Re-opening in the remote system should happen only when both:
        1. The user asked for it.
        2. The delta contains the 'closingUserId' field.

    The second condition is mandatory so we will not send a re-opening request in case where the incident is updated so there is
    a delta, but it is not the status that was changed.

    Args:
        user_selection: True if the user wants to mirror out re-opening of an incident ('close_alert' integration parameter),
                        otherwise - False.
        delta: A dictionary of fields that changed from the last update - containing only the changed fields.

    Returns: True - if re-opening the prisma alert is needed, False - otherwise.

    """
    return user_selection and 'closingUserId' in delta


def update_remote_alert(client: Client, delta: Dict[str, Any],
                        inc_status: IncidentStatus, incident_id: str):
    """
    Updates the remote prisma alert according to the changes of the mirrored xsaor incident.
    The possible updates are closing or re-opening the alert.

    When closing an incident in XSOAR the possible reasons are: False Positive, Duplicate, Other and Resolved.
    As a result, the remote Prisma alert will be closed with a 'Dismissed' status, and the reason and close notes will be added to
    the 'Reason' field of the remote alert.
    * It is not possible to close an incident as 'Resolved' in XSOAR and mark it as 'Resolved' in Prisma,
    it will be closed with a 'dismissed' status even if the selected reason is 'Resolved'.

    Args:
        client: Demisto client.
        delta: A dictionary of fields that changed from the last update - containing only the changed fields.
        inc_status: The status of the incident.
        incident_id: Contains the value of the dbotMirrorId field, which represents the ID of the alert in prisma.

    Returns: None.
    """
    # XSOAR incident was closed - closing the mirrored prisma alert
    if inc_status == IncidentStatus.DONE and whether_to_close_in_prisma_cloud(client.close_alert, delta):
        demisto.debug(f'Closing incident with remote ID {incident_id} in remote system.')
        close_alert_in_prisma_cloud(client, [incident_id], delta)
        demisto.debug(f'Remote Incident: {incident_id} was updated successfully.')

    # XSOAR incident was re-opened - re-opening the mirrored prisma alert
    elif inc_status == IncidentStatus.ACTIVE and whether_to_reopen_in_prisma_cloud(client.close_alert, delta):
        demisto.debug(f'Reopening incident with remote ID {incident_id} in remote system.')
        reopen_alert_in_prisma_cloud(client, [incident_id])
        demisto.debug(f'Remote Incident: {incident_id} was updated successfully.')

    else:
        demisto.debug(f"Skipping the update of remote incident {incident_id} as it has not closed or re-opened in XSOAR.")


''' V1 DEPRECATED COMMAND FUNCTIONS to support backwards compatibility '''

RISK_GRADE_NOT_SUPPORTED_MSG = 'In the new API version of Prisma Cloud, "risk-grade" argument is not supported ' \
                               'and therefore removed from the available command arguments.'


def get_v1_filters(args: Dict[str, Any]) -> List[str]:
    """
    Transform V1 arguments to V2 filters list.
    """
    filters = []
    args_name_to_filter_name = {
        'alert-status': 'alert.status',
        'policy-name': 'policy.name',
        'policy-label': 'policy.label',
        'policy-compliance-standard': 'policy.complianceStandard',
        'cloud-account': 'cloud.account',
        'cloud-account-id': 'cloud.accountId',
        'cloud-region': 'cloud.region',
        'alert-rule-name': 'alertRule.name',
        'resource-id': 'resource.id',
        'resource-name': 'resource.name',
        'resource-type': 'resource.type',
        'alert-id': 'alert.id',
        'cloud-type': 'cloud.type',
        'policy-type': 'policy.type',
        'policy-severity': 'policy.severity',
    }
    for arg_name, filter_name in args_name_to_filter_name.items():
        if arg_value := args.get(arg_name):
            filters.append(f'{filter_name}={arg_value}')

    return filters


def alert_to_v1_context(alert: Any, args: Dict[str, Any]) -> Dict[str, Any]:
    """
    This was copied from V1 and should not be maintained.
    Transform a single alert to context struct.
    """
    ec = {
        'ID': alert.get('id'),
        'Status': alert.get('status'),
        'AlertTime': alert.get('alertTime'),
        'Policy': {
            'ID': demisto.get(alert, 'policy.policyId'),
            'Name': demisto.get(alert, 'policy.name'),
            'Type': demisto.get(alert, 'policy.policyType'),
            'Severity': demisto.get(alert, 'policy.severity'),
            'Remediable': demisto.get(alert, 'policy.remediable')
        },
        'Resource': {
            'ID': demisto.get(alert, 'resource.id'),
            'Name': demisto.get(alert, 'resource.name'),
            'Account': demisto.get(alert, 'resource.account'),
            'AccountID': demisto.get(alert, 'resource.accountId')
        }
    }
    if 'resource_keys' in args:
        # if resource_keys argument was given, include those items from resource.data
        extra_keys = demisto.getArg('resource_keys')
        resource_data = {}
        keys = extra_keys.split(',')
        for key in keys:
            resource_data[key] = demisto.get(alert, f'resource.data.{key}')

        ec['Resource']['Data'] = resource_data

    if alert.get('alertRules'):
        ec['AlertRules'] = [alert_rule.get('name') for alert_rule in alert.get('alertRules')]

    return ec


def format_v1_response(response: Any) -> Any:
    """
    This was copied from V1 and should not be maintained.
    """
    if response and isinstance(response, dict):
        response = {pascalToSpace(key).replace(" ", ""): format_v1_response(value) for key, value in response.items()}
    elif response and isinstance(response, list):
        response = [format_v1_response(item) for item in response]
    return response


def alert_search_v1_command(client: Client, args: Dict[str, Any], return_v1_output: bool) -> \
        Union[CommandResults, List[Union[CommandResults, str]], Dict]:
    """
    This command is for supporting backwards compatibility, to make transition to V2 easier for users with custom playbooks.
    """
    new_args = {
        'time_range_unit': args.get('time-range-unit'),
        'time_range_value': args.get('time-range-value'),
        'time_range_date_from': args.get('time-range-date-from'),
        'time_range_date_to': args.get('time-range-date-to'),
        'filters': get_v1_filters(args),
        'limit': args.get('limit', DEFAULT_LIMIT),
        'detailed': 'true'
    }

    command_results = alert_search_command(client, new_args)
    if return_v1_output:
        response = command_results.raw_response

        context_path = 'Redlock.Alert(val.ID === obj.ID)'
        context: dict = {context_path: []}
        for alert in response:  # type: ignore[attr-defined]
            context[context_path].append(alert_to_v1_context(alert, args))
        context['Redlock.Metadata.CountOfAlerts'] = len(response)  # type: ignore[arg-type]

        command_results = command_results.to_context()
        command_results['EntryContext'].update(context)  # type: ignore[index]

    if args.get('risk-grade'):
        return [RISK_GRADE_NOT_SUPPORTED_MSG, command_results]

    return command_results


def alert_get_details_v1_command(client: Client, args: Dict[str, Any], return_v1_output: bool) -> Union[CommandResults, Dict]:
    """
    This command is for supporting backwards compatibility, to make transition to V2 easier for users with custom playbooks.
    """
    new_args = {
        'alert_id': args.get('alert-id')
    }

    command_results = alert_get_details_command(client, new_args)
    if return_v1_output:
        response = command_results.raw_response
        command_results = command_results.to_context()
        command_results['EntryContext'].update(  # type: ignore[index]
            {'Redlock.Alert(val.ID === obj.ID)': alert_to_v1_context(response, args)})
    return command_results


def alert_dismiss_v1_command(client: Client, args: Dict[str, Any], return_v1_output: bool) -> \
        Union[CommandResults, List[Union[CommandResults, str]], Dict]:
    """
    This command is for supporting backwards compatibility, to make transition to V2 easier for users with custom playbooks.
    """
    new_args = {
        'alert_ids': args.get('alert-id'),
        'policy_ids': args.get('policy-id'),
        'dismissal_note': args.get('dismissal-note'),
        'snooze_value': args.get('snooze-value'),
        'snooze_unit': args.get('snooze-unit'),
        'time_range_unit': args.get('time-range-unit'),
        'time_range_value': args.get('time-range-value'),
        'time_range_date_from': args.get('time-range-date-from'),
        'time_range_date_to': args.get('time-range-date-to'),
        'filters': get_v1_filters(args)
    }

    command_results = alert_dismiss_command(client, new_args)
    if return_v1_output and args.get('alert-id'):
        command_results = command_results.to_context()
        command_results['EntryContext'].update({'Redlock.DismissedAlert.ID': args.get('alert-id')})  # type: ignore[index]

    if args.get('risk-grade'):
        return [RISK_GRADE_NOT_SUPPORTED_MSG, command_results]

    return command_results


def alert_reopen_v1_command(client: Client, args: Dict[str, Any], return_v1_output: bool) -> \
        Union[CommandResults, List[Union[CommandResults, str]], Dict]:
    """
    This command is for supporting backwards compatibility, to make transition to V2 easier for users with custom playbooks.
    """
    new_args = {
        'alert_ids': args.get('alert-id'),
        'policy_ids': args.get('policy-id'),
        'time_range_unit': args.get('time-range-unit'),
        'time_range_value': args.get('time-range-value'),
        'time_range_date_from': args.get('time-range-date-from'),
        'time_range_date_to': args.get('time-range-date-to'),
        'filters': get_v1_filters(args)
    }

    command_results = alert_reopen_command(client, new_args)
    if return_v1_output and args.get('alert-id'):
        command_results = command_results.to_context()
        command_results['EntryContext'].update({'Redlock.ReopenedAlert.ID': args.get('alert-id')})  # type: ignore[index]

    if args.get('risk-grade'):
        return [RISK_GRADE_NOT_SUPPORTED_MSG, command_results]

    return command_results


def remediation_command_list_v1_command(client: Client, args: Dict[str, Any], return_v1_output: bool) -> \
        Union[CommandResults, Dict]:
    """
    This command is for supporting backwards compatibility, to make transition to V2 easier for users with custom playbooks.
    """
    new_args = {
        'alert_ids': args.get('alert-id'),
        'all_results': 'true'
    }

    command_results = remediation_command_list_command(client, new_args)
    if return_v1_output:
        response = command_results.raw_response

        context = []
        for alert in response:  # type: ignore[attr-defined]
            details = {
                'ID': alert.get('alertId'),
                'Remediation': {
                    'CLI': alert.get('CLIScript'),
                    'Description': alert.get('description')
                }
            }
            context.append(details)

        command_results = command_results.to_context()
        command_results['EntryContext'].update({'Redlock.Alert(val.ID == obj.ID)': context})  # type: ignore[index]
    return command_results


def rql_config_search_v1_command(client: Client, args: Dict[str, Any], return_v1_output: bool) -> Union[CommandResults, Dict]:
    """
    This command is for supporting backwards compatibility, to make transition to V2 easier for users with custom playbooks.
    """
    query = f'{args.get("rql")} limit search records to {args.get("limit", "1")}'
    new_args = {
        'query': query,
        'limit': args.get('limit', '1'),
    }

    command_results = config_search_command(client, new_args)
    if return_v1_output:
        rql_data = {'Query': query, 'Response': format_v1_response(command_results.raw_response)}

        command_results = command_results.to_context()
        command_results['EntryContext'].update({'Redlock.RQL(val.Query === obj.Query)': rql_data})  # type: ignore[index]
    return command_results


def config_search_v1_command(client: Client, args: Dict[str, Any], return_v1_output: bool) -> Union[CommandResults, Dict]:
    """
    This command is for supporting backwards compatibility, to make transition to V2 easier for users with custom playbooks.
    """
    new_args = {
        'query': args.get('query'),
        'limit': args.get('limit', '100'),
        'time_range_unit': args.get('time-range-unit'),
        'time_range_value': args.get('time-range-value'),
        'time_range_date_from': args.get('time-range-date-from'),
        'time_range_date_to': args.get('time-range-date-to'),
    }

    command_results = config_search_command(client, new_args)
    if return_v1_output:
        response = command_results.raw_response
        command_results = command_results.to_context()
        command_results['EntryContext'].update({'Redlock.Asset(val.id == obj.id)': response})  # type: ignore[index]
    return command_results


def event_search_v1_command(client: Client, args: Dict[str, Any], return_v1_output: bool) -> Union[CommandResults, Dict]:
    """
    This command is for supporting backwards compatibility, to make transition to V2 easier for users with custom playbooks.
    """
    new_args = {
        'query': args.get('query'),
        'limit': args.get('limit', '100'),
        'time_range_unit': args.get('time-range-unit'),
        'time_range_value': args.get('time-range-value'),
        'time_range_date_from': args.get('time-range-date-from'),
        'time_range_date_to': args.get('time-range-date-to'),
    }

    command_results = event_search_command(client, new_args)
    if return_v1_output:
        response = command_results.raw_response
        command_results = command_results.to_context()
        command_results['EntryContext'].update({'Redlock.Event(val.id == obj.id)': response})  # type: ignore[index]
    return command_results


def network_search_v1_command(client: Client, args: Dict[str, Any], return_v1_output: bool) -> Union[CommandResults, Dict]:
    """
    This command is for supporting backwards compatibility, to make transition to V2 easier for users with custom playbooks.
    """
    new_args = {
        'query': args.get('query'),
        'cloud_type': args.get('cloud-type'),
        'time_range_unit': args.get('time-range-unit'),
        'time_range_value': args.get('time-range-value'),
        'time_range_date_from': args.get('time-range-date-from'),
        'time_range_date_to': args.get('time-range-date-to'),
    }

    command_results = network_search_command(client, new_args)
    if return_v1_output:
        response = command_results.raw_response
        command_results = command_results.to_context()
        command_results['EntryContext'].update({  # type: ignore[index]
            'Redlock.Network.Node(val.id == obj.id)': response.get('nodes', []),  # type: ignore[attr-defined]
            'Redlock.Network.Connection(val.id == obj.from)': response.get('connections', [])  # type: ignore[attr-defined]
        })
    return command_results


def alert_filter_list_v1_command(client: Client, args: Dict[str, Any], return_v1_output: bool) -> Union[CommandResults, Dict]:
    """
    This command is for supporting backwards compatibility, to make transition to V2 easier for users with custom playbooks.
    """
    return alert_filter_list_command(client)


''' COMMAND FUNCTIONS '''


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


def alert_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    filters = argToList(args.get('filters'))
    detailed = args.get('detailed', 'true')
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    next_token = args.get('next_token')
    time_filter = handle_time_filter(base_case=ALERT_SEARCH_BASE_TIME_FILTER,
                                     unit_value=args.get('time_range_unit'),
                                     amount_value=arg_to_number(args.get('time_range_value')),
                                     time_from=args.get('time_range_date_from'),
                                     time_to=args.get('time_range_date_to'))
    sort_by = (
        [f'{sort_field}:{args.get("sort_direction")}']
        if (sort_field := args.get('sort_field'))
        else None
    )

    response = client.alert_search_request(time_filter, filters, limit, detailed, next_token, sort_by)
    response_items = response.get('items', [])
    next_page_token = response.get('nextPageToken')
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
    for readable_response in readable_responses:
        extract_nested_values(readable_response, nested_headers)

    headers = ['Alert ID', 'reason', 'status', 'alertTime', 'firstSeen', 'lastSeen', 'lastUpdated'] \
        + list(nested_headers.values())[1:]
    output = {
        'PrismaCloud.AlertPageToken(val.nextPageToken)': {'nextPageToken': next_page_token},  # values are overridden
        'PrismaCloud.Alert(val.id && val.id == obj.id)': response_items  # values are appended to list based on id
    }
    command_results = CommandResults(
        readable_output=f'Showing {len(readable_responses)} of {response.get("totalRows", 0)} results:\n'
                        + tableToMarkdown('Alerts Details:',
                                          readable_responses,
                                          headers=headers,
                                          removeNull=True,
                                          headerTransform=pascalToSpace)
                        + f'### Next Page Token:\n{next_page_token}',
        outputs=output,
        raw_response=response_items
    )
    return command_results


def alert_get_details_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alert_id = args.get('alert_id')
    detailed = args.get('detailed', 'true')

    response = client.alert_get_details_request(str(alert_id), detailed)
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

    client.alert_dismiss_request(str(dismissal_note), time_filter, alert_ids, policy_ids, dismissal_time_filter, filters)

    command_results = CommandResults(
        readable_output=(f'### Alerts snoozed successfully.\nSnooze note: {dismissal_note}.'
                         if dismissal_time_filter
                         else f'### Alerts dismissed successfully.\nDismissal note: {dismissal_note}.')
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

    client.alert_reopen_request(time_filter, alert_ids, policy_ids, filters)

    command_results = CommandResults(
        readable_output='### Alerts re-opened successfully.'
    )
    return command_results


def remediation_command_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alert_ids = argToList(args.get('alert_ids'))
    policy_id = args.get('policy_id')
    if not alert_ids and not policy_id:
        raise DemistoException('You must provide either "alert_ids" or "policy_id".')
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    all_results = argToBoolean(args.get('all_results', 'false'))

    time_filter = handle_time_filter(base_case=TIME_FILTER_BASE_CASE,
                                     unit_value=args.get('time_range_unit'),
                                     amount_value=arg_to_number(args.get('time_range_value')),
                                     time_from=args.get('time_range_date_from'),
                                     time_to=args.get('time_range_date_to'))

    try:
        response = client.remediation_command_list_request(time_filter, alert_ids, policy_id)
        description = response.get('cliDescription')
        script_impact = response.get('scriptImpact')
        readable_response = [{'description': description,
                              'scriptImpact': script_impact,
                              'alertId': alert_id,
                              'CLIScript': cli_script}
                             for alert_id, cli_script in response.get('alertIdVsCliScript', {}).items()]
        total_response_amount = len(readable_response)
        if not all_results and limit and readable_response:
            demisto.debug(f'Returning results only up to limit={limit}, from {len(readable_response)} results returned.')
            readable_response = readable_response[:limit]

    except DemistoException as de:
        if not (hasattr(de, 'res') and hasattr(de.res, 'status_code')):
            raise
        if de.res.status_code == 405:
            raise DemistoException(
                f'Remediation unavailable {" for the time given" if time_filter != TIME_FILTER_BASE_CASE else ""}.',
                exception=de) from de
        elif de.res.status_code == 400:
            raise DemistoException('Policy type disallowed using this remediation api.', exception=de) from de
        raise

    command_results = CommandResults(
        outputs_prefix='PrismaCloud.AlertRemediation',
        outputs_key_field='alertId',
        readable_output=f'Showing {len(readable_response)} of {total_response_amount} results:\n'
                        + tableToMarkdown('Remediation Command List:',
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
        client.alert_remediate_request(str(alert_id))

    except DemistoException as de:
        if not (hasattr(de, 'res') and hasattr(de.res, 'status_code')):
            raise
        if de.res.status_code == 405:
            raise DemistoException(f'Remediation unavailable for alert {alert_id}.', exception=de) from de
        elif de.res.status_code == 404:
            raise DemistoException(f'Alert {alert_id} is not found.', exception=de) from de
        raise

    command_results = CommandResults(
        readable_output=f'Alert {alert_id} remediated successfully.',
    )
    return command_results


def config_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    query = args.get('query')
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    time_filter = handle_time_filter(base_case=TIME_FILTER_BASE_CASE,
                                     unit_value=args.get('time_range_unit'),
                                     amount_value=arg_to_number(args.get('time_range_value')),
                                     time_from=args.get('time_range_date_from'),
                                     time_to=args.get('time_range_date_to'))
    search_id = args.get('search_id')
    sort_direction = args.get('sort_direction', 'desc')
    sort_field = args.get('sort_field', 'insertTs')
    if any([sort_direction, sort_field]) and not all([sort_direction, sort_field]):
        raise DemistoException('Both sort direction and field must be specified if sorting.')

    response = client.config_search_request(time_filter, str(query), limit, search_id, sort_direction, sort_field)
    response_items = response.get('data', {}).get('items', [])
    for response_item in response_items:
        change_timestamp_to_datestring_in_dict(response_item)

    headers = ['name', 'id', 'cloudType', 'service', 'accountName', 'regionName', 'deleted', 'accountId', 'assetId', 'createdTs',
               'insertTs', 'regionId', 'resourceType', 'rrn']
    command_results = CommandResults(
        outputs_prefix='PrismaCloud.Config',
        outputs_key_field='assetId',
        readable_output=f'Showing {len(response_items)} of {response.get("data", {}).get("totalRows", 0)} results:\n'
                        + tableToMarkdown('Configuration Details:',
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
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    time_filter = handle_time_filter(base_case=TIME_FILTER_BASE_CASE,
                                     unit_value=args.get('time_range_unit'),
                                     amount_value=arg_to_number(args.get('time_range_value')),
                                     time_from=args.get('time_range_date_from'),
                                     time_to=args.get('time_range_date_to'))
    sort_by = [
        {
            'field': sort_field,
            'direction': args.get('sort_direction'),
        }
    ] if (sort_field := args.get('sort_field')) else None

    response = client.event_search_request(time_filter, str(query), limit, sort_by)
    response_items = response.get('data', {}).get('items', [])
    for response_item in response_items:
        change_timestamp_to_datestring_in_dict(response_item)

    headers = ['subject', 'accountName', 'name', 'source', 'ip', 'eventTs', 'countryName', 'stateName', 'cityName',
               'location', 'account', 'regionId', 'type', 'id', 'role', 'accessKeyUsed', 'success', 'internal']
    command_results = CommandResults(
        outputs_prefix='PrismaCloud.Event',
        outputs_key_field='id',
        readable_output=f'Showing {len(response_items)} of {response.get("data", {}).get("totalRows", 0)} results:\n'
                        + tableToMarkdown('Event Details:',
                                          response_items,
                                          headers=headers,
                                          removeNull=True,
                                          headerTransform=pascalToSpace),
        outputs=response_items,
        raw_response=response_items
    )
    return command_results


def network_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    query = args.get('query')
    search_id = args.get('search_id')
    cloud_type = args.get('cloud_type')
    time_filter = handle_time_filter(base_case=TIME_FILTER_BASE_CASE,
                                     unit_value=args.get('time_range_unit'),
                                     amount_value=arg_to_number(args.get('time_range_value')),
                                     time_from=args.get('time_range_date_from'),
                                     time_to=args.get('time_range_date_to'))

    response = client.network_search_request(str(query), time_filter, search_id, cloud_type)
    response_items = response.get('data', {})
    nodes = response_items.get('nodes', [])
    connections = response_items.get('connections', [])

    output = {
        'PrismaCloud.Network.Node(val.id && val.id == obj.id)': nodes,  # values are appended to list based on id
        'PrismaCloud.Network.Connection(val.from && val.from == obj.from && val.to && val.to == obj.to)': connections
        # values are appended to list based on 'from' and 'to' keys
    }
    command_results = CommandResults(
        readable_output='## Network Details\n'
                        + tableToMarkdown('Nodes:',
                                          nodes,
                                          headers=['id', 'name', 'ipAddr', 'grouped', 'suspicious', 'vulnerable'],
                                          removeNull=True,
                                          headerTransform=pascalToSpace)
                        + tableToMarkdown('Connections:',
                                          connections,
                                          headers=['from', 'to', 'label', 'suspicious'],
                                          removeNull=True,
                                          headerTransform=pascalToSpace),
        outputs=output,
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


def error_file_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    cicd_run_id = args.get('cicd_run_id')
    if cicd_run_id:
        arg_to_number(cicd_run_id)  # for input validation or readable errors
        cicd_run_id = float(cicd_run_id)
    authors = argToList(args.get('authors'))
    branch = args.get('branch')
    categories = argToList(args.get('categories'))
    code_status = args.get('code_status')
    file_types = argToList(args.get('file_types'))
    repository = args.get('repository')
    repository_id = args.get('repository_id')
    search_options = argToList(args.get('search_options'))
    search_text = args.get('search_text', '')
    search_title = args.get('search_title')
    severities = argToList(args.get('severities'))
    source_types = argToList(args.get('source_types'))
    tags = argToList(args.get('tags'))
    statuses = argToList(args.get('statuses'))
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    all_results = argToBoolean(args.get('all_results', 'false'))

    error_file_list_command_args_validation(source_types, categories, statuses, file_types, search_options, severities)

    response = client.error_file_list_request(repository=str(repository), source_types=source_types, cicd_run_id=cicd_run_id,
                                              authors=authors, branch=branch, categories=categories, code_status=code_status,
                                              file_types=file_types, repository_id=repository_id, search_options=search_options,
                                              search_text=search_text, search_title=search_title, severities=severities,
                                              tags=tags, statuses=statuses)
    response_items = response.get('data', [])
    total_response_amount = len(response_items)
    if not all_results and limit and response_items:
        demisto.debug(f'Returning results only up to {limit=}, from {len(response_items)} results returned.')
        response_items = response_items[:limit]

    headers = ['filePath', 'suppressedErrorsCount', 'passedCount', 'openErrorsCount', 'errorsCount', 'fixedCount', 'type']
    command_results = CommandResults(
        outputs_prefix='PrismaCloud.ErrorFile',
        outputs_key_field='filePath',
        readable_output=f'Showing {len(response_items)} of {total_response_amount} results:\n'
                        + tableToMarkdown('Files Error Details:',
                                          response_items,
                                          headers=headers,
                                          removeNull=True,
                                          url_keys=['url'],
                                          headerTransform=pascalToSpace),
        outputs=response_items,
        raw_response=response_items
    )
    return command_results


def resource_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    rrn = args.get('rrn')

    response = client.resource_get_request(str(rrn))
    change_timestamp_to_datestring_in_dict(response)

    headers = ['rrn', 'id', 'name', 'url', 'accountId', 'accountName', 'cloudType', 'regionId', 'regionName', 'service',
               'resourceType', 'insertTs', 'deleted', 'vpcId', 'vpcName', 'tags', 'riskGrade', 'hasNetwork',
               'hasExternalFinding', 'hasExternalIntegration', 'allowDrillDown', 'hasExtFindingRiskFactors']
    command_results = CommandResults(
        outputs_prefix='PrismaCloud.Resource',
        outputs_key_field='rrn',
        readable_output=tableToMarkdown('Resource Details:',
                                        response,
                                        headers=headers,
                                        removeNull=True,
                                        url_keys=['url'],
                                        headerTransform=pascalToSpace),
        outputs=response,
        raw_response=response
    )
    return command_results


def account_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    exclude_account_group_details = args.get('exclude_account_group_details', 'false')
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    all_results = argToBoolean(args.get('all_results', 'false'))

    response = client.account_list_request(exclude_account_group_details)
    total_response_amount = len(response)
    if not all_results and limit and response:
        demisto.debug(f'Returning results only up to {limit=}, from {len(response)} results returned.')
        response = response[:limit]
    for response_item in response:
        change_timestamp_to_datestring_in_dict(response_item)

    headers = ['accountId', 'name', 'cloudType', 'accountType', 'enabled', 'addedOn', 'lastModifiedTs', 'lastModifiedBy',
               'storageScanEnabled', 'protectionMode', 'ingestionMode', 'deploymentType', 'status']
    command_results = CommandResults(
        outputs_prefix='PrismaCloud.Account',
        outputs_key_field='accountId',
        readable_output=f'Showing {len(response)} of {total_response_amount} results:\n'
                        + tableToMarkdown('Accounts Details:',
                                          response,
                                          headers=headers,
                                          removeNull=True,
                                          headerTransform=pascalToSpace),
        outputs=response,
        raw_response=response
    )
    return command_results


def account_status_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    account_ids = argToList(args.get('account_ids'))

    responses = []
    for account_id in account_ids:
        if response := client.account_status_get_request(account_id):
            response[0]['accountId'] = account_id
            responses.append(response[0])

    headers = ['accountId', 'name', 'status', 'message', 'remediation']
    command_results = CommandResults(
        outputs_prefix='PrismaCloud.Account',
        outputs_key_field='accountId',
        readable_output=tableToMarkdown('Accounts Status Details:',
                                        responses,
                                        headers=headers,
                                        removeNull=True,
                                        headerTransform=pascalToSpace),
        outputs=responses,
        raw_response=responses
    )
    return command_results


def account_owner_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    account_ids = argToList(args.get('account_ids'))

    responses = []
    for account_id in account_ids:
        response = client.account_owner_list_request(account_id)
        responses.append({'accountId': account_id, 'emails': response})

    command_results = CommandResults(
        outputs_prefix='PrismaCloud.Account',
        outputs_key_field='accountId',
        readable_output=tableToMarkdown('Accounts Owner Details:',
                                        responses,
                                        removeNull=True,
                                        headerTransform=pascalToSpace),
        outputs=responses,
        raw_response=responses
    )
    return command_results


def host_finding_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    rrn = args.get('rrn')
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    all_results = argToBoolean(args.get('all_results', 'false'))

    finding_types = argToList(args.get('finding_types'))
    finding_types = [finding_type.lower() for finding_type in finding_types]
    validate_array_arg(finding_types, 'Finding types', FINDING_TYPES_OPTIONS)

    risk_factors = argToList(args.get('risk_factors'))
    risk_factors = [risk_factor.upper() for risk_factor in risk_factors]
    validate_array_arg(risk_factors, 'Risk factors', RISK_FACTORS_OPTIONS)

    response = client.host_finding_list_request(str(rrn), finding_types, risk_factors)
    total_response_amount = len(response)
    if not all_results and limit and response:
        demisto.debug(f'Returning results only up to {limit=}, from {len(response)} results returned.')
        response = response[:limit]
    for response_item in response:
        change_timestamp_to_datestring_in_dict(response_item)
    readable_responses = deepcopy(response)

    nested_headers = {'sourceData.accountId': 'Source Data Account ID',
                      'sourceData.arn': 'ARN',
                      }
    headers = ['accountId', 'regionId', 'findingId', 'type', 'source', 'severity', 'status', 'createdOn', 'updatedOn',
               'normalizedNames', 'scanId', 'resourceCloudId', 'Source Data Account ID', 'ARN', 'title', 'description',
               'resourceUrl']
    for readable_response in readable_responses:
        extract_nested_values(readable_response, nested_headers)

    command_results = CommandResults(
        outputs_prefix='PrismaCloud.HostFinding',
        outputs_key_field='findingId',
        readable_output=f'Showing {len(readable_responses)} of {total_response_amount} results:\n'
                        + tableToMarkdown('Host Finding Details:',
                                          readable_responses,
                                          headers=headers,
                                          removeNull=True,
                                          url_keys=['resourceUrl'],
                                          headerTransform=pascalToSpace),
        outputs=response,
        raw_response=response
    )
    return command_results


def permission_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    user_id = args.get('user_id')
    query = args.get('query')
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    next_token = args.get('next_token')

    if not query and not next_token:
        raise DemistoException('You must provide either "query" or "next_token" for getting permission list.')
    if next_token and (user_id or query):
        raise DemistoException('You can\'t provide "next_token" with "user_id" or "query".')

    if query:
        response = client.permission_list_request(query, limit, user_id)  # type: ignore[arg-type]
        response = response.get('data', {})
    else:
        response = client.permission_list_next_page_request(str(next_token), limit)  # type: ignore[arg-type]
    response_items = response.get('items', [])
    next_page_token = response.get('nextPageToken')

    readable_responses = deepcopy(response_items)
    nested_headers = {'destCloudType': 'destinationCloudType',
                      'destCloudServiceName': 'destinationCloudServiceName',
                      'destResourceType': 'destinationResourceType'}
    for readable_response in readable_responses:
        extract_nested_values(readable_response, nested_headers)

    headers = ['id', 'sourceCloudType', 'sourceCloudAccount', 'sourceResourceId', 'destinationCloudType',
               'destinationCloudServiceName', 'destinationResourceType', 'effectiveActionName', 'grantedByCloudType',
               'grantedByCloudPolicyId', 'grantedByCloudPolicyName', 'grantedByCloudPolicyType', 'grantedByCloudPolicyRrn',
               'grantedByCloudEntityId', 'grantedByCloudEntityName', 'grantedByCloudEntityRrn']
    output = {
        'PrismaCloud.PermissionPageToken(val.nextPageToken)': {'nextPageToken': next_page_token},  # values are overridden
        'PrismaCloud.Permission(val.id && val.id == obj.id)': response_items  # values are appended to list based on id
    }
    command_results = CommandResults(
        readable_output=f'Showing {len(readable_responses)} of {response.get("totalRows", 0)} results:\n'
                        + tableToMarkdown('Permissions Details:',
                                          readable_responses,
                                          headers=headers,
                                          removeNull=True,
                                          headerTransform=pascalToSpace)
                        + f'### Next Page Token:\n{next_page_token}',
        outputs=output,
        raw_response=response_items
    )
    return command_results


def fetch_incidents(client: Client, last_run: Dict[str, Any], params: Dict[str, Any]) -> \
        tuple[List[Dict[str, Any]], Dict[str, int], int]:
    """
    Retrieve new incidents periodically based on pre-defined instance parameters
    """
    last_run_time = last_run.get('time')
    now = convert_date_to_unix('now')
    first_fetch = params.get('first_fetch', FETCH_DEFAULT_TIME)
    look_back = arg_to_number(params.get('look_back', FETCH_LOOK_BACK_TIME)) or FETCH_LOOK_BACK_TIME
    time_range = calculate_fetch_time_range(now, first_fetch, look_back, last_run_time)

    fetched_ids = last_run.get('fetched_ids', {})
    limit = arg_to_number(params.get('max_fetch', MAX_INCIDENTS_TO_FETCH)) or MAX_INCIDENTS_TO_FETCH
    filters = argToList(params.get('filters'))

    incidents, fetched_ids, updated_last_run_time = fetch_request(client, fetched_ids, filters, limit, now, time_range)
    updated_last_run_time = max(convert_date_to_unix(first_fetch), updated_last_run_time)
    demisto.debug(f'Fetched {len(incidents)} incidents, {updated_last_run_time=}')
    ids_to_insert = expire_stored_ids(fetched_ids, updated_last_run_time, look_back)

    return incidents, ids_to_insert, updated_last_run_time


''' MIRRORING COMMANDS '''


def get_modified_remote_data_command(client: Client,
                                     args: Dict[str, str],
                                     params: Dict[str, Any]) -> GetModifiedRemoteDataResponse:
    """
    Gets the modified remote alerts IDs.

    Args:
        client: Demisto client.
        args:
            last_update: The last time we retrieved modified incidents.
        params: Demisto params.

    Returns: GetModifiedRemoteDataResponse object, which contains a list of the retrieved alerts IDs.
    """
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update = remote_args.last_update
    parsed_date = dateparser.parse(last_update, settings={'TIMEZONE': 'UTC'})  # convert to utc format
    if not parsed_date:
        raise DemistoException(f'could not parse {last_update}')
    last_update_timestamp = parsed_date.strftime(DATE_FORMAT)
    demisto.debug(f'Remote arguments last_update in UTC is {last_update_timestamp}')

    detailed = 'false'
    sort_by = ['alertTime:asc']
    time_filter = handle_time_filter(time_from=last_update,
                                     time_to='now')
    filters = argToList(params.get('filters'))

    # According to the PM of prisma cloud the following filter provide us with all the alerts that their status has been changed.
    # It is not yet documented in the Prisma Cloud API reference - for more info see this issue:
    # https://jira-hq.paloaltonetworks.local/browse/CIAC-5504.
    filters.append('timeRange.type=ALERT_STATUS_UPDATED')

    # Removes any status-related filter to retrieve all the relevant statuses (open, resolved, dismissed and snoozed)
    for status_filter in ['alert.status=open', 'alert.status=dismissed', 'alert.status=snoozed', 'alert.status=resolved']:
        if status_filter in set(filters):
            filters.remove(status_filter)

    response = client.alert_search_request(time_range=time_filter, filters=filters, detailed=detailed, sort_by=sort_by)
    response_items = response.get('items', [])
    modified_records_ids = [str(item.get('id')) for item in response_items]
    demisto.debug(f"Detected {len(modified_records_ids)} modified alerts in Prisma Cloud")

    return GetModifiedRemoteDataResponse(modified_records_ids)


def get_remote_data_command(client: Client, args: Dict[str, Any]) -> GetRemoteDataResponse:
    """
    Returns an updated remote alert.

    Args:
        client: Demisto client.
        args:
            id: alert id to retrieve.
            lastUpdate: when was the last time we retrieved data.

    Returns: GetRemoteDataResponse object, which contains the alert data to update.
    """
    remote_args = GetRemoteDataArgs(args)
    remote_alert_id = remote_args.remote_incident_id
    entries = []

    try:
        demisto.debug(f'Performing get-remote-data command with incident id: {remote_alert_id} '
                      f'and last_update: {remote_args.last_update}')
        mirrored_data, updated_object = get_remote_alert_data(client, remote_alert_id)
        if updated_object and client.close_incident:
            demisto.debug(f'Update incident {remote_alert_id} with fields: {updated_object}')
            entry = set_xsoar_incident_entries(updated_object, remote_alert_id)
            if entry:
                entries.append(entry)

        if not updated_object:
            demisto.debug(f'No delta was found for incident id: {remote_alert_id}.')

        return GetRemoteDataResponse(mirrored_object=updated_object, entries=entries)

    except Exception as e:
        demisto.debug(f"Error in Prisma Cloud v2 incoming mirror for incident: {remote_alert_id}\n"
                      f"Error message: {str(e)}")

        if not mirrored_data:
            mirrored_data = {'id': remote_alert_id}
        mirrored_data['in_mirror_error'] = str(e)

        return GetRemoteDataResponse(mirrored_object=mirrored_data, entries=[])


def update_remote_system_command(client: Client, args: Dict[str, Any]) -> str:
    """
    Mirrors out local changes (closing or reopening of an xsoar incident) to the remote system (Prisma Cloud).

    To determine a closing of an XSOAR incident that should be mirrored to Prisma we check that:
        1. parsed_args.incident_changed = True (meaning the incident has changed).
        2. Incident status is Done (=2).
        3. The delta contains at least one of the following fields: 'closeReason', 'closingUserId', 'closeNotes'.

    To determine a re-opening of an XSOAR incident that should be mirrored to Prisma we check that:
        1. parsed_args.incident_changed = True (meaning the incident has changed).
        2. Incident status is Active (=1).
        3. The delta contains the 'closingUserId'.

    These conditions should be sufficient.

    In any other case, the change in XSOAR won't be mirrored to the remote system.

    Args:
        client: Demisto client.
        args: A dictionary containing the data regarding a modified incident, including: data, entries,
              incident_changed, remote_incident_id, inc_status and delta.

    Returns: The remote incident id that was modified.
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    delta = parsed_args.delta
    remote_incident_id = parsed_args.remote_incident_id

    try:
        if parsed_args.incident_changed:
            incident_status = parsed_args.inc_status
            demisto.debug(f'Performing update_remote_system command with incident id {remote_incident_id}, incident status'
                          f' {incident_status} and delta {delta}.')
            update_remote_alert(client, delta, incident_status, remote_incident_id)

        else:
            demisto.debug(f"Skipping the update of remote incident {remote_incident_id} as it has not changed.")

    except Exception as e:
        demisto.error(f'Error in Prisma Cloud V2 outgoing mirror for incident {remote_incident_id}. '
                      f'Error message: {str(e)}')

    return remote_incident_id


''' TEST MODULE '''


def test_module(client: Client, params: Dict[str, Any]) -> str:
    if params.get('isFetch'):
        max_fetch = arg_to_number(params.get('max_fetch'), arg_name='Maximum number of incidents to fetch')
        if max_fetch and (max_fetch > MAX_INCIDENTS_TO_FETCH or max_fetch <= 0):
            return f'Maximum number of incidents to fetch must be between 1 and {MAX_INCIDENTS_TO_FETCH} ({max_fetch} provided).'

        filters = argToList(params.get('filters'))
        # check the filters format
        handle_filters(filters)  # raises if invalid, otherwise we don't use the value

        # check the filters names
        filters_available_names = client.alert_filter_list_request().keys()
        for filter_ in filters:
            filter_name = filter_.split('=')[0]
            if filter_name not in filters_available_names:
                return f'Filter "{filter_name}" is not one of the available filters. ' \
                       f'The available filters names can be found by running "prisma-cloud-alert-filter-list" command.'

        look_back = arg_to_number(params.get('look_back'), arg_name='Time in minutes to look back when fetching incidents')
        if look_back and look_back < 0:
            return 'Time in minutes to look back when fetching incidents must be a positive value, greater than or equal to zero.'
        time_range = calculate_fetch_time_range(now=convert_date_to_unix('now'),
                                                first_fetch=params.get('first_fetch', FETCH_DEFAULT_TIME))
        alerts = client.alert_search_request(time_range=time_range, filters=filters, detailed='true',
                                             limit=max_fetch, sort_by=['alertTime:asc']).get('items', [])
        if not alerts:
            return 'The connection succeeded, but no alerts were found for the provided filters and first fetch time. ' \
                   'To pass the test, increase the first fetch time to a time when there were alerts at.'

    # Authorization is done in client.generate_auth_token
    return 'ok'


''' MAIN FUNCTION '''


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = format_url(str(params.get('url')))
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')

    mirror_direction = MIRROR_DIRECTION_MAPPING.get(params.get('mirror_direction', 'None'))
    close_incident = argToBoolean(params.get('close_incident', False))
    close_alert = argToBoolean(params.get('close_alert', False))

    return_v1_output = params.get('output_old_format', False)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        urllib3.disable_warnings()
        client: Client = Client(url, verify_certificate, proxy, headers=HEADERS, username=username, password=password,
                                mirror_direction=mirror_direction, close_incident=close_incident, close_alert=close_alert)
        commands_without_args = {
            'prisma-cloud-alert-filter-list': alert_filter_list_command,

            'prisma-cloud-trigger-scan': trigger_scan_command,
        }
        commands_with_args = {
            'prisma-cloud-alert-search': alert_search_command,
            'prisma-cloud-alert-get-details': alert_get_details_command,
            'prisma-cloud-alert-dismiss': alert_dismiss_command,
            'prisma-cloud-alert-reopen': alert_reopen_command,
            'prisma-cloud-remediation-command-list': remediation_command_list_command,
            'prisma-cloud-alert-remediate': alert_remediate_command,

            'prisma-cloud-config-search': config_search_command,
            'prisma-cloud-event-search': event_search_command,
            'prisma-cloud-network-search': network_search_command,

            'prisma-cloud-error-file-list': error_file_list_command,

            'prisma-cloud-resource-get': resource_get_command,
            'prisma-cloud-account-list': account_list_command,
            'prisma-cloud-account-status-get': account_status_get_command,
            'prisma-cloud-account-owner-list': account_owner_list_command,

            'prisma-cloud-host-finding-list': host_finding_list_command,
            'prisma-cloud-permission-list': permission_list_command,
            'get-remote-data': get_remote_data_command,
            'update-remote-system': update_remote_system_command,
        }
        commands_v1 = {
            'redlock-search-alerts': alert_search_v1_command,
            'redlock-get-alert-details': alert_get_details_v1_command,
            'redlock-dismiss-alerts': alert_dismiss_v1_command,
            'redlock-reopen-alerts': alert_reopen_v1_command,
            'redlock-get-remediation-details': remediation_command_list_v1_command,
            'redlock-get-rql-response': rql_config_search_v1_command,
            'redlock-search-config': config_search_v1_command,
            'redlock-search-event': event_search_v1_command,
            'redlock-search-network': network_search_v1_command,
            'redlock-list-alert-filters': alert_filter_list_v1_command,
        }

        if command in commands_without_args:
            return_results(commands_without_args[command](client))
        elif command in commands_with_args:
            return_results(commands_with_args[command](client, args))
        elif command in commands_v1:
            return_results(commands_v1[command](client, args, return_v1_output))
        elif command == 'test-module':
            return_results(test_module(client, params))
        elif command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            incidents, fetched_ids, last_run_time = fetch_incidents(client, last_run, params)
            demisto.incidents(incidents)
            demisto.setLastRun({
                'fetched_ids': fetched_ids,
                'time': last_run_time
            })
        elif command == 'get-modified-remote-data':
            return_results(get_modified_remote_data_command(client, args, params))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        error_msg = str(e)
        if hasattr(e, 'res'):
            error_msg += get_response_status_header(e.res)  # type: ignore[attr-defined]
        return_error(error_msg, error=e)


''' ENTRY POINT '''

if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
