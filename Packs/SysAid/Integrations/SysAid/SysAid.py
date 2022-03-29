import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import requests
from typing import Dict, Any, Tuple

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

SERVICE_RECORD_ARGS = ['agreement', 'assigned_group', 'change_category', 'company', 'computer_id', 'cust_notes', 'department',
                       'description', 'due_date', 'email_account', 'escalation', 'followup_text', 'followup_user', 'impact',
                       'location', 'priority', 'problem_sub_type', 'problem_type', 'responsibility', 'solution', 'sr_type',
                       'status', 'sub_type', 'third_level_category', 'title', 'urgency']

TEMPLATE_OUTPUTS = ['key', 'value', 'mandatory', 'editable', 'type', 'defaultValue', 'keyCaption']

STATUSES = {'1', '2', '3', '4', '5', '6', '7', '8', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30',
            '31', '32', '33', '34', '35', '36', '39', '40', 'OPEN_CLASSES'}

MAX_INCIDENTS_TO_FETCH = 500

FETCH_DEFAULT_TIME = '3 days'

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, auth=auth)
        self._cookies: requests.cookies.RequestsCookieJar = self._get_cookies()

    def _get_cookies(self) -> requests.cookies.RequestsCookieJar:
        data = {'user_name': self._auth[0], 'password': self._auth[1]}

        response = self._http_request('POST', 'login', json_data=data, resp_type='response')

        return response.cookies

    def table_list_request(self, entity: str = None, fields: List[str] = None, offset: int = None, limit: int = None):
        params = assign_params(entity=entity, fields=fields, offset=offset, limit=limit)

        response = self._http_request('GET', 'list', params=params, cookies=self._cookies)

        return response

    def table_list_with_id_request(self, list_id: str, entity: str = None, entity_id: str = None, entity_type: int = None,
                                   fields: List[str] = None, offset: int = None, limit: int = None, key: str = None):
        params = assign_params(entity=entity, fields=fields, offset=offset, limit=limit,
                               entityId=entity_id, entityType=entity_type, key=key)

        response = self._http_request('GET', f'list/{list_id}', params=params, cookies=self._cookies)

        return response

    def asset_list_request(self, fields: List[str] = None, offset: int = None, limit: int = None):
        params = assign_params(fields=fields, offset=offset, limit=limit)

        response = self._http_request('GET', 'asset', params=params, cookies=self._cookies)

        return response

    def asset_list_with_id_request(self, asset_id: str, fields: List[str] = None):
        params = assign_params(fields=fields)

        response = self._http_request('GET', f'asset/{asset_id}', params=params, cookies=self._cookies)

        return response

    def asset_search_request(self, query: str, fields: List[str] = None, limit: int = None, offset: int = None):
        params = assign_params(query=query, fields=fields, limit=limit, offset=offset)

        response = self._http_request('GET', 'asset/search', params=params, cookies=self._cookies)

        return response

    def filter_list_request(self, fields: List[str] = None, offset: int = None, limit: int = None):
        params = assign_params(fields=fields, offset=offset, limit=limit)

        response = self._http_request('GET', 'filters', params=params, cookies=self._cookies)

        return response

    def user_list_request(self, fields: List[str] = None, type_: str = None, offset: int = None, limit: int = None):
        params = assign_params(fields=fields, type=type_, offset=offset, limit=limit)

        response = self._http_request('GET', 'users', params=params, cookies=self._cookies)

        return response

    def user_search_request(self, query: str, fields: List[str] = None, type_: str = None, offset: int = None, limit: int = None):
        params = assign_params(query=query, fields=fields, type=type_, offset=offset, limit=limit)

        response = self._http_request('GET', 'users/search', params=params, cookies=self._cookies)

        return response

    def service_record_list_request(self, type_: str, fields: List[str] = None, offset: int = None, limit: int = None,
                                    ids: List[str] = None, archive: int = None, filters: Dict[str, Any] = None):
        params = assign_params(type=type_, fields=fields, offset=offset, limit=limit, ids=ids, archive=archive)
        params.update(filters or {})

        response = self._http_request('GET', 'sr', params=params, cookies=self._cookies)

        return response

    def service_record_search_request(self, type_: str, query: str, fields: List[str] = None, offset: int = None,
                                      limit: int = None, archive: int = None, filters: Dict[str, Any] = None):
        params = assign_params(type=type_, fields=fields, offset=offset, limit=limit, query=query, archive=archive)
        params.update(filters)

        response = self._http_request('GET', 'sr/search', params=params, cookies=self._cookies)

        return response

    def service_record_update_request(self, id_: str, info: List[Dict[str, str]] = None):
        data = {"id": id_, "info": info}

        response = self._http_request('PUT', f'sr/{id_}', json_data=data, cookies=self._cookies, resp_type='response')

        return response

    def service_record_close_request(self, id_: str, solution: str = None):
        data = {"solution": solution}

        # 400 - 'This service record is already closed' might be raised - which isn't a real error
        response = self._http_request('PUT', f'sr/{id_}/close', json_data=data, cookies=self._cookies, resp_type='response',
                                      ok_codes=(200, 400))

        return response

    def service_record_template_get_request(self, type_: str, fields: List[str] = None, template_id: str = None):
        params = assign_params(fields=fields, type=type_, template=template_id)

        response = self._http_request('GET', 'sr/template', params=params, cookies=self._cookies)

        return response

    def service_record_create_request(self, type_: str, info: List[Dict[str, str]], fields: List[str] = None,
                                      template_id: str = None):
        params = assign_params(fields=fields, type=type_, template=template_id)
        data = {"info": info}

        response = self._http_request('GET', 'sr/template', params=params, json_data=data, cookies=self._cookies)

        return response

    def service_record_delete_request(self, ids: List[str], solution: str = None):
        params = assign_params(ids=ids)
        data = {"solution": solution}

        # 400 - 'Invalid service record id' might be raised - which isn't a real error
        response = self._http_request('DELETE', 'sr', params=params, json_data=data, cookies=self._cookies, resp_type='response',
                                      ok_codes=(200, 400))
        return response


''' HELPER FUNCTIONS '''


def asset_list_readable_response(responses: Union[dict, List[dict], str], remove_if_null: str) \
        -> Union[str, List[Dict[str, str]]]:
    readable_response = []

    if isinstance(responses, dict):
        responses = [responses]

    if isinstance(responses, str):
        return responses

    for response in responses:
        new_info = []
        response_entry = {key: response[key] for key in ['id', 'name'] if key in response}

        if 'info' in response:
            for info in response['info']:
                if info['keyCaption'] in ['Model', 'Description'] and info[remove_if_null]:
                    new_info.append(f'{info["keyCaption"]}: {info["valueCaption"]}')

            response_entry['info'] = new_info
        readable_response.append(response_entry)

    return readable_response


def filter_list_readable_response(responses: Union[dict, List[dict], str]) -> Union[str, List[Dict[str, str]]]:
    readable_response = []

    if isinstance(responses, dict):
        responses = [responses]

    if isinstance(responses, str):
        return responses

    for response in responses:
        new_info = []
        response_entry = {key: response[key] for key in ['id', 'type', 'caption'] if key in response}

        if 'values' in response:
            for info in response['values']:
                new_info.append(f'{info["id"]}: {info["caption"]}')

            response_entry['values'] = new_info
        readable_response.append(response_entry)

    return readable_response


def service_record_readable_response(responses: Union[dict, List[dict], str]) -> Union[str, List[Dict[str, str]]]:
    readable_response = []

    if isinstance(responses, dict):
        responses = [responses]

    if isinstance(responses, str):
        return responses

    for response in responses:
        response_entry = {'id': response['id']}

        if 'info' in response:
            for info in response['info']:
                if info['key'] in ['title', 'status']:
                    response_entry[info['key']] = info['value']

            if len(response_entry) == 3:
                readable_response.append(response_entry)

    return readable_response


def extract_filters(custom_fields_keys: List[str], custom_fields_values: List[str]) -> Dict[str, Any]:
    filters = {}
    for key, value in zip(custom_fields_keys, custom_fields_values):
        filters[key] = value
    return filters


def set_service_record_info(args: Dict[str, Any]) -> List[Dict[str, str]]:
    info = []

    for arg_name in SERVICE_RECORD_ARGS:
        arg_value = args.get(arg_name)
        if arg_value:
            info.append({"key": arg_name, "value": arg_value})

    custom_fields_keys = argToList(args.get('custom_fields_keys'))
    custom_fields_values = argToList(args.get('custom_fields_values'))
    for key, value in zip(custom_fields_keys, custom_fields_values):
        info.append({"key": key, "value": value})

    return info


def template_readable_response(responses: Union[dict, List[dict], str]) -> Union[str, List[Dict[str, Any]]]:
    readable_response = []

    if isinstance(responses, dict):
        responses = [responses]

    if isinstance(responses, str):
        return responses

    for response in responses:
        if 'info' in response:
            for response_info in response['info']:
                response_entry = {}
                for key in TEMPLATE_OUTPUTS:
                    response_entry[key] = response_info[key] if key in response_info else None

                readable_response.append(response_entry)

    return readable_response


''' COMMAND FUNCTIONS '''


def table_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    entity = args.get('entity')
    entity_id = args.get('entity_id')
    entity_type = arg_to_number(args.get('entity_type'))
    key = args.get('key')
    list_id = args.get('list_id')
    offset = arg_to_number(args.get('offset'))
    limit = arg_to_number(args.get('limit'))
    fields = argToList(args.get('fields'))

    if list_id:
        response = client.table_list_with_id_request(list_id, entity, entity_id, entity_type, fields, offset, limit, key)
    else:
        response = client.table_list_request(entity, fields, offset, limit)
    headers = ['id', 'caption', 'values']
    command_results = CommandResults(
        outputs_prefix='SysAid.List',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(f'List {f"ID {list_id}" if list_id else entity or "sr"} Results:',
                                        response,
                                        headers=headers,
                                        removeNull=True,
                                        headerTransform=pascalToSpace)
    )

    return command_results


def asset_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    asset_id = args.get('asset_id')
    fields = argToList(args.get('fields'))
    offset = arg_to_number(args.get('offset'))
    limit = arg_to_number(args.get('limit'))

    if asset_id:
        response = client.asset_list_with_id_request(asset_id, fields)
    else:
        response = client.asset_list_request(fields, offset, limit)
    headers = ['id', 'name', 'info']
    readable_response = asset_list_readable_response(response, 'valueCaption')
    command_results = CommandResults(
        outputs_prefix='SysAid.Asset',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(f'Asset {asset_id + " " if asset_id else ""}Results:',
                                        readable_response,
                                        headers=headers,
                                        removeNull=True,
                                        headerTransform=pascalToSpace)
    )

    return command_results


def asset_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    query = args.get('query')
    fields = argToList(args.get('fields'))
    offset = arg_to_number(args.get('offset'))
    limit = arg_to_number(args.get('limit'))

    response = client.asset_search_request(str(query), fields, limit, offset)
    headers = ['id', 'name', 'info']
    readable_response = asset_list_readable_response(response, 'value')
    command_results = CommandResults(
        outputs_prefix='SysAid.Asset',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Asset Results:',
                                        readable_response,
                                        headers=headers,
                                        removeNull=True,
                                        headerTransform=pascalToSpace)
    )

    return command_results


def filter_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    fields = argToList(args.get('fields'))
    offset = arg_to_number(args.get('offset'))
    limit = arg_to_number(args.get('limit'))

    response = client.filter_list_request(fields, offset, limit)
    headers = ['id', 'caption', 'type', 'values']
    readable_response = filter_list_readable_response(response)
    command_results = CommandResults(
        outputs_prefix='SysAid.Filter',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Filter Results:',
                                        readable_response,
                                        headers=headers,
                                        removeNull=True,
                                        headerTransform=pascalToSpace)
    )

    return command_results


def user_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    fields = argToList(args.get('fields'))
    type_ = args.get('type')
    offset = arg_to_number(args.get('offset'))
    limit = arg_to_number(args.get('limit'))

    response = client.user_list_request(fields, type_, offset, limit)
    headers = ['id', 'name', 'isAdmin', 'isManager', 'isSysAidAdmin', 'isGuest']
    command_results = CommandResults(
        outputs_prefix='SysAid.User',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Filter Results:',
                                        response,
                                        headers=headers,
                                        removeNull=True)
    )

    return command_results


def user_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    query = args.get('query')
    fields = argToList(args.get('fields'))
    type_ = args.get('type')
    offset = arg_to_number(args.get('offset'))
    limit = arg_to_number(args.get('limit'))

    response = client.user_search_request(str(query), fields, type_, offset, limit)
    headers = ['id', 'name', 'isAdmin', 'isManager', 'isSysAidAdmin', 'isGuest']
    command_results = CommandResults(
        outputs_prefix='SysAid.User',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('User Results:',
                                        response,
                                        headers=headers,
                                        removeNull=True)
    )

    return command_results


def service_record_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    type_ = args.get('type')
    fields = argToList(args.get('fields'))
    offset = arg_to_number(args.get('offset'))
    limit = arg_to_number(args.get('limit'))
    ids = argToList(args.get('ids'))
    archive = arg_to_number(args.get('archive'))
    custom_fields_keys = argToList(args.get('custom_fields_keys'))
    custom_fields_values = argToList(args.get('custom_fields_values'))
    filters = extract_filters(custom_fields_keys, custom_fields_values)

    response = client.service_record_list_request(str(type_), fields, offset, limit, ids, archive, filters)
    headers = ['id', 'title', 'status']
    readable_response = service_record_readable_response(response)
    command_results = CommandResults(
        outputs_prefix='SysAid.ServiceRecord',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Service Record Results:',
                                        readable_response,
                                        headers=headers,
                                        removeNull=True,
                                        headerTransform=pascalToSpace)
    )

    return command_results


def service_record_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    query = args.get('query')
    type_ = args.get('type')
    fields = argToList(args.get('fields'))
    offset = arg_to_number(args.get('offset'))
    limit = arg_to_number(args.get('limit'))
    archive = arg_to_number(args.get('archive'))
    custom_fields_keys = argToList(args.get('custom_fields_keys'))
    custom_fields_values = argToList(args.get('custom_fields_values'))
    filters = extract_filters(custom_fields_keys, custom_fields_values)

    response = client.service_record_search_request(str(type_), str(query), fields, offset, limit, archive, filters)
    headers = ['id', 'title', 'status']
    readable_response = service_record_readable_response(response)
    command_results = CommandResults(
        outputs_prefix='SysAid.ServiceRecord',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Service Record Results:',
                                        readable_response,
                                        headers=headers,
                                        removeNull=True,
                                        headerTransform=pascalToSpace)
    )

    return command_results


def service_record_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = args.get('id')
    info = set_service_record_info(args)

    response = client.service_record_update_request(str(id_), info)
    if response.ok:
        msg = f'Service Record {id_} Updated Successfully.'
    else:
        msg = f'Error {response.status_code} occurred while updating service record {id_}.'
    command_results = CommandResults(
        outputs_prefix='SysAid.ServiceRecord',
        readable_output=msg
    )

    return command_results


def service_record_close_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = args.get('id')
    solution = args.get('solution')

    response = client.service_record_close_request(str(id_), solution)
    if response.status_code == 200:
        msg = f'Service Record {id_} Closed Successfully.'
    elif response.status_code == 400:
        msg = f'Service record {id_} is already closed.'
    else:
        msg = f'Error {response.status_code} occurred while closing service record {id_}.'
    command_results = CommandResults(
        outputs_prefix='SysAid.ServiceRecord',
        readable_output=msg
    )

    return command_results


def service_record_template_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    fields = argToList(args.get('fields'))
    type_ = args.get('type')
    template_id = args.get('template_id')

    response = client.service_record_template_get_request(str(type_), fields, template_id)
    readable_response = template_readable_response(response)
    command_results = CommandResults(
        outputs_prefix='SysAid.ServiceRecordTemplate',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Service Record Results:',
                                        readable_response,
                                        headers=TEMPLATE_OUTPUTS,
                                        removeNull=True,
                                        headerTransform=pascalToSpace)
    )

    return command_results


def service_record_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    fields = argToList(args.get('fields'))
    type_ = args.get('type')
    template_id = args.get('template_id')
    info = set_service_record_info(args)

    response = client.service_record_create_request(str(type_), info, fields, template_id)
    headers = ['id', 'title', 'status']
    readable_response = service_record_readable_response(response)
    command_results = CommandResults(
        outputs_prefix='SysAid.ServiceRecord',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Service Record Results:',
                                        readable_response,
                                        headers=headers,
                                        removeNull=True,
                                        headerTransform=pascalToSpace)
    )

    return command_results


def service_record_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ids = argToList(args.get('ids'))
    solution = args.get('solution')

    response = client.service_record_delete_request(ids, solution)
    if response.status_code == 200:
        msg = f'Service Records {ids} Deleted Successfully.'
    elif response.status_code == 400:
        msg = f'Service records {ids} are already deleted.'
    else:
        msg = f'Error {response.status_code} occurred while deleting service records {ids}.'
    command_results = CommandResults(
        outputs_prefix='SysAid.ServiceRecord',
        readable_output=msg
    )

    return command_results


def fetch_incidents(client: Client, first_fetch: str, limit: Optional[int] = MAX_INCIDENTS_TO_FETCH,
                    included_statuses: str = None, include_archived: bool = False, fetch_types: str = None):
    last_fetch = demisto.getLastRun().get('last_fetch')
    last_id_fetched = demisto.getLastRun().get('last_id_fetched', -1)
    fetch_start_datetime = calculate_fetch_start_datetime(last_fetch, first_fetch)
    demisto.debug(f'last fetch was at: {last_fetch}, last id fetched was: {last_id_fetched}, '
                  f'time to fetch from is: {fetch_start_datetime}.')

    responses = fetch_request(client, fetch_types, include_archived, included_statuses)

    limit = limit or MAX_INCIDENTS_TO_FETCH
    last_fetch, last_id_fetched, incidents = parse_service_records(responses, limit, fetch_start_datetime, last_id_fetched)
    demisto.setLastRun({'last_fetch': last_fetch.isoformat(), 'last_id_fetched': last_id_fetched})
    return incidents


def fetch_request(client: Client, fetch_types: str = None, include_archived: bool = False, included_statuses: str = None):
    fetch_types = 'all' if not fetch_types or 'all' in fetch_types else fetch_types
    filters = {'status': included_statuses} if included_statuses else {}

    response = client.service_record_list_request(type_=fetch_types, archive=int(include_archived), filters=filters)

    responses = [response] if isinstance(response, dict) else response
    demisto.debug(f'The request returned {len(response)} service records.')
    return responses


def filter_service_records_by_time(service_records: List[Dict[str, Any]], fetch_start_timestamp: datetime) \
        -> List[Dict[str, Any]]:
    filtered_service_records = []
    for service_record in service_records:
        update_time = get_service_record_update_time(service_record)
        if update_time and update_time >= fetch_start_timestamp:
            filtered_service_records.append(service_record)

    return filtered_service_records


def filter_service_records_by_id(service_records: List[Dict[str, Any]], fetch_start_timestamp: datetime, last_id_fetched: int):
    # only for service_records with the same update_time as fetch_start_timestamp
    return [service_record for service_record in service_records
            if get_service_record_update_time(service_record) != fetch_start_timestamp
            or service_record['id'] > last_id_fetched]


def reduce_service_records_to_limit(service_records: List[Dict[str, Any]], limit: int, last_fetch: datetime,
                                    last_id_fetched: int) -> Tuple[datetime, int, List[Dict[str, Any]]]:
    incidents_count = min(limit, len(service_records))
    # limit can't be 0 or less, but there could be no service_records at the wanted time
    if incidents_count > 0:
        service_records = service_records[:limit]
        last_fetched_service_record = service_records[incidents_count - 1]
        last_fetch = get_service_record_update_time(last_fetched_service_record)  # type: ignore
        last_id_fetched = last_fetched_service_record['id']
    return last_fetch, last_id_fetched, service_records


def parse_service_records(service_records: List[Dict[str, Any]], limit: int, fetch_start_timestamp: datetime,
                          last_id_fetched: int) -> Tuple[datetime, int, List[Dict[str, Any]]]:
    service_records = filter_service_records_by_time(service_records, fetch_start_timestamp)
    service_records = filter_service_records_by_id(service_records, fetch_start_timestamp, last_id_fetched)

    # sorting service_records by date and then by id
    service_records.sort(key=lambda service_record: (get_service_record_update_time(service_record), service_record['id']))

    last_fetch, last_id_fetched, service_records = reduce_service_records_to_limit(service_records, limit, fetch_start_timestamp,
                                                                                   last_id_fetched)

    incidents: List[Dict[str, Any]] = [service_record_to_incident_context(service_record) for service_record in service_records]
    return last_fetch, last_id_fetched, incidents


def calculate_fetch_start_datetime(last_fetch: str, first_fetch: str) -> datetime:
    first_fetch_datetime = dateparser.parse(first_fetch, settings={'TIMEZONE': 'UTC'})
    if last_fetch is None:
        return first_fetch_datetime

    last_fetch_datetime = dateparser.parse(last_fetch, settings={'TIMEZONE': 'UTC'})
    return max(last_fetch_datetime, first_fetch_datetime)


def get_service_record_update_time(service_record: Dict[str, Any]) -> Optional[datetime]:
    for i in service_record['info']:
        if i['key'] == 'update_time':
            # We are using 'valueCaption' and not 'value' as they hold different values
            occurred = str(i['valueCaption'])
            return dateparser.parse(occurred, settings={'TIMEZONE': 'UTC'})

    demisto.debug(f'The service record with ID {service_record["id"]} does not have a modify time (update_time).')
    return None


def service_record_to_incident_context(service_record: Dict[str, Any]):
    title, type_ = '', ''
    for i in service_record['info']:
        if i['key'] == 'sr_type':
            type_ = str(i['valueCaption'])
        if i['key'] == 'title':
            title = i['valueCaption']

    occurred = get_service_record_update_time(service_record)

    if not occurred:
        demisto.debug(f'The service record {type_} with ID {service_record["id"]} does not have a modify time (update_time) '
                      f'and therefore can\'t be fetched.')
        return None

    incident_context = {
        'name': title,
        'occurred': occurred.strftime(DATE_FORMAT),
        'rawJSON': json.dumps(service_record),
        'type': f'SysAid {type_}'
    }
    demisto.debug(f'New service record {type_} is: name: {incident_context["name"]}, occurred: {incident_context["occurred"]}, '
                  f'type: {incident_context["type"]}.')
    return incident_context


def test_module(client: Client, params: dict) -> None:
    message: str = ''

    try:
        if service_record_list_command(client, {'type': 'all'}):
            message = 'ok'

        if params['isFetch']:
            max_fetch = arg_to_number(params.get('max_fetch'))
            if max_fetch is not None and (max_fetch > MAX_INCIDENTS_TO_FETCH or max_fetch <= 0):
                raise DemistoException(f'Maximum number of service records to fetch exceeds the limit '
                                       f'(restricted to {MAX_INCIDENTS_TO_FETCH}), or is below zero.')

            included_statuses = params.get('included_statuses')
            statuses_set = set(argToList(included_statuses))
            if statuses_set - STATUSES:
                # todo needed? API lets us send unreal statuses
                raise DemistoException(f'Statuses {statuses_set - STATUSES} were given and are not legal statuses.'
                                       f'Statuses can be found by running the "sysaid-table-list" command with the '
                                       f'"list_id=status" argument.')

            fetch_types = params.get('fetch_types')
            fetch_types = 'all' if not fetch_types or 'all' in fetch_types else fetch_types

            include_archived = argToBoolean(params.get('include_archived', False))
            filters = {'status': included_statuses} if included_statuses else {}

            client.service_record_list_request(type_=fetch_types, limit=max_fetch, archive=int(include_archived), filters=filters)

    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure username and password are correctly set'
        else:
            raise e
    return return_results(message)


''' MAIN FUNCTION '''


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get('url')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    username = params['credentials']['identifier']
    password = params['credentials']['password']

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        client: Client = Client(urljoin(url, '/api/v1'), verify_certificate, proxy, auth=(username, password))
        commands = {
            'sysaid-table-list': table_list_command,
            'sysaid-asset-list': asset_list_command,
            'sysaid-asset-search': asset_search_command,
            'sysaid-filter-list': filter_list_command,
            'sysaid-user-list': user_list_command,
            'sysaid-user-search': user_search_command,
            'sysaid-service-record-list': service_record_list_command,
            'sysaid-service-record-search': service_record_search_command,
            'sysaid-service-record-update': service_record_update_command,
            'sysaid-service-record-close': service_record_close_command,
            'sysaid-service-record-template-get': service_record_template_get_command,
            'sysaid-service-record-create': service_record_create_command,
            'sysaid-service-record-delete': service_record_delete_command,
        }
        if command == 'fetch-incidents':
            first_fetch = params.get('first_fetch', FETCH_DEFAULT_TIME)
            included_statuses = params.get('included_statuses')
            include_archived = argToBoolean(params.get('include_archived', False))
            limit = arg_to_number(params.get('max_fetch'))
            fetch_types = params.get('fetch_types')

            incidents = fetch_incidents(client, first_fetch, limit, included_statuses, include_archived, fetch_types)
            demisto.incidents(incidents)

        elif command == 'test-module':
            test_module(client, params)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


''' ENTRY POINT '''

if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
