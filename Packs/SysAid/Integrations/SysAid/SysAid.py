import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import urllib3
import os
import mimetypes
from datetime import datetime


import requests
from typing import Any
from collections.abc import Callable

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

SERVICE_RECORD_ARGS = ['agreement', 'assigned_group', 'change_category', 'company', 'computer_id', 'cust_notes', 'department',
                       'description', 'due_date', 'email_account', 'escalation', 'followup_text', 'followup_user', 'impact',
                       'location', 'priority', 'problem_sub_type', 'problem_type', 'responsibility', 'solution', 'sr_type',
                       'status', 'sub_type', 'third_level_category', 'title', 'urgency']

TEMPLATE_OUTPUTS = ['key', 'value', 'mandatory', 'editable', 'type', 'defaultValue', 'keyCaption']

STATUSES = {'1', '2', '3', '4', '5', '6', '7', '8', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30',
            '31', '32', '33', '34', '35', '36', '39', '40', 'OPEN_CLASSES'}

DEFAULT_PAGE_SIZE = 100
DEFAULT_PAGE_NUMBER = 1
MAX_INCIDENTS_TO_FETCH = 200
FETCH_DEFAULT_TIME = '3 days'


''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, auth=auth)
        self._cookies: requests.cookies.RequestsCookieJar = self._get_cookies()

    def _get_cookies(self) -> requests.cookies.RequestsCookieJar:
        data = {'user_name': self._auth[0], 'password': self._auth[1]}

        # authentication errors are raised here
        response = self._http_request('POST', 'login', json_data=data, resp_type='response')

        return response.cookies

    def table_list_request(self, entity: str = None, fields: str = None):
        params = assign_params(entity=entity, fields=fields)

        response = self._http_request('GET', 'list', params=params, cookies=self._cookies)

        return response

    def table_list_with_id_request(self, list_id: str, entity: str = None, entity_id: str = None, entity_type: int = None,
                                   fields: str = None, key: str = None):
        params = assign_params(entity=entity, fields=fields, entityId=entity_id, entityType=entity_type, key=key)

        response = self._http_request('GET', f'list/{list_id}', params=params, cookies=self._cookies)

        return response

    def asset_list_request(self, fields: str = None, offset: int = None, limit: int = None):
        params = assign_params(fields=fields, offset=offset, limit=limit)

        response = self._http_request('GET', 'asset', params=params, cookies=self._cookies)

        return response

    def asset_list_with_id_request(self, asset_id: str, fields: str = None):
        params = assign_params(fields=fields)

        response = self._http_request('GET', f'asset/{asset_id}', params=params, cookies=self._cookies)

        return response

    def asset_search_request(self, query: str, fields: str = None, limit: int = None, offset: int = None):
        params = assign_params(query=query, fields=fields, limit=limit, offset=offset)

        response = self._http_request('GET', 'asset/search', params=params, cookies=self._cookies)

        return response

    def filter_list_request(self, fields: str = None):
        params = assign_params(fields=fields)

        response = self._http_request('GET', 'filters', params=params, cookies=self._cookies)

        return response

    def user_list_request(self, fields: str = None, record_type: str = None, offset: int = None, limit: int = None):
        params = assign_params(fields=fields, type=record_type, offset=offset, limit=limit)

        response = self._http_request('GET', 'users', params=params, cookies=self._cookies)

        return response

    def user_search_request(self, query: str, fields: str = None, record_type: str = None, offset: int = None, limit: int = None):
        params = assign_params(query=query, fields=fields, type=record_type, offset=offset, limit=limit)

        response = self._http_request('GET', 'users/search', params=params, cookies=self._cookies)

        return response

    def service_record_list_request(self, record_type: str, fields: str = None, offset: int = None, limit: int = None,
                                    ids: List[str] = None, archive: int = None, filters: dict[str, Any] = None, ):
        params = assign_params(type=record_type, fields=fields, offset=offset, limit=limit, ids=ids, archive=archive)
        params.update(filters or {})
        response = self._http_request('GET', 'sr', params=params, cookies=self._cookies)

        return response

    def service_record_search_request(self, record_type: str, query: str, fields: str = None, offset: int = None,
                                      limit: int = None, archive: int = None, filters: dict[str, Any] = None):
        params = assign_params(type=record_type, fields=fields, offset=offset, limit=limit, query=query, archive=archive)
        params.update(filters)

        response = self._http_request('GET', 'sr/search', params=params, cookies=self._cookies)

        return response

    def service_record_update_request(self, id_: str, info: List[dict[str, str]] = None):
        data = {"id": id_, "info": info}

        response = self._http_request('PUT', f'sr/{id_}', json_data=data, cookies=self._cookies, resp_type='response')

        return response

    def service_record_close_request(self, id_: str, solution: str = None):
        data = {"solution": solution}

        # 400 - 'This service record is already closed' might be raised - which isn't a real error
        response = self._http_request('PUT', f'sr/{id_}/close', json_data=data, cookies=self._cookies, resp_type='response',
                                      ok_codes=(200, 400))

        return response

    def service_record_template_get_request(self, record_type: str, fields: str = None, template_id: str = None):
        params = assign_params(fields=fields, type=record_type, template=template_id)

        response = self._http_request('GET', 'sr/template', params=params, cookies=self._cookies)

        return response

    def service_record_create_request(self, record_type: str, info: List[dict[str, str]], fields: str = None,
                                      template_id: str = None):
        params = assign_params(fields=fields, type=record_type, template=template_id)
        data = {"info": info}

        response = self._http_request('POST', 'sr', params=params, json_data=data, cookies=self._cookies)

        return response

    def service_record_delete_request(self, ids: str, solution: str = None):
        params = assign_params(ids=ids)
        data = {"solution": solution}

        # 400 - 'Invalid service record id' might be raised - which isn't a real error
        response = self._http_request('DELETE', 'sr', params=params, json_data=data, cookies=self._cookies, resp_type='response',
                                      ok_codes=(200, 400))
        return response

    def service_record_attach_file_request(self, sr_id: str, file_id: str):
        # Get file info
        file_data, file_size, file_name = read_file(file_id)
        file_type = get_content_type(file_name)

        response = self._http_request('POST', f'sr/{sr_id}/attachment', files={'file': (file_name, file_data, file_type)},
                                      cookies=self._cookies, resp_type='response')

        return response

    def service_record_get_file_request(self, sr_id: str, file_id: str):

        response = self._http_request('GET', f'sr/{sr_id}/attachment/{file_id}', cookies=self._cookies, resp_type='response')

        return response

    def service_record_delete_file_request(self, sr_id: str, file_id: str):
        data = {'fileId': f'{file_id}'}

        response = self._http_request('DELETE', f'sr/{sr_id}/attachment', json_data=data, cookies=self._cookies,
                                      resp_type='response')

        return response

    def service_record_get_request(self, sr_id: str, fields: str = None):
        params = assign_params(fields=fields)
        response = self._http_request('GET', f'sr/{sr_id}', params=params, cookies=self._cookies)

        return response

    def service_record_add_note_request(self, sr_id: str, note: str, username: str):
        now = datetime.now().strftime('%s')
        now_ms = f'{now}000'

        data = {
            "id": f"{sr_id}",
            "info": [
                {
                    "key": "notes",
                    "value": [
                        {
                            "userName": f"{username}",
                            "createDate": f"{now_ms}",
                            "text": f"{note}"
                        }
                    ]
                }
            ]
        }
        response = self._http_request('PUT', f'sr/{sr_id}', json_data=data, cookies=self._cookies, resp_type='response')

        return response


''' HELPER FUNCTIONS '''


def read_file(file_id: str) -> tuple[bytes, int, str]:
    """
    Reads file that was uploaded to War Room.

    :type file_id: ``str``
    :param file_id: The id of uploaded file to War Room

    :return: data, size of the file in bytes and uploaded file name.
    :rtype: ``bytes``, ``int``, ``str``
    """
    try:
        file_info = demisto.getFilePath(file_id)
        with open(file_info['path'], 'rb') as file_data:
            data = file_data.read()
            file_size = os.path.getsize(file_info['path'])
            return data, file_size, file_info['name']
    except Exception as e:
        raise Exception(f'Unable to read file with id {file_id}', e)


def get_content_type(file_name: str):
    """Get the correct content type for the POST request.

    Args:
        file_name: file name

    Returns:
        the content type - image with right type for images , and general for other types..
    """
    file_type = None
    if not file_name:
        demisto.debug("file name was not suplied, uploading with general type")
    else:
        file_type, _ = mimetypes.guess_type(file_name)
    return file_type or '*/*'


def create_readable_response(responses: Union[dict, List[dict], str], handle_one_response: Callable, remove_if_null: str = None) \
        -> Union[str, List[dict[str, str]]]:
    """
    Creates a readable response for responses that have fields in the form of:
        {
        'key': 'The Wanted Key',
        'value': 'The Wanted Value'
        }

    :param responses: The response to turn to human readable
    :param handle_one_response: The function to operate on one response to turn it to human readable
    :param remove_if_null: Field name that if it has no value- the whole response will be ignored
    """
    readable_response = []

    if isinstance(responses, dict):
        responses = [responses]

    if isinstance(responses, str):
        return responses

    for response in responses:
        if remove_if_null:
            response_entry = handle_one_response(response, remove_if_null)
        else:
            response_entry = handle_one_response(response)

        if response_entry:
            readable_response.append(response_entry)

    return readable_response


def asset_list_handler(response: dict[str, Any], remove_if_null: str):
    """
    Creates a readable response for one asset response. Is sent as **handle_one_response** to *create_readable_response*.

    :param response: The response to turn to human readable
    :param remove_if_null: Field name that if it has no value- the whole response will be ignored
    """
    new_info = []
    response_entry = {key: response[key] for key in ['id', 'name'] if key in response}
    if 'info' in response:
        for asset_info in response['info']:
            if asset_info['keyCaption'] in ['Model', 'Description'] and asset_info[remove_if_null]:
                new_info.append(f'{asset_info["keyCaption"]}: {asset_info["valueCaption"]}')

        response_entry['info'] = new_info
    return response_entry


def filter_list_handler(response: dict[str, Any]):
    """
    Creates a readable response for one filter response. Is sent as **handle_one_response** to *create_readable_response*.

    :param response: The response to turn to human readable
    """
    new_info = []
    response_entry = {key: response[key] for key in ['id', 'type', 'caption'] if key in response}
    if 'values' in response:
        for filter_info in response['values']:
            new_info.append(f'{filter_info["id"]}: {filter_info["caption"]}')

        response_entry['values'] = new_info
    return response_entry


def service_record_handler(response: dict[str, Any]):
    """
    Creates a readable response for one service record response. Is sent as **handle_one_response** to *create_readable_response*.

    :param response: The response to turn to human readable
    """
    response_entry = {'id': response['id']}
    if 'info' in response:
        for service_record_info in response['info']:
            if service_record_info['key'] in ['title', 'notes']:
                response_entry[service_record_info['key']] = service_record_info['value']
            if service_record_info['key'] in ['status', 'update_time', 'sr_type']:
                response_entry[service_record_info['keyCaption']] = service_record_info['valueCaption']

        return response_entry

    return None


def service_record_response_handler(response: dict[str, Any]):
    """
    Creates a response for one service record response. Is sent as **handle_one_response** to *create_readable_response*.
    Saves all fields with their key names.

    :param response: The response to turn to human readable
    """
    for service_record_info in response.get('info', []):
        response[service_record_info['key']] = service_record_info['valueCaption']

    return response


def extract_filters(custom_fields_keys: List[str], custom_fields_values: List[str]) -> dict[str, Any]:
    """
    Additional filters are sent in a request in a form of:
        {filter1}={filter1_value}&{filter2}={filter2_value}
    This function organizes them in a form similar to regular arguments given.
    """
    filters = {}
    for key, value in zip(custom_fields_keys, custom_fields_values):
        filters[key] = value
    return filters


def set_service_record_info(args: dict[str, Any]) -> List[dict[str, str]]:
    """
    Update and create service record commands have many arguments, this function organizes the arguments in the form they need to
    appear in the body of the request.
    """
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


def template_readable_response(responses: Union[dict, List[dict], str]) -> Union[str, List[dict[str, Any]]]:
    """
    Creates a readable response for responses that have fields in the form of:
        {
            'defaultValue': null,
            'editable': true,
            'key': 'sr_type',
            'keyCaption': 'Service Record Type',
            'mandatory': false,
            'type': 'list',
            'value': 2
        }

    :param responses: The response to turn to human readable
    """
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


def calculate_offset(page_size: int, page_number: int) -> int:
    """
    SysAid receives offset and page_size arguments. To follow our convention, we receive page_size and page_number arguments and
    calculate the offset from them.
    The offset is the start point from which to retrieve values, zero based. It starts at 0.

    :param page_size: The number of results to show in one page.
    :param page_number: The page number to show, starts at 1.
    """
    return page_size * (page_number - 1)


def create_paging_header(page_size: Union[str, int] = None, page_number: Union[str, int] = None):
    if page_number or page_size:
        return 'Showing' + (f' {page_size}' if page_size else '') + ' results' + \
               (f' from page {page_number}' if page_number else '') + ':\n'
    return ''


def set_returned_fields(fields: str = None) -> Optional[str]:
    """
    We made the 'fields' argument mandatory, so the context data won’t be filled with unneeded data.
    It is not mandatory by SysAid, and when it is not sent- all fields will be returned in the response.
    To enable this behavior, we added an option to send 'fields=all'. In that case, we will not send a value to SysAid in the
    fields parameter.
    """
    if fields and 'all' in fields:
        return None
    return fields


''' FETCH HELPER FUNCTIONS '''


def fetch_request(client: Client, fetch_types: str = None, include_archived: bool = False, included_statuses: str = None,
                  filter_times: str = None):
    fetch_types = 'all' if not fetch_types or 'all' in fetch_types else fetch_types
    filters = {'status': included_statuses} if included_statuses else {}
    if filter_times is not None:
        filters.update({'insert_time': filter_times})

    response = client.service_record_list_request(record_type=fetch_types, archive=int(include_archived), filters=filters)
    responses = [response] if isinstance(response, dict) else response
    demisto.debug(f'The request returned {len(response)} service records.')

    return responses


def filter_service_records_by_time(service_records: List[dict[str, Any]], fetch_start_datetime: datetime) \
        -> List[dict[str, Any]]:
    """
    Returns the service records that changed after the fetch_start_datetime, from the service_records given.

    :param service_records: Service records as given form SysAid.
    :param fetch_start_datetime: The datetime to start fetching service records from.
    """
    filtered_service_records = []
    for service_record in service_records:
        update_time = get_service_record_update_time(service_record)
        if update_time and update_time >= fetch_start_datetime:
            filtered_service_records.append(service_record)

    return filtered_service_records


def filter_service_records_by_id(service_records: List[dict[str, Any]], fetch_start_datetime: datetime, last_id_fetched: str):
    # only for service_records with the same update_time as fetch_start_datetime
    return [service_record for service_record in service_records
            if get_service_record_update_time(service_record) != fetch_start_datetime
            or service_record['id'] > last_id_fetched]


def reduce_service_records_to_limit(service_records: List[dict[str, Any]], limit: int, last_fetch: datetime,
                                    last_id_fetched: str) -> tuple[datetime, str, List[dict[str, Any]]]:
    incidents_count = min(limit, len(service_records))
    # limit can't be 0 or less, but there could be no service_records at the wanted time
    if incidents_count > 0:
        service_records = service_records[:limit]
        last_fetched_service_record = service_records[incidents_count - 1]
        last_fetch = get_service_record_update_time(last_fetched_service_record)  # type: ignore
        last_id_fetched = last_fetched_service_record['id']
    return last_fetch, last_id_fetched, service_records


def parse_service_records(service_records: List[dict[str, Any]], limit: int, fetch_start_datetime: datetime,
                          last_id_fetched: str) -> tuple[datetime, str, List[dict[str, Any]]]:
    service_records = filter_service_records_by_time(service_records, fetch_start_datetime)
    service_records = filter_service_records_by_id(service_records, fetch_start_datetime, last_id_fetched)

    # sorting service_records by date and then by id
    service_records.sort(key=lambda service_record: (get_service_record_update_time(service_record), service_record['id']))

    last_fetch, last_id_fetched, service_records = reduce_service_records_to_limit(service_records, limit, fetch_start_datetime,
                                                                                   last_id_fetched)

    incidents: List[dict[str, Any]] = [service_record_to_incident_context(service_record) for service_record in service_records]
    return last_fetch, last_id_fetched, incidents


def calculate_fetch_start_datetime(last_fetch: str, first_fetch: str):
    first_fetch_datetime = dateparser.parse(first_fetch, settings={'TIMEZONE': 'UTC'})
    if last_fetch is None:
        return first_fetch_datetime

    last_fetch_datetime = dateparser.parse(last_fetch, settings={'TIMEZONE': 'UTC'})
    if last_fetch_datetime is None:
        raise DemistoException(f'Could not parse {last_fetch}')
    if first_fetch_datetime is None:
        return last_fetch_datetime
    return max(last_fetch_datetime, first_fetch_datetime)


def get_service_record_update_time(service_record: dict[str, Any]) -> Optional[datetime]:
    for service_record_info in service_record['info']:
        if service_record_info['key'] == 'update_time':
            # We are using 'valueCaption' and not 'value' as they hold different values
            occurred = str(service_record_info['valueCaption'])
            return dateparser.parse(occurred, settings={'TIMEZONE': 'UTC'})

    demisto.debug(f'The service record with ID {service_record["id"]} does not have a modify time (update_time).')
    return None


def service_record_to_incident_context(service_record: dict[str, Any]):
    title, record_type = '', ''
    for service_record_info in service_record['info']:
        if service_record_info['key'] == 'sr_type':
            record_type = str(service_record_info['valueCaption'])
        elif service_record_info['key'] == 'title':
            title = service_record_info['valueCaption']

    occurred_datetime = get_service_record_update_time(service_record)
    occurred = occurred_datetime.strftime(DATE_FORMAT) if occurred_datetime else None

    incident_context = {
        'name': title,
        'occurred': occurred,
        'rawJSON': json.dumps(service_record),
        'type': f'SysAid {record_type}'
    }
    demisto.debug(f'New service record {record_type} is: name: {incident_context["name"]}, occurred: '
                  f'{incident_context["occurred"]}, type: {incident_context["type"]}.')
    return incident_context


''' COMMAND FUNCTIONS '''


def table_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    entity = args.get('entity')
    entity_id = args.get('entity_id')
    entity_type = arg_to_number(args.get('entity_type'))
    key = args.get('key')
    list_id = args.get('list_id')
    fields = args.get('fields')

    if list_id:
        response = client.table_list_with_id_request(list_id, entity, entity_id, entity_type, fields, key)
    else:
        response = client.table_list_request(entity, fields)
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


def asset_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    asset_id = args.get('asset_id')
    fields = set_returned_fields(args.get('fields'))

    limit = arg_to_number(args.get('page_size')) or DEFAULT_PAGE_SIZE
    page_number = arg_to_number(args.get('page_number')) or DEFAULT_PAGE_NUMBER
    offset = calculate_offset(limit, page_number)
    heading = ''

    if asset_id:
        response = client.asset_list_with_id_request(asset_id, fields)
    else:
        response = client.asset_list_request(fields, offset, limit)
        heading = create_paging_header(limit, page_number)
    headers = ['id', 'name', 'info']
    readable_response = create_readable_response(response, asset_list_handler, 'valueCaption')
    command_results = CommandResults(
        outputs_prefix='SysAid.Asset',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=heading + tableToMarkdown(
            f'Asset {asset_id + " " if asset_id else ""}Results:',
            readable_response,
            headers=headers,
            removeNull=True,
            headerTransform=pascalToSpace)
    )

    return command_results


def asset_search_command(client: Client, args: dict[str, Any]) -> CommandResults:
    query = args.get('query')
    fields = set_returned_fields(args.get('fields'))

    limit = arg_to_number(args.get('page_size')) or DEFAULT_PAGE_SIZE
    page_number = arg_to_number(args.get('page_number')) or DEFAULT_PAGE_NUMBER
    offset = calculate_offset(limit, page_number)

    response = client.asset_search_request(str(query), fields, limit, offset)
    headers = ['id', 'name', 'info']
    readable_response = create_readable_response(response, asset_list_handler, 'value')
    command_results = CommandResults(
        outputs_prefix='SysAid.Asset',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=create_paging_header(limit, page_number) + tableToMarkdown('Asset Results:',
                                                                                   readable_response,
                                                                                   headers=headers,
                                                                                   removeNull=True,
                                                                                   headerTransform=pascalToSpace)
    )

    return command_results


def filter_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    fields = set_returned_fields(args.get('fields'))

    response = client.filter_list_request(fields)
    headers = ['id', 'caption', 'type', 'values']
    readable_response = create_readable_response(response, filter_list_handler)
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


def user_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    fields = set_returned_fields(args.get('fields'))
    record_type = args.get('type')

    limit = arg_to_number(args.get('page_size')) or DEFAULT_PAGE_SIZE
    page_number = arg_to_number(args.get('page_number')) or DEFAULT_PAGE_NUMBER
    offset = calculate_offset(limit, page_number)

    response = client.user_list_request(fields, record_type, offset, limit)
    headers = ['id', 'name', 'isAdmin', 'isManager', 'isSysAidAdmin', 'isGuest']
    command_results = CommandResults(
        outputs_prefix='SysAid.User',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=create_paging_header(limit, page_number) + tableToMarkdown('Filter Results:',
                                                                                   response,
                                                                                   headers=headers,
                                                                                   removeNull=True)
    )

    return command_results


def user_search_command(client: Client, args: dict[str, Any]) -> CommandResults:
    query = args.get('query')
    fields = set_returned_fields(args.get('fields'))
    record_type = args.get('type')

    limit = arg_to_number(args.get('page_size')) or DEFAULT_PAGE_SIZE
    page_number = arg_to_number(args.get('page_number')) or DEFAULT_PAGE_NUMBER
    offset = calculate_offset(limit, page_number)

    response = client.user_search_request(str(query), fields, record_type, offset, limit)
    headers = ['id', 'name', 'isAdmin', 'isManager', 'isSysAidAdmin', 'isGuest']
    command_results = CommandResults(
        outputs_prefix='SysAid.User',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=create_paging_header(limit, page_number) + tableToMarkdown('User Results:',
                                                                                   response,
                                                                                   headers=headers,
                                                                                   removeNull=True)
    )

    return command_results


def service_record_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    record_type = args.get('type')
    fields = set_returned_fields(args.get('fields'))
    ids = args.get('ids')
    archive = arg_to_number(args.get('archive'))

    limit = arg_to_number(args.get('page_size')) or DEFAULT_PAGE_SIZE
    page_number = arg_to_number(args.get('page_number')) or DEFAULT_PAGE_NUMBER
    offset = calculate_offset(limit, page_number)

    custom_fields_keys = argToList(args.get('custom_fields_keys'))
    custom_fields_values = argToList(args.get('custom_fields_values'))

    # SysAid expects the timestamp to be provided as `timestamp,timestamp`, but we are splitting on ,
    # This breaks the inputs. Instead we are asking for `timestamp-timestamp` as input, then convert the - to ,
    custom_fields_values = [value.replace("-", ",") for value in custom_fields_values]
    filters = extract_filters(custom_fields_keys, custom_fields_values)

    response = client.service_record_list_request(str(record_type), fields, offset, limit, ids, archive, filters)
    headers = ['id', 'title', 'Status', 'Modify time', 'Service Record Type', 'notes']
    readable_response = create_readable_response(response, service_record_handler)
    response = create_readable_response(response, service_record_response_handler)
    command_results = CommandResults(
        outputs_prefix='SysAid.ServiceRecord',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=create_paging_header(limit, page_number) + tableToMarkdown('Service Record Results:',
                                                                                   readable_response,
                                                                                   headers=headers,
                                                                                   removeNull=True,
                                                                                   headerTransform=pascalToSpace)
    )

    return command_results


def service_record_search_command(client: Client, args: dict[str, Any]) -> CommandResults:
    query = args.get('query')
    record_type = args.get('type')
    fields = set_returned_fields(args.get('fields'))
    archive = arg_to_number(args.get('archive'))

    limit = arg_to_number(args.get('page_size')) or DEFAULT_PAGE_SIZE
    page_number = arg_to_number(args.get('page_number')) or DEFAULT_PAGE_NUMBER
    offset = calculate_offset(limit, page_number)

    custom_fields_keys = argToList(args.get('custom_fields_keys'))
    custom_fields_values = argToList(args.get('custom_fields_values'))
    filters = extract_filters(custom_fields_keys, custom_fields_values)

    response = client.service_record_search_request(str(record_type), str(query), fields, offset, limit, archive, filters)
    headers = ['id', 'title', 'Status', 'Modify time', 'Service Record Type', 'notes']
    readable_response = create_readable_response(response, service_record_handler)
    response = create_readable_response(response, service_record_response_handler)
    command_results = CommandResults(
        outputs_prefix='SysAid.ServiceRecord',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=create_paging_header(limit, page_number) + tableToMarkdown('Service Record Results:',
                                                                                   readable_response,
                                                                                   headers=headers,
                                                                                   removeNull=True,
                                                                                   headerTransform=pascalToSpace)
    )

    return command_results


def service_record_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
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


def service_record_close_command(client: Client, args: dict[str, Any]) -> CommandResults:
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


def service_record_template_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    fields = set_returned_fields(args.get('fields'))
    record_type = args.get('type')
    template_id = args.get('template_id')

    response = client.service_record_template_get_request(str(record_type), fields, template_id)
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


def service_record_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    fields = set_returned_fields(args.get('fields'))
    record_type = args.get('type')
    template_id = args.get('template_id')
    info = set_service_record_info(args)

    response = client.service_record_create_request(str(record_type), info, fields, template_id)

    headers = ['id', 'title', 'Status', 'Modify time', 'Service Record Type', 'notes']
    readable_response = create_readable_response(response, service_record_handler)
    response = create_readable_response(response, service_record_response_handler)
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


def service_record_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    ids = str(args.get('ids'))
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


def service_record_attach_file_command(client: Client, args: dict[str, Any]) -> CommandResults:
    sr_id = str(args.get('id'))
    file_id = str(args.get('file_id'))

    response = client.service_record_attach_file_request(sr_id, file_id)
    if response.status_code == 200:
        msg = f'File uploaded to Service Record {sr_id} successfully.'
    else:
        msg = f'Error {response.status_code} occurred while uploading file to service record {sr_id}.'

    command_results = CommandResults(
        outputs_prefix='SysAid.ServiceRecord',
        readable_output=msg
    )

    return command_results


def service_record_get_file_command(client: Client, args: dict[str, Any]):
    sr_id = str(args.get('id'))
    file_id = str(args.get('file_id'))
    file_name = str(args.get('file_name'))

    response = client.service_record_get_file_request(sr_id, file_id)

    if response.status_code == 200:
        file_data = response.content
        return_results(fileResult(file_name, file_data))

        attachment_list = []
        attachment_list.append({"file_name": file_name, "data": file_data})
        return_results(str(attachment_list))
    else:
        msg = f'Error {response.status_code} occurred while try to download file from service record {sr_id}.'
        return_error(msg)


def service_record_delete_file_command(client: Client, args: dict[str, Any]) -> CommandResults:
    sr_id = str(args.get('id'))
    file_id = str(args.get('file_id'))

    response = client.service_record_delete_file_request(sr_id, file_id)
    if response.status_code == 200:
        msg = f'File deleted from Service Record {sr_id} successfully.'
    else:
        msg = f'Error {response.status_code} occurred while deleting file from service record {sr_id}.'

    command_results = CommandResults(
        outputs_prefix='SysAid.ServiceRecord',
        readable_output=msg
    )

    return command_results


def service_record_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    sr_id = str(args.get('id'))
    fields = set_returned_fields(args.get('fields'))

    response = client.service_record_get_request(sr_id, fields)
    headers = ['id', 'title', 'Status', 'Modify time', 'Service Record Type', 'notes']
    readable_response = create_readable_response(response, service_record_handler)
    response = create_readable_response(response, service_record_response_handler)
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


def service_record_add_note_command(client: Client, args: dict[str, Any]) -> CommandResults:
    sr_id = str(args.get('id'))
    note = str(args.get('note'))
    username = str(args.get('username'))

    client.service_record_add_note_request(sr_id, note, username)
    msg = 'Updated record with new note'

    command_results = CommandResults(
        outputs_prefix='SysAid.ServiceRecord',
        readable_output=msg
    )

    return command_results


def fetch_incidents(client: Client, first_fetch: str, limit: Optional[int] = MAX_INCIDENTS_TO_FETCH,
                    included_statuses: str = None, include_archived: bool = False, fetch_types: str = None):
    last_fetch = demisto.getLastRun().get('last_fetch')
    last_id_fetched = demisto.getLastRun().get('last_id_fetched', '-1')
    fetch_start_datetime = calculate_fetch_start_datetime(last_fetch, first_fetch)

    # Filter only tickets since the last pull time
    fetch_start_epoch = int(fetch_start_datetime.timestamp() * 1000)
    filter_times = f'{fetch_start_epoch},0'
    demisto.debug(f'last fetch was at: {last_fetch}, last id fetched was: {last_id_fetched}, '
                  f'time to fetch from is: {fetch_start_datetime}, time filter is: {filter_times}.')

    responses = fetch_request(client, fetch_types, include_archived, included_statuses, filter_times)
    limit = limit or MAX_INCIDENTS_TO_FETCH
    last_fetch, last_id_fetched, incidents = parse_service_records(responses, limit, fetch_start_datetime, last_id_fetched)
    demisto.setLastRun({'last_fetch': last_fetch.isoformat(), 'last_id_fetched': last_id_fetched})

    return incidents


def test_module(client: Client, params: dict) -> None:
    message: str = ''

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
            raise DemistoException(f'Statuses {statuses_set - STATUSES} were given and are not legal statuses. '
                                   f'Statuses can be found by running the "sysaid-table-list" command with the '
                                   f'"list_id=status" argument.')

        fetch_types = params.get('fetch_types')
        fetch_types = 'all' if not fetch_types or 'all' in fetch_types else fetch_types

        include_archived = argToBoolean(params.get('include_archived', False))
        filters = {'status': included_statuses} if included_statuses else {}

        client.service_record_list_request(record_type=fetch_types, limit=max_fetch, archive=int(include_archived),
                                           filters=filters)

    return return_results(message)


''' MAIN FUNCTION '''


def main() -> None:
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
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
            'sysaid-service-record-attach-file': service_record_attach_file_command,
            'sysaid-service-record-get-file': service_record_get_file_command,
            'sysaid-service-record-delete-file': service_record_delete_file_command,
            'sysaid-service-record-get': service_record_get_command,
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
        elif command == 'sysaid-service-record-add-note':
            args['username'] = username
            return_results(service_record_add_note_command(client, args))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


''' ENTRY POINT '''

if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
