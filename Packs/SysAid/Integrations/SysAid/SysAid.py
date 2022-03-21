import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import requests
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

SERVICE_RECORD_ARGS = ['agreement', 'assigned_group', 'change_category', 'company', 'computer_id', 'cust_notes', 'department',
                       'description', 'due_date', 'email_account', 'escalation', 'followup_text', 'followup_user', 'impact',
                       'location', 'priority', 'problem_sub_type', 'problem_type', 'responsibility', 'solution', 'sr_type',
                       'status', 'sub_type', 'third_level_category', 'title', 'urgency']

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
                                    ids: List[str] = None, archive: int = None,
                                    filters: Dict[str, str] = None):
        params = assign_params(type=type_, fields=fields, offset=offset, limit=limit, ids=ids, archive=archive)
        params.update(filters)

        response = self._http_request('GET', 'sr', params=params, cookies=self._cookies)

        return response

    def service_record_search_request(self, type_: str, query: str, fields: List[str] = None, offset: int = None,
                                      limit: int = None, archive: int = None, filters: Dict[str, str] = None):
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


def asset_list_readable_response(responses: Union[dict, List[dict], str], regular_titles: List[str], special_title: str,
                                 special_title_key: str, special_title_value: str, remove_if_null: str = None) \
        -> Union[str, List[Dict[str, str]]]:
    readable_response = []

    if isinstance(responses, dict):
        responses = [responses]

    if isinstance(responses, str):
        return responses

    for response in responses:
        new_info = []
        response_entry = {key: response[key] for key in regular_titles}

        for info in response[special_title]:
            if not remove_if_null or info[remove_if_null]:
                new_info.append(f'{info[special_title_key]}: {info[special_title_value]}')

        response_entry[special_title] = new_info
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

        for info in response['info']:
            if info['key'] == 'title':
                response_entry['title'] = info['value']
            elif info['key'] == 'status':
                response_entry['status'] = info['value']

        if len(response_entry) == 3:
            readable_response.append(response_entry)

    return readable_response


def extract_filters(custom_fields_keys: List[str], custom_fields_values: List[str]) -> Dict[str, str]:
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
        all_info_for_response = []

        for response_info in response['info']:
            info = ''
            for key in ['key', 'value', 'mandatory', 'editable', 'type', 'defaultValue', 'keyCaption']:
                if key in response_info:
                    info += f'{", " if info else ""}{key}: {response_info[key]}'

            if info:
                all_info_for_response.append(info)

        readable_response.append({'id': response['id'], 'info': all_info_for_response})

    return readable_response


''' COMMAND FUNCTIONS '''


def table_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    entity = args.get('entity')
    entity_id = args.get('entity_id')
    entity_type = arg_to_number(args.get('entity_type'))
    key = args.get('key')
    list_id = str(args.get('list_id'))
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
        readable_output=tableToMarkdown(f'Lists {list_id if list_id else entity or "sr"} Results:',
                                        response,
                                        headers=headers,
                                        removeNull=True)
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
    readable_response = asset_list_readable_response(response, ['id', 'name'], 'info', 'keyCaption', 'valueCaption',
                                                     'valueCaption')
    command_results = CommandResults(
        outputs_prefix='SysAid.Asset',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(f'Asset {asset_id + " " if asset_id else ""}Results:',
                                        readable_response,
                                        headers=headers,
                                        removeNull=True)
    )

    return command_results


def asset_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    query = str(args.get('query'))
    fields = argToList(args.get('fields'))
    offset = arg_to_number(args.get('offset'))
    limit = arg_to_number(args.get('limit'))

    response = client.asset_search_request(query, fields, limit, offset)
    headers = ['id', 'name', 'info']
    readable_response = asset_list_readable_response(response, ['id', 'name'], 'info', 'keyCaption', 'valueCaption', 'value')
    command_results = CommandResults(
        outputs_prefix='SysAid.Asset',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Asset Results:',
                                        readable_response,
                                        headers=headers,
                                        removeNull=True)
    )

    return command_results


def filter_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    fields = argToList(args.get('fields'))
    offset = arg_to_number(args.get('offset'))
    limit = arg_to_number(args.get('limit'))

    response = client.filter_list_request(fields, offset, limit)
    headers = ['id', 'caption', 'type', 'values']
    readable_response = asset_list_readable_response(response, ['id', 'type', 'caption'], 'values', 'id', 'caption')
    command_results = CommandResults(
        outputs_prefix='SysAid.Filter',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Filter Results:',
                                        readable_response,
                                        headers=headers,
                                        removeNull=True)
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
    query = str(args.get('query'))
    fields = argToList(args.get('fields'))
    type_ = args.get('type')
    offset = arg_to_number(args.get('offset'))
    limit = arg_to_number(args.get('limit'))

    response = client.user_search_request(query, fields, type_, offset, limit)
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
    type_ = str(args.get('type'))
    fields = argToList(args.get('fields'))
    offset = arg_to_number(args.get('offset'))
    limit = arg_to_number(args.get('limit'))
    ids = argToList(args.get('ids'))
    archive = arg_to_number(args.get('archive'))
    custom_fields_keys = argToList(args.get('custom_fields_keys'))
    custom_fields_values = argToList(args.get('custom_fields_values'))
    filters = extract_filters(custom_fields_keys, custom_fields_values)

    response = client.service_record_list_request(type_, fields, offset, limit, ids, archive, filters)
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
                                        removeNull=True)
    )

    return command_results


def service_record_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    query = str(args.get('query'))
    type_ = str(args.get('type'))
    fields = argToList(args.get('fields'))
    offset = arg_to_number(args.get('offset'))
    limit = arg_to_number(args.get('limit'))
    archive = arg_to_number(args.get('archive'))
    custom_fields_keys = argToList(args.get('custom_fields_keys'))
    custom_fields_values = argToList(args.get('custom_fields_values'))
    filters = extract_filters(custom_fields_keys, custom_fields_values)

    response = client.service_record_search_request(type_, query, fields, offset, limit, archive, filters)
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
                                        removeNull=True)
    )

    return command_results


def service_record_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id'))
    info = set_service_record_info(args)

    response = client.service_record_update_request(id_, info)
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
    id_ = str(args.get('id'))
    solution = args.get('solution')

    response = client.service_record_close_request(id_, solution)
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
    type_ = str(args.get('type'))
    template_id = args.get('template_id')

    response = client.service_record_template_get_request(type_, fields, template_id)
    readable_response = template_readable_response(response)
    headers = ['id', 'info']
    command_results = CommandResults(
        outputs_prefix='SysAid.ServiceRecordTemplate',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Service Record Results:',
                                        readable_response,
                                        headers=headers,
                                        removeNull=True)
    )

    return command_results


def service_record_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    fields = argToList(args.get('fields'))
    type_ = str(args.get('type'))
    template_id = args.get('template_id')
    info = set_service_record_info(args)

    response = client.service_record_create_request(type_, info, fields, template_id)
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
                                        removeNull=True)
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


def test_module(client: Client) -> None:
    message: str = ''

    try:
        if service_record_list_command(client, {'type': 'all'}):
            message = 'ok'
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
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

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


''' ENTRY POINT '''

if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
