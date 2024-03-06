import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

from typing import Any

''' CONSTANTS '''

USER_STATUS_DICT = {
    'Active': '1',
    'Registered': '2',
    'Locked': '3',
}

ISSUE_TRACKER_DICT = {
    'Bug': '1',
    'Feature': '2',
    'Support': '3'}

ISSUE_STATUS_DICT = {
    'New': '1',
    'In progress': '2',
    'Resolved': '3',
    'Feedback': '4',
    'Closed': '5',
    'Rejected': '6',
    'open': 'open',
    'closed': 'closed',
    '*': '*'
}

ISSUE_PRIORITY_DICT = {
    'Low': '1',
    'Normal': '2',
    'High': '3',
    'Urgent': '4',
    'Immediate': '5'
}
''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, server_url, api_key, verify=True, proxy=False, headers=None, auth=None, project_id=None):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

        self._post_put_header = {'Content-Type': 'application/json', 'X-Redmine-API-Key': api_key}
        self._upload_file_header = {'Content-Type': 'application/octet-stream', 'X-Redmine-API-Key': api_key}
        self._get_header = {'X-Redmine-API-Key': api_key}
        self._project_id = project_id

    def create_issue_request(self, args, project_id=None):
        remove_nulls_from_dictionary(args)
        uploads = args.pop('uploads', None)  # to remove the out and in of uploads
        body_for_request = {'issue': args}
        if uploads:
            body_for_request['issue']['uploads'] = uploads
        response = self._http_request('POST', '/issues.json', params={},
                                      json_data=body_for_request, headers=self._post_put_header)
        return response

    def create_file_token_request(self, args, entry_id):
        file_content = get_file_content(entry_id)
        response = self._http_request('POST', '/uploads.json', params=args, headers=self._upload_file_header,
                                      data=file_content)
        return response

    def update_issue_request(self, args):
        issue_id = args.pop('issue_id')
        params = assign_params(**args)
        response = self._http_request('PUT', f'/issues/{issue_id}.json', json_data={"issue": params}, headers=self._post_put_header,
                                      empty_valid_codes=[204], return_empty_response=True)
        return response

    def get_issues_list_request(self, project_id, status_id, offset_to_dict, limit_to_dict, args: dict[str, Any]):
        params = assign_params(project_id=project_id, status_id=status_id, offset=offset_to_dict, limit=limit_to_dict, **args)
        response = self._http_request('GET', '/issues.json', params=params, headers=self._get_header)
        return response

    def delete_issue_by_id_request(self, issue_id):
        response = self._http_request('DELETE', f'/issues/{issue_id}.json', headers=self._post_put_header,
                                      empty_valid_codes=[200, 204, 201], return_empty_response=True)
        return response

    def get_issue_by_id_request(self, issue_id, included_fields):
        response = self._http_request('GET', f'/issues/{issue_id}.json', params={"include": included_fields},
                                      headers=self._post_put_header)
        return response

    def add_issue_watcher_request(self, issue_id, watcher_id):
        args_to_add = {'user_id': watcher_id}
        response = self._http_request('POST', f'/issues/{issue_id}/watchers.json', params=args_to_add,
                                      headers=self._post_put_header, empty_valid_codes=[200, 204, 201], return_empty_response=True)
        return response

    def remove_issue_watcher_request(self, issue_id, watcher_id):
        response = self._http_request('DELETE', f'/issues/{issue_id}/watchers/{watcher_id}.json', headers=self._post_put_header,
                                      empty_valid_codes=[200, 204, 201], return_empty_response=True)
        return response

    def get_project_list_request(self, args: dict[str, Any]):
        response = self._http_request('GET', '/projects.json', params=args, headers=self._get_header)
        return response

    def get_custom_fields_request(self):
        response = self._http_request('GET', '/custom_fields.json', headers=self._get_header)
        return response

    def get_users_request(self, args: dict[str, Any]):
        response = self._http_request('GET', '/users.json', params=args, headers=self._get_header)
        return response


''' HELPER FUNCTIONS '''


def set_project_id_for_command(client: Client, project_id_from_command=None):
    if project_id_from_command:
        return project_id_from_command
    else:
        return client._project_id


def create_paging_header(page_size: int, page_number: int):
    return '#### Showing' + (f' {page_size}') + ' results' + (f' from page {page_number}') + ':\n'


def adjust_paging_to_request(args: dict[str, Any]):
    page_number = args.pop('page_number', None)
    page_size = args.pop('page_size', None)
    limit = args.pop('limit', None)
    offset_to_dict = None
    limit_to_dict = None
    if page_number or page_size:
        if page_size:
            page_size = int(page_size)
        else:
            page_size = 50
        if page_number:
            page_number = int(page_number)
        else:
            page_number = 1
        offset_to_dict = (page_number - 1) * page_size
        limit_to_dict = page_size
        page_number_for_header = page_number
    else:
        if limit:
            offset_to_dict = 0
            limit_to_dict = int(limit) if int(limit) <= 100 else 100
        else:
            offset_to_dict = 0
            limit_to_dict = 25
        page_number_for_header = 1
    return offset_to_dict, limit_to_dict, page_number_for_header


def map_header(header_string: str) -> str:
    header_mapping = {
        'id': 'ID',
        'author': 'Author',
        'project': 'Project',
        'status': 'Status',
        'priority': ' Priority',
        'login': 'Login',
        'admin': 'Admin',
        'firstname': 'First Name',
        'lastname': 'Last Name',
        'mail': 'Email',
        'created_on': 'Created On',
        'last_login_on': 'Last Login On',
        'estimated_hours': 'Estimated Hours',
        'start_date': 'Start Date',
        'custom_fields': 'Custom Fields',
        'description': 'Description',
        'subject': 'Subject',
    }
    return header_mapping.get(header_string, header_string)


def map_predefined_values_to_id(predefined_value, converter_dict, error_message):
    if predefined_value is not None:
        predefined_id = converter_dict.get(predefined_value)
        if predefined_id is not None:
            return predefined_id
        else:
            raise DemistoException(error_message)
    return None


def convert_args_to_request_format(args):  # put pop in line, remove exceptions
    tracker_id = args.pop('tracker_id', None)
    status_id = args.pop('status_id', None)
    priority_id = args.pop('priority_id', None)
    custom_fields = args.pop('custom_fields', None)
    watcher_user_ids = args.pop('watcher_user_ids', None)

    args['tracker_id'] = map_predefined_values_to_id(
        tracker_id, ISSUE_TRACKER_DICT, "Tracker_id invalid, please make sure you use only predefined values")
    args['status_id'] = map_predefined_values_to_id(
        status_id, ISSUE_STATUS_DICT, "Status_id invalid, please make sure you use only predefined values")
    args['priority_id'] = map_predefined_values_to_id(
        priority_id, ISSUE_PRIORITY_DICT, "Priority_id invalid, please make sure you use only predefined values")

    if custom_fields:
        custom_fields = custom_fields.split(',')
        try:
            args['custom_fields'] = [{'id': field.split(':')[0], 'value': field.split(':')[1]} for field in custom_fields]
        except Exception:
            raise DemistoException("Custom fields not in format, please follow the instructions")

    if watcher_user_ids:
        args['watcher_user_ids'] = argToList(watcher_user_ids)


def get_file_content(entry_id: str) -> bytes:
    """Returns the XSOAR file entry's content.

    Args:
        entry_id (str): The entry id inside XSOAR.

    Returns:
        Tuple[str, bytes]: A tuple, where the first value is the file name, and the second is the
        content of the file in bytes.
    """
    get_file_path_res = demisto.getFilePath(entry_id)
    file_path = get_file_path_res.pop('path')
    file_bytes: bytes = b''
    with open(file_path, 'rb') as f:
        file_bytes = f.read()
    return file_bytes


def handle_file_attachment(client: Client, args: Dict[str, Any]):
    """If a file was provided create a token and add to args

    Args:
        client (Client)
        args (Dict[str,Any]): Raw arguments dict from user

    Raises:
        DemistoException: response not in format or could not create a token
    """
    try:
        entry_id = args.pop('file_entry_id', None)
        if entry_id:
            file_name = args.pop('file_name', '')
            file_description = args.pop('file_description', '')
            content_type = args.pop('file_content_type', '')
            args_for_file = assign_params(file_name=file_name, content_type=content_type)
            token_response = client.create_file_token_request(args_for_file, entry_id)
            if 'upload' not in token_response:
                raise DemistoException(f"Could not upload file with entry id {entry_id}")
            uploads = assign_params(token=token_response['upload'].get('token', ''),
                                    content_type=content_type,
                                    filename=file_name,
                                    description=file_description)
            args['uploads'] = [uploads]
    except Exception as e:
        raise DemistoException("Could not create a token for your file- please try again."
                               f"With error {e}.")


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> None:
    message: str = ''
    try:
        if (get_issues_list_command(client, {'limit': '1'})):
            message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return return_results(message)


def create_issue_command(client: Client, args: dict[str, Any]) -> CommandResults:
    if not args.get('project_id', None) and not client._project_id:
        raise DemistoException('project_id field is missing in order to create an issue')
    '''Checks if a file needs to be added'''
    handle_file_attachment(client, args)
    try:
        convert_args_to_request_format(args)
        project_id = args.pop('project_id', client._project_id)
        response = client.create_issue_request(args, project_id)
        issue_response = response['issue']
        headers = ['id', 'project', 'tracker', 'status', 'priority', 'author', 'estimated_hours', 'created_on',
                   'subject', 'description', 'start_date', 'estimated_hours', 'custom_fields']
        issue_response['id'] = str(issue_response['id'])

        command_results = CommandResults(
            outputs_prefix='Redmine.Issue',
            outputs_key_field='id',
            outputs=issue_response,
            raw_response=issue_response,
            readable_output=tableToMarkdown('The issue you created:', issue_response, headers=headers,
                                            removeNull=True, is_auto_json_transform=True, headerTransform=map_header)
        )
        return command_results
    except Exception as e:
        if 'Error in API call [422]' in e.args[0] or 'Error in API call [404]' in e.args[0]:
            raise DemistoException("Invalid ID for one or more fields that request IDs \n"
                                   "Please make sure all IDs are correct")
        else:
            raise DemistoException(e.args[0])


def update_issue_command(client: Client, args: dict[str, Any]):
    issue_id = args.get('issue_id')
    handle_file_attachment(client, args)
    try:
        convert_args_to_request_format(args)
        client.update_issue_request(args)
        command_results = CommandResults(
            readable_output=f'Issue with id {issue_id} was successfully updated.')
        return (command_results)
    except Exception as e:
        if 'Error in API call [422]' in e.args[0] or 'Error in API call [404]' in e.args[0]:
            raise DemistoException("Invalid ID for one or more fields that request IDs "
                                   "Please make sure all IDs are correct")
        else:
            raise DemistoException(e.args[0])


def get_issues_list_command(client: Client, args: dict[str, Any]):
    try:
        offset_to_dict, limit_to_dict, page_number_for_header = adjust_paging_to_request(args)
        status_id = args.pop('status_id', None)
        if status_id:
            if status_id in ISSUE_STATUS_DICT:
                status_id = ISSUE_STATUS_DICT[status_id]
            else:
                raise DemistoException("Invalid status ID, please use only predefined values")
        project_id = args.pop('project_id', None) or client._project_id
        response = client.get_issues_list_request(project_id, status_id, offset_to_dict, limit_to_dict, args)
        issues_response = response['issues']
        page_header = create_paging_header(len(issues_response), page_number_for_header)

        '''Issue id is a number and tableToMarkdown can't transform it'''
        for issue in issues_response:
            issue['id'] = str(issue['id'])

        headers = ['id', 'tracker', 'status', 'priority', 'author', 'subject', 'description', 'start_date', 'due_date',
                   'done_ratio', 'is_private', 'estimated_hours', 'custom_fields', 'created_on', 'updated_on',
                   'closed_on', 'attachments', 'relations']
        command_results = CommandResults(
            outputs_prefix='Redmine.Issue',
            outputs_key_field='id',
            outputs=issues_response,
            raw_response=issues_response,
            readable_output=page_header + tableToMarkdown('Issues Results:',
                                                          issues_response,
                                                          headers=headers,
                                                          removeNull=True,
                                                          headerTransform=pascalToSpace,
                                                          is_auto_json_transform=True,
                                                          json_transform_mapping={
                                                              "tracker": JsonTransformer(keys=["name"]),
                                                              "status": JsonTransformer(keys=["name"]),
                                                              "priority": JsonTransformer(keys=["name"]),
                                                              "author": JsonTransformer(keys=["name"]),
                                                          }
                                                          )
        )
        return command_results
    except Exception as e:
        if 'Error in API call [422]' in e.args[0] or 'Error in API call [404]' in e.args[0]:
            raise DemistoException("Invalid ID for one or more fields that request IDs \n"
                                   "Please make sure all IDs are correct")
        else:
            raise DemistoException(e.args[0])


def get_issue_by_id_command(client: Client, args: dict[str, Any]):
    try:
        issue_id = args.pop('issue_id', None)
        include_possible_values = {'children', 'attachments', 'relations',
                                   'changesets', 'journals', 'watchers', 'allowed_statuses'}
        included_fields = args.pop('include', None)
        if included_fields and not all(field_value in include_possible_values for field_value in included_fields.split(',')):
            raise DemistoException("You can only include the following values: 'changesets', 'children', 'attachments', "
                                   "'journals', 'relations', 'watchers', 'allowed_statuses'}, separated with comma")
        response = client.get_issue_by_id_request(issue_id, included_fields)
        response_issue = response['issue']

        headers = ['id', 'project', 'tracker', 'status', 'priority', 'author', 'subject', 'description', 'start_date',
                   'due_date', 'done_ratio', 'is_private', 'estimated_hours', 'custom_fields', 'created_on', 'closed_on',
                   'attachments', 'watchers', 'children', 'relations', 'changesets', 'journals', 'allowed_statuses']
        response_issue['id'] = str(response_issue['id'])
        command_results = CommandResults(outputs_prefix='Redmine.Issue',
                                         outputs_key_field='id',
                                         outputs=response_issue,
                                         raw_response=response_issue,
                                         readable_output=tableToMarkdown('Issues List:', response_issue,
                                                                         headers=headers,
                                                                         removeNull=True,
                                                                         headerTransform=underscoreToCamelCase,
                                                                         is_auto_json_transform=True,
                                                                         json_transform_mapping={
                                                                             "tracker": JsonTransformer(keys=["name"]),
                                                                             "project": JsonTransformer(keys=["name"]),
                                                                             "status": JsonTransformer(keys=["name"]),
                                                                             "priority": JsonTransformer(keys=["name"]),
                                                                             "author": JsonTransformer(keys=["name"]),
                                                                             "custom_fields": JsonTransformer(keys=["name", "value"]),
                                                                             "watchers": JsonTransformer(keys=["name"]),
                                                                         }))
        return command_results
    except Exception as e:
        if 'Error in API call [422]' in e.args[0] or 'Error in API call [404]' in e.args[0]:
            raise DemistoException("Invalid ID for one or more fields that request IDs "
                                   "Please make sure all IDs are correct")
        else:
            raise DemistoException(e.args[0])


def delete_issue_by_id_command(client: Client, args: dict[str, Any]):
    issue_id = args.get('issue_id')
    try:
        client.delete_issue_by_id_request(issue_id)
        command_results = CommandResults(
            readable_output=f'Issue with id {issue_id} was deleted successfully.')
        return (command_results)
    except Exception as e:
        if 'Error in API call [422]' in e.args[0] or 'Error in API call [404]' in e.args[0]:
            raise DemistoException("Invalid ID for one or more fields that request IDs \n"
                                   "Please make sure all IDs are correct")
        else:
            raise DemistoException(e.args[0])


def add_issue_watcher_command(client: Client, args: dict[str, Any]):
    issue_id = args.get('issue_id')
    watcher_id = args.get('watcher_id')
    try:
        client.add_issue_watcher_request(issue_id, watcher_id)
        command_results = CommandResults(
            readable_output=f'Watcher with id {watcher_id} was added successfully to issue with id {issue_id}.')
        return (command_results)
    except Exception as e:
        if 'Error in API call [422]' in e.args[0] or 'Error in API call [404]' in e.args[0] or 'Error in API call [403]' in e.args[0]:
            raise DemistoException("Invalid ID for one or more fields that request IDs "
                                   "Please make sure all IDs are correct")
        else:
            raise DemistoException(e.args[0])


def remove_issue_watcher_command(client: Client, args: dict[str, Any]):
    try:
        issue_id = args.get('issue_id')
        watcher_id = args.get('watcher_id')
        client.remove_issue_watcher_request(issue_id, watcher_id)
        command_results = CommandResults(
            readable_output=f'Watcher with id {watcher_id} was removed successfully from issue with id {issue_id}.')
        return command_results
    except Exception as e:
        if 'Error in API call [422]' in e.args[0] or 'Error in API call [404]' in e.args[0]:
            raise DemistoException("Invalid ID for one or more fields that request IDs "
                                   "Please make sure all IDs are correct")
        else:
            raise DemistoException(e.args[0])


def get_project_list_command(client: Client, args: dict[str, Any]):
    try:
        INCLUDE_SET = {'trackers', 'issue_categories', 'enabled_modules', 'time_entry_activities', 'issue_custom_fields'}
        include_arg = args.get('include', None)
        if include_arg:
            included_values = include_arg.split(',')
            invalid_values = [value for value in included_values if value not in INCLUDE_SET]
            if invalid_values:
                raise DemistoException("The 'include' argument should only contain values from trackers/issue_categories/"
                                       "enabled_modules/time_entry_activities/issue_custom_fields, separated by commas. "
                                       f"These values are not in options {invalid_values}")
        response = client.get_project_list_request(args)
        projects_response = response['projects']
        headers = ['id', 'name', 'identifier', 'description', 'status', 'is_public', 'time_entry_activities', 'created_on',
                   'updated_on', 'default_value', 'visible', 'roles']
        for project in projects_response:
            project['id'] = str(project['id'])
        command_results = CommandResults(outputs_prefix='Redmine.Project',
                                         outputs_key_field='id',
                                         outputs=projects_response,
                                         raw_response=projects_response,
                                         readable_output=tableToMarkdown('Projects List:', projects_response,
                                                                         headers=headers,
                                                                         removeNull=True,
                                                                         headerTransform=underscoreToCamelCase,
                                                                         is_auto_json_transform=True),
                                         )
        return command_results
    except Exception as e:
        if 'Error in API call [422]' in e.args[0] or 'Error in API call [404]' in e.args[0]:
            raise DemistoException("Invalid ID for one or more fields that request IDs "
                                   "Please make sure all IDs are correct")
        else:
            raise DemistoException(e.args[0])


def get_custom_fields_command(client: Client, args):
    try:
        response = client.get_custom_fields_request()
        custom_fields_response = response['custom_fields']
        headers = ['id', 'name', 'customized_type', 'field_format', 'regexp', 'max_length', 'is_required', 'is_filter', 'searchable',
                   'trackers', 'issue_categories', 'enabled_modules', 'time_entry_activities', 'issue_custom_fields']
        for custom_field in custom_fields_response:
            custom_field['id'] = str(custom_field['id'])
        command_results = CommandResults(outputs_prefix='Redmine.CustomField',
                                         outputs_key_field='id',
                                         outputs=custom_fields_response,
                                         raw_response=custom_fields_response,
                                         readable_output=tableToMarkdown('Custom Fields List:', custom_fields_response,
                                                                         headers=headers,
                                                                         removeNull=True,
                                                                         headerTransform=underscoreToCamelCase,
                                                                         is_auto_json_transform=True
                                                                         )
                                         )
        return command_results
    except Exception as e:
        if 'Error in API call [422]' in e.args[0] or 'Error in API call [404]' in e.args[0]:
            raise DemistoException("Invalid ID for one or more fields that request IDs \n"
                                   "Please make sure all IDs are correct")
        else:
            raise DemistoException(e.args[0])


def get_users_command(client: Client, args: dict[str, Any]):
    try:
        status_string = args.get('status')
        if status_string:
            try:
                args['status'] = USER_STATUS_DICT[status_string]
            except Exception:
                raise DemistoException("Invalid status value- please use the predefined options only")
        response = client.get_users_request(args)['users']
        headers = ['id', 'login', 'admin', 'firstname', 'lastname', 'mail', 'created_on', 'last_login_on']
        for user in response:
            user['id'] = str(user['id'])
        command_results = CommandResults(outputs_prefix='Redmine.Users',
                                         outputs_key_field='id',
                                         outputs=response,
                                         raw_response=response,
                                         readable_output=tableToMarkdown('Users List:', response, headers=headers,
                                                                         removeNull=True, headerTransform=map_header,
                                                                         is_auto_json_transform=True))
        return command_results
    except Exception as e:
        if 'Error in API call [422]' in e.args[0] or 'Error in API call [404]' in e.args[0]:
            raise DemistoException("Invalid ID for one or more fields that request IDs "
                                   "Please make sure all IDs are correct")
        else:
            raise DemistoException(e.args[0])


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    base_url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    api_key = params.get('credentials', {}).get('password', '')
    project_id = params.get('project_id', None)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        commands = {'redmine-issue-create': create_issue_command,
                    'redmine-issue-update': update_issue_command,
                    'redmine-issue-show': get_issue_by_id_command,
                    'redmine-issue-delete': delete_issue_by_id_command,
                    'redmine-issue-watcher-add': add_issue_watcher_command,
                    'redmine-issue-watcher-remove': remove_issue_watcher_command,
                    'redmine-issue-list': get_issues_list_command,
                    'redmine-project-list': get_project_list_command,
                    'redmine-custom-field-list': get_custom_fields_command,
                    'redmine-user-id-list': get_users_command}

        client = Client(
            server_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            api_key=api_key,
            project_id=project_id)

        if command == 'test-module':
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
