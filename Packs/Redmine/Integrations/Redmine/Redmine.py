import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

from typing import Any

''' CONSTANTS '''
POST_PUT_HEADER = {'Content-Type': 'application/json'}

GET_HEADER = {}

UPLOAD_FILE_HEADER = {'Content-Type': 'application/octet-stream'}

USER_STATUS_DICT = {
    'Active' : '1',
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
    def __init__(self, server_url, verify=True, proxy=False, headers=None, auth=None):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def create_issue_request(self, args):
        try:
            uploads = args.pop('uploads', None)
            body_for_request = {'issue': args}
            if uploads:
                body_for_request['issue']['uploads'] = uploads
            response = self._http_request('POST', '/issues.json', params=args,
                                          json_data=body_for_request, headers=POST_PUT_HEADER)
        except Exception as e:
            raise DemistoException(f'Could not create an issue with error: {e}')
        return response

    def create_file_token_request(self, args, entry_id):
        file_content = get_file_name_and_content(entry_id)
        response = self._http_request('POST', '/uploads.json', params=args, headers=UPLOAD_FILE_HEADER,
                                      data=file_content)
        return response

    def update_issue_request(self, args):
        issue_id = args.pop('issue_id')
        file_token = args.pop('token', None)
        file_name = args.pop('file_name', '')
        description = args.pop('description', '')
        content_type = args.pop('content_type', '')
        if file_token:
            args['uploads'] = [{'token': file_token, 'filename': file_name,
                                'description': description, 'content_type': content_type}]
        response = self._http_request('PUT', f'/issues/{issue_id}.json', json_data={"issue": args}, headers=POST_PUT_HEADER,
                                      empty_valid_codes=[204], return_empty_response=True)
        return response

    def get_issues_list_request(self, args: dict[str, Any]):
        response = self._http_request('GET', '/issues.json', params=args, headers=GET_HEADER)
        return response

    def delete_issue_by_id_request(self, issue_id):
        response = self._http_request('DELETE', f'/issues/{issue_id}.json', headers=POST_PUT_HEADER,
                                      empty_valid_codes=[200,204,201],return_empty_response=True)
        return response

    def get_issue_by_id_request(self, args, issue_id):
        response = self._http_request('GET', f'/issues/{issue_id}.json', params=args, headers=POST_PUT_HEADER)
        return response

    def add_issue_watcher_request(self, issue_id, watcher_id):
        args_to_add = {'user_id': watcher_id}
        response = self._http_request('POST', f'/issues/{issue_id}/watchers.json', params=args_to_add, headers=POST_PUT_HEADER,
                                      empty_valid_codes=[200,204,201], return_empty_response=True)
        return response

    def remove_issue_watcher_request(self, issue_id, watcher_id):
        response = self._http_request('DELETE', f'/issues/{issue_id}/watchers/{watcher_id}.json', headers=POST_PUT_HEADER,
                                      empty_valid_codes=[200,204,201], return_empty_response=True)
        return response

    def get_project_list_request(self, args: dict[str, Any]):
        response = self._http_request('GET', '/projects.json', params=args, headers=GET_HEADER)
        return response

    def get_custom_fields_request(self):
        response = self._http_request('GET', '/custom_fields.json', headers=GET_HEADER)
        return response

    def get_users_request(self, args: dict[str, Any]):
        response = self._http_request('GET', 'users.json', params=args, headers=GET_HEADER)
        return response


''' HELPER FUNCTIONS '''


def create_paging_header(page_size: int, page_number: int):
    return '#### Showing' + (f' {page_size}') + ' results' + (f' from page {page_number}') + ':\n'


def adjust_paging_to_request(args: dict[str, Any]):
    page_number = args.pop('page_number', None)
    page_size = args.pop('page_size', None)
    limit = args.pop('limit', None)
    offset_to_dict = None
    limit_to_dict = None
    page_header = None
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
        page_header = create_paging_header(page_size, page_number)
    else:
        if limit:
            offset_to_dict = 0
            limit_to_dict = int(limit) if int(limit) <= 100 else 100
        else:
            offset_to_dict = 0
            limit_to_dict = 25
        page_header = create_paging_header(limit_to_dict, 1)
    return offset_to_dict, limit_to_dict, page_header


def map_header(header_string: str) -> str:
    header_mapping = {
        'id': 'ID',
        'login': 'Login',
        'admin': 'Admin',
        'firstname': 'First Name',
        'lastname': 'Last Name',
        'mail': 'Email',
        'created_on': 'Created On',
        'last_login_on': 'Last Login On'
    }
    return header_mapping.get(header_string, header_string)

def convert_args_to_request_format(args):
    tracker_id = args.pop('tracker_id', None)
    status_id = args.pop('status_id', None)
    priority_id = args.pop('priority_id', None)
    custom_fields = args.pop('custom_fields', None)
    watcher_user_ids = args.pop('custom_fields', None)
    if tracker_id:
        args['tracker_id'] = ISSUE_TRACKER_DICT[tracker_id]
    if status_id:
        args['status_id'] = ISSUE_STATUS_DICT[status_id]
    if priority_id:
        args['priority_id'] = ISSUE_PRIORITY_DICT[priority_id]
    if custom_fields:
        custom_fields = custom_fields.split(',')
        args['custom_fields'] = [dict(zip(('id', 'value'), field.split(':'))) for field in custom_fields]
    if watcher_user_ids:
        args['watcher_user_ids'] = [watcher_user_ids]


def get_file_name_and_content(entry_id: str) -> bytes:
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
    # is it redundant
    print(args)
    required_fields = ['status_id', 'priority_id', 'subject', 'project_id']
    missing_fields = [field for field in required_fields if not args.get(field)]
    if missing_fields:
        raise DemistoException('One or more required arguments not specified: {}'.format(', '.join(missing_fields)))

    '''Checks if a file needs to be added'''
    entry_id = args.pop('file_entry_id', None)
    if entry_id:
        file_name = args.pop('file_name', '')
        file_description = args.pop('file_description', '')
        content_type = args.pop('file_content_type', '')
        args_for_file = assign_params(file_name=file_name, content_type=content_type)
        response = client.create_file_token_request(args_for_file, entry_id)

        if 'upload' not in response:
            raise DemistoException(f"Could not upload file with entry id {entry_id}")

        uploads = assign_params(token=response['upload'].get('token', ''),
                                content_type=content_type,
                                filename=file_name,
                                description=file_description)
        args['uploads'] = [uploads]
    convert_args_to_request_format(args)

    response = client.create_issue_request(args)['issue']

    headers = ['id', 'project', 'tracker', 'status', 'priority', 'author', 'estimated_hours', 'created_on',
               'subject', 'description', 'start_date', 'estimated_hours', 'custom fields']
    response['id'] = str(response['id'])

    command_results = CommandResults(
        outputs_prefix='Redmine.Issue',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('The issue you created:', response, headers=headers,
                                        removeNull=True, is_auto_json_transform=True, headerTransform=pascalToSpace)
    )
    return command_results
        
def update_issue_command(client: Client, args: dict[str, Any]):
    # need to deal with watchers,customfields,attachments
    issue_id = args.get('issue_id')
    if issue_id:
        entry_id = args.pop('file_entry_id', None)
        if (entry_id):
            file_name = args.pop('file_name', '')
            file_token = client.create_file_token_request(assign_params(file_name=file_name), entry_id)['upload']['token']
            args = assign_params(token=file_token, **args)
        convert_args_to_request_format(args)
        client.update_issue_request(args)
        command_results = CommandResults(
            readable_output=f'Issue with id {issue_id} was successfully updated.')
        return (command_results)
    else:
        raise DemistoException('Issue_id is missing in order to update this issue')


def get_issues_list_command(client: Client, args: dict[str, Any]):
    offset_to_dict, limit_to_dict, page_header = adjust_paging_to_request(args)
    status_id = args.pop('status_id', None)
    if status_id:
        status_id = ISSUE_STATUS_DICT[status_id]
    args = assign_params(status_id=status_id, offset=offset_to_dict, limit=limit_to_dict, **args)
    response = client.get_issues_list_request(args)['issues']
    if not page_header:
        page_header = create_paging_header(len(response), 1)
    for issue in response:
        issue['id'] = str(issue['id'])
    headers = ['id', 'tracker', 'status', 'priority', 'author', 'subject', 'description', 'start_date', 'due_date', 'done_ratio',
               'is_private', 'estimated_hours', 'custom_fields', 'created_on', 'updated_on',
               'closed_on', 'attachments', 'relations']
    command_results = CommandResults(
        outputs_prefix='Redmine.Issue',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=page_header + tableToMarkdown('Issues Results:',
                                                      response,
                                                      headers=headers,
                                                      removeNull=True,
                                                      headerTransform=pascalToSpace,
                                                      is_auto_json_transform=True))
    return command_results


def get_issue_by_id_command(client: Client, args: dict[str, Any]):
    issue_id = args.pop('issue_id', None)
    if issue_id:
        include_possible_values = {'children', 'attachments', 'relations',
                                   'changesets', 'journals', 'watchers', 'allowed_statuses'}
        included_fields = args.get('include')
        if included_fields and not all(field_value in include_possible_values for field_value in included_fields.split(',')):
            raise DemistoException(f"You can only include the following values {include_possible_values}")
        response = client.get_issue_by_id_request(args, issue_id)['issue']
        headers = ['id', 'project', 'tracker', 'status', 'priority', 'author', 'subject', 'description', 'start_date',
                   'due_date', 'done_ratio', 'is_private', 'estimated_hours', 'custom_fields', 'created_on', 'closed_on',
                   'attachments', 'watchers', 'children', 'relations', 'changesets', 'journals', 'allowed_statuses']
        response['id'] = str(response['id'])
        command_results = CommandResults(outputs_prefix='Redmine.Issue',
                                         outputs_key_field='id',
                                         outputs=response,
                                         raw_response=response,
                                         readable_output=tableToMarkdown('Issues List:', response,
                                                                         headers=headers,
                                                                         removeNull=True,
                                                                         headerTransform=underscoreToCamelCase,
                                                                         is_auto_json_transform=True))
        return command_results
    else:
        raise DemistoException('Issue_id is missing in order to get this issue')


def delete_issue_by_id_command(client: Client, args: dict[str, Any]):
    # if issue_id doesnt exist application crashes due to api 404
    issue_id = args.get('issue_id')
    if issue_id:
        client.delete_issue_by_id_request(issue_id)
        command_results = CommandResults(
            readable_output=f'Issue with id {issue_id} was deleted successfully.')
        return (command_results)
    else:
        raise DemistoException('Issue_id is missing in order to delete')


def add_issue_watcher_command(client: Client, args: dict[str, Any]):
    # is it redandent?
    issue_id = args.get('issue_id')
    watcher_id = args.get('watcher_id')
    if issue_id:
        if watcher_id:
            client.add_issue_watcher_request(issue_id, watcher_id)
            command_results = CommandResults(
                readable_output=f'Watcher with id {watcher_id} was added successfully to issue with id {issue_id}.')
            return (command_results)
        else:
            raise DemistoException('watcher_id is missing in order to add this watcher to the issue')
    else:
        raise DemistoException('Issue_id is missing in order to add a watcher to this issue')


def remove_issue_watcher_command(client: Client, args: dict[str, Any]):
    # is it redandent?
    issue_id = args.get('issue_id')
    watcher_id = args.get('watcher_id')
    if issue_id:
        if watcher_id:
            client.remove_issue_watcher_request(issue_id, watcher_id)
            command_results = CommandResults(
                readable_output=f'Watcher with id {watcher_id} was removed successfully from issue with id {issue_id}.')
            return command_results
        else:
            raise DemistoException('watcher_id is missing in order to remove watcher from this issue')
    else:
        raise DemistoException('Issue_id is missing in order to remove watcher from this issue')


def get_project_list_command(client: Client, args: dict[str, Any]):
    INCLUDE_SET = {'trackers', 'issue_categories', 'enabled_modules', 'time_entry_activities','issue_custom_fields'}
    include_arg = args['include']
    if include_arg:
        included_values = include_arg.split(',')
        invalid_values = [value for value in included_values if value not in INCLUDE_SET]
        if invalid_values:
            raise DemistoException("The 'include' argument should only contain values from trackers/issue_categories/"\
                                   "enabled_modules/time_entry_activities/issue_custom_fields, separated by commas. "\
                                f"These values are not in options {invalid_values}")
    response = client.get_project_list_request(args)['projects']
    headers = ['id', 'name', 'identifier', 'description', 'status', 'is_public', 'time_entry_activities', 'created_on',
               'updated_on', 'default_value', 'visible', 'roles']
    for project in response:
        project['id'] = str(project['id'])
    command_results = CommandResults(outputs_prefix='Redmine.Project',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response,
                                     readable_output=tableToMarkdown('Projects List:', response,
                                                                     headers=headers,
                                                                     removeNull=True,
                                                                     headerTransform=underscoreToCamelCase,
                                                                     is_auto_json_transform=True),
                                     )
    return command_results


def get_custom_fields_command(client: Client, args):
    response = client.get_custom_fields_request()['custom_fields']
    headers = ['id', 'name', 'customized_type', 'field_format', 'regexp', 'max_length', 'is_required', 'is_filter', 'searchable',
               'trackers', 'issue_categories', 'enabled_modules', 'time_entry_activities', 'issue_custom_fields']
    for custom in response:
        custom['id'] = str(custom['id'])
    command_results = CommandResults(outputs_prefix='Redmine.CustomField',
                                     outputs_key_field='id',
                                     outputs=response,
                                     raw_response=response,
                                     readable_output=tableToMarkdown('Custom Fields List:', response,
                                                                     headers=headers,
                                                                     removeNull=True,
                                                                     headerTransform=underscoreToCamelCase,
                                                                     is_auto_json_transform=True
                                                                     )
                                     )
    return command_results


def get_users_command(client: Client, args: dict[str, Any]):
    status_string = args.get('status')
    if status_string:
        args['status'] = USER_STATUS_DICT[status_string]
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


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    base_url = params.get('url')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = params.get('proxy', False)

    api_key = params.get('credentials', {}).get('password', '')

    command = demisto.command()

    POST_PUT_HEADER['X-Redmine-API-Key'] = api_key
    UPLOAD_FILE_HEADER['X-Redmine-API-Key'] = api_key
    GET_HEADER['X-Redmine-API-Key'] = api_key

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
            base_url,
            verify_certificate,
            proxy,
            auth=("", api_key))
        if command == 'test-module':
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, args))
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
