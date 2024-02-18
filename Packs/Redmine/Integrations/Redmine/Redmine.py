import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

from typing import Any

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
POST_PUT_HEADER = {'Content-Type': 'application/json'}
GET_HEADER = {}
UPLOAD_FILE_HEADER = {'Content-Type' : 'application/octet-stream'}

''' CLIENT CLASS '''
class Client(BaseClient):
    def __init__(self, server_url, verify=True, proxy=False, headers=None, auth=None):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def create_issue_request(self, args):
        try :
            subject = args.pop('subject', None)
            uploads = args.pop('uploads', None)
            if subject:
                body_for_request = {'issue': {'subject': subject}}
            if uploads:
                body_for_request['issue']['uploads'] = uploads
            response = self._http_request('POST', '/issues.json', params=args,
                                        json_data=body_for_request, headers=POST_PUT_HEADER)
        except Exception as e:
            raise DemistoException(f'Could not create an issue with error: {e}')
        return response

    def create_file_token_request(self,args,file_address_arg):
        response = self._http_request('POST','/uploads.json', params=args, headers=UPLOAD_FILE_HEADER,
                                      json_data=file_address_arg)
        return response
    def update_issue_request(self,args):
        issue_id = args.pop('issue_id')
        response = self._http_request('PUT', f'/issues/{issue_id}.json', json_data={"issue":args}, headers=POST_PUT_HEADER)
        return response
    def get_issues_list_request(self, args: dict[str, Any]):
        response = self._http_request('GET', '/issues.json', params=args, headers=GET_HEADER)
        return response
    
    def delete_issue_by_id_request(self, issue_id):
        response = self._http_request('DELETE', f'/issues/{issue_id}.json', headers=POST_PUT_HEADER)
        return response
    
    def get_issue_by_id_request(self, args, issue_id):
        response = self._http_request('GET', f'/issues/{issue_id}.json', params=args, headers=POST_PUT_HEADER)
        return response
    
    def add_issue_watcher_request(self, issue_id, watcher_id):
        args_to_add = {'user_id': watcher_id}
        response = self._http_request('POST', f'/issues/{issue_id}/watchers.json',params=args_to_add, headers=POST_PUT_HEADER)
        return response
    
    def remove_issue_watcher_request(self, issue_id, watcher_id):
        response = self._http_request('DELETE', f'/issues/{issue_id}/watchers/{watcher_id}.json', headers=POST_PUT_HEADER)
        return response
    
    def get_project_list_request(self, args: dict[str, Any]):
        response = self._http_request('GET', '/projects.json', params=args, headers=GET_HEADER)
        return response
    
    def get_custom_fields_request(self):
        response = self._http_request('GET', '/custom_fields.json', headers=GET_HEADER)
        return response
    
    def get_users_request(self, args: dict[str,Any]):
        response = self._http_request('GET', 'users.json', params=args, headers=GET_HEADER)
        return response
''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> None:
    message: str = ''
    try:
        if (get_issues_list_command(client, {})):
            message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return return_results(message)


def create_issue_command(client: Client, args: dict[str, Any]) -> CommandResults:
    status_id = args.get('status_id') 
    priority_id = args.get('priority_id')
    subject = args.get('subject')
    project_id = args.get('project_id')

    if not status_id or not priority_id or not subject or not project_id:
        raise DemistoException('One or more required arguments not specified')
    
    entry_id = args.get('entry_id')
    file_name = args.get('file_name')
    file_description = args.get('file_description')
    if (entry_id): #to ask about file_name
        args_for_file = assign_params(file_name=file_name, file_description=file_description)
        response = client.create_file_token_request(args_for_file, {'entry_id':entry_id})
        if (response['upload']):
            args['uploads'] = response['upload']
            args['uploads']['file_name'] = file_name
            _ = args['uploads'].pop('id')
        else:
            raise DemistoException(f"Could not upload file with entry id {entry_id}")
    response = client.create_issue_request(args)

    headers = ['id', 'project id', 'tracker id', 'status id', 'priority id',
               'subject', 'description', 'estimated_hours', 'custom fields']

    return CommandResults(
        outputs_prefix='Redmine.Issue',
        outputs_key_field='id',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('The issue you created:', response, headers={},
                                        removeNull=True, headerTransform=pascalToSpace)
    )

def update_issue_command(client: Client, args: dict[str, Any]):
    #need to deal with watchers,customfields,attachments
    if args.get('issue_id'):
        watchers = args.pop('watcher_user_ids', None)
        custom_fields = args.pop('custom_fields', None)
        attachments = args.pop('attachments', None)
        return client.update_issue_request(args)
    else:
        raise DemistoException('Issue_id is missing- in order to update this issue')

def get_issues_list_command(client: Client, args: dict[str, Any]):
    return client.get_issues_list_request(args)

def get_issue_by_id_command(client: Client, args: dict[str, Any]):
    include_possible_values = {'children', 'attachments', 'relations', 'changesets', 'journals', 'watchers', 'allowed_statuses'}
    included_fields = args.get('include')
    issue_id = args.pop('issue_id', None)
    if issue_id:
        if included_fields and not all(field_value in include_possible_values for field_value in included_fields):
                raise DemistoException(f"You can only include the following values {include_possible_values}")        
        elif (included_fields):
            array_of_include_to_string = ','.join(included_fields)
            args['include'] = array_of_include_to_string
        response = client.get_issue_by_id_request(args, issue_id)
        headers = ['id', 'project', 'tracker', 'status', 'priority','author','subject','description','start_date',
            'due_date','done_ratio','is_private', 'estimated_hours', 'custom_fields', 'created_on', 'closed_on',
            'attachments', 'watchers', 'children', 'relations', 'changesets', 'journals', 'allowed_statuses']
        command_results = CommandResults(outputs_prefix='Redmine.Issue',
                                outputs_key_field='id',
                                outputs=response,
                                raw_response=response,
                                    readable_output=tableToMarkdown('Issues List:', response['issue'],
                                                                headers=headers,
                                                                removeNull=True, 
                                                                headerTransform=underscoreToCamelCase))
        print(command_results.readable_output)
        return command_results  
    else:
        raise DemistoException('Issue_id is missing- in order to get this issue')
    
def delete_issue_by_id_command(client: Client, args: dict[str, Any]):
    #if issue_id doesnt exist application crashes due to api 404
    issue_id = args.get('issue_id')
    if issue_id:
        response = client.delete_issue_by_id_request(issue_id)
        command_results = CommandResults(
            readable_output=f'Issue with id {issue_id} was deleted successfully.')
        print(command_results.readable_output)
        return (command_results)
    else:
        raise DemistoException('Issue_id is missing')
       
def add_issue_watcher_command(client: Client, args: dict[str, Any]):
    issue_id = args.get('issue_id')
    watcher_id = args.get('watcher_id')
    if issue_id:
        if watcher_id:
            response = client.add_issue_watcher_request(issue_id, watcher_id)
            command_results = CommandResults(
                readable_output=f'Watcher with id {watcher_id} was added successfully to issue with id {issue_id}.')
            print(command_results.readable_output)
            return (command_results)
        else:
            raise DemistoException('watcher_id is missing in order to add this watcher')
    else:
        raise DemistoException('Issue_id is missing in order to add a watcher to this issue')
       
def remove_issue_watcher_command(client: Client, args: dict[str, Any]):
    issue_id = args.get('issue_id')
    watcher_id = args.get('watcher_id')
    if issue_id:
        if watcher_id:
            response = client.remove_issue_watcher_request(issue_id, watcher_id)
            command_results = CommandResults(
                readable_output=f'Watcher with id {watcher_id} was removed successfully from issue with id {issue_id}.')
            print(command_results.readable_output)
            return (command_results)
        else:
            raise DemistoException('watcher_id is missing in order to remove watcher from this issue')
    else:
        raise DemistoException('Issue_id is missing in order to remove watcher from this issue')
    
def get_project_list_command(client: Client, args: dict[str, Any]):
    #sub field are as dictionary- ui not well
    response = client.get_project_list_request(args)
    headers = ['id', 'name', 'identifier', 'description', 'status','is_public','time_entry_activities','created_on','updated_on',
               'default_value','visible','roles']
    command_results = CommandResults(outputs_prefix='Redmine.Project',
                                    outputs_key_field='id',
                                    outputs=response,
                                    raw_response=response,
                                     readable_output=tableToMarkdown('Projects List:', response['projects'],
                                                                    headers=headers,
                                                                    removeNull=True, 
                                                                    headerTransform=underscoreToCamelCase))
    print(command_results.readable_output)
    return command_results  
        
def get_custom_fields_command(client: Client):
    #didnt put all fields here- i think it is not user visible
    response = client.get_custom_fields_request()
    headers = ['id', 'name', 'customized_type', 'field_format', 'regexp', 'max_length', 'is_required', 'is_filter', 'searchable',
               'trackers', 'issue_categories', 'enabled_modules', 'time_entry_activities', 'issue_custom_fields']
    command_results = CommandResults(outputs_prefix='Redmine.CustomField',
                                    outputs_key_field='id',
                                    outputs=response,
                                    raw_response=response,
                                     readable_output=tableToMarkdown('Projects List:', response['projects'],
                                                                    headers=headers,
                                                                    removeNull=True, 
                                                                    headerTransform=underscoreToCamelCase))
    print(command_results.readable_output)
    return command_results

def get_users_command(client: Client, args: dict[str, Any]):
    possible_values_for_status = {'1':'means Active', '2':'means Registered', '3':'means Locked'}
    status_for_request = args.get('status')
    if status_for_request and status_for_request not in possible_values_for_status.keys():
        raise DemistoException(f'Status value for get users request must be one of the following {possible_values_for_status}')
    response = client.get_users_request(args)
    headers = ['id', 'login', 'admin', 'firstname', 'lastname', 'mail', 'created_on', 'last_login_on']
    command_results = CommandResults(outputs_prefix='Redmine.Users',
                                    outputs_key_field='id',
                                    outputs=response,
                                    raw_response=response,
                                    readable_output=tableToMarkdown('Users List:', response['users'], headers=headers,
                                                                    removeNull=True, 
                                                                    headerTransform=underscoreToCamelCase))
    print(command_results.readable_output)
    return command_results

def main() -> None:
    params = demisto.params()
    args = demisto.args()
    url = params.get('url')
    # base_url = urljoin(demisto.params()['url'], '/api/v1')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = params.get('proxy', False)

    api_key = params['credentials']['password']

    # command = demisto.command()
    command = 'test-module'
    demisto.debug(f'Command being called is {command}')
    POST_PUT_HEADER['X-Redmine-API-Key'] = api_key
    UPLOAD_FILE_HEADER['X-Redmine-API-Key'] = api_key
    GET_HEADER['X-Redmine-API-Key'] = api_key
    
    try:
        commands = {'redmine-issue-create': create_issue_command,
                    'redmine-issue-update': update_issue_command,
                    'redmine-issue-list': get_issues_list_command,
                    'redmine-issue-show': get_issue_by_id_command,
                    'redmine-issue-delete': delete_issue_by_id_command,
                    'redmine-issue-watcher-add': add_issue_watcher_command,
                    'redmine-project-list': get_project_list_command,
                    'redmine-custom-field-list': get_custom_fields_command,
                    'redmine-user-id-list': get_users_command}
        
        client = Client(
            url,
            verify_certificate,
            proxy,
            auth=("", api_key))
        #response = get_issues_list_command(client,{'limit':'10','offset':'9'})
        # response = create_issue_command(client,{'project_id':'1','status_id':'1', 'priority_id':'1', 'subject':'wdq', 'entry_id':'/Users/sdepaz/Desktop/all/example.png'})
        #return_results(get_users_command(client, {'status':'1'}))
        # return_results(get_users_command(client, {'name':'Redmine'}))
        # return_results(get_custom_fields_command(client))
        # return_results(get_project_list_command(client,{'include':'time_entry_activities'}))
        # return_results(remove_issue_watcher_command(client,{'issue_id':'44','watcher_id':'1'}))
        # return_results(add_issue_watcher_command(client,{'issue_id':'44','watcher_id':'1'}))
        # return_results(delete_issue_by_id_command(client, {'issue_id':'41'}))
        return_results(get_issue_by_id_command(client, {'issue_id' : '44', 'include':['watchers', 'attachments']}))
        # response = update_issue_command(client, {'issue_id' : '44', 'subject':'changeFromCode','tracker_id':'1'})
        if command == 'test-module':
            test_module(client)
        # elif command in commands:
        #     return_results(commands[command](client,args))
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
