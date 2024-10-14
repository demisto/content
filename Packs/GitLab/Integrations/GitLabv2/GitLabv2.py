import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from xmlrpc.client import Boolean
from CommonServerUserPython import *
from typing import Any
import urllib.parse
import re

PIPELINE_FIELDS_TO_EXTRACT = {'id', 'project_id', 'status', 'ref', 'sha', 'created_at', 'updated_at', 'started_at',
                              'finished_at', 'duration', 'web_url', 'user'}

PIPELINE_SCHEDULE_FIELDS_TO_EXTRACT = {'id', 'description', 'ref', 'next_run_at', 'active', 'created_at', 'updated_at',
                                       'last_pipeline'}

JOB_FIELDS_TO_EXTRACT = {'created_at', 'started_at', 'finished_at', 'duration', 'id', 'name', 'pipeline', 'ref',
                         'stage', 'web_url', 'status'}

'''--------------------- CLIENT CLASS --------------------'''


class Client(BaseClient):
    def __init__(self, project_id, base_url, verify, proxy, headers, trigger_token=None):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)
        self.project_id = project_id
        self.trigger_token = trigger_token

    def group_projects_list_request(self, params: dict | None, group_id: str | None) -> dict:
        headers = self._headers
        suffix = f'/groups/{group_id}/projects'
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202])
        return response

    def get_project_list_request(self, params: dict | None) -> list:
        headers = self._headers
        suffix = '/projects'
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202])
        return response

    def issue_list_request(self, params: dict | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/issues'
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202])
        return response

    def commit_list_request(self, params: dict | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/repository/commits'
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202], resp_type='json')
        return response

    def get_raw_file_request(self, file_path: str, ref: str) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/repository/files/{file_path}/raw'
        params = {'ref': ref}
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202], resp_type='text')
        return response

    def branch_list_request(self, params: dict | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/repository/branches'
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202], resp_type='json')
        return response

    def group_list_request(self, params: dict | None) -> dict:
        headers = self._headers
        suffix = '/groups'
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202], resp_type='json')
        return response

    def issue_note_list_request(self, params: dict | None, issue_iid: str | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/issues/{issue_iid}/notes'
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202])
        return response

    def merge_request_list_request(self, params: dict | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/merge_requests'
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202], resp_type='json')
        return response

    def merge_request_note_list_request(self, params: dict | None, merge_request_iid: str | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/merge_requests/{merge_request_iid}/notes'
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202])
        return response

    def group_member_list_request(self, group_id: str | None) -> dict:
        headers = self._headers
        suffix = f'/groups/{group_id}/members'
        response = self._http_request('GET', suffix, headers=headers, ok_codes=[200, 202])
        return response

    def codes_search_request(self, params: dict | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/search'
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202])
        return response

    def project_user_list_request(self, params: dict | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/users'
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202])
        return response

    def create_issue_request(self, labels: str, title: str, description: str) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/issues'
        params = assign_params(
            labels=labels,
            title=title,
            description=description
        )
        response = self._http_request('POST', suffix, headers=headers, params=params, ok_codes=[201])
        return response

    def create_branch_request(self, branch: str, ref: str) -> dict:
        params = assign_params(branch=branch, ref=ref)
        headers = self._headers
        suffix = f'/projects/{self.project_id}/repository/branches'
        response = self._http_request('POST', suffix, params=params, headers=headers)
        return response

    def branch_delete_request(self, branch: str) -> dict:
        headers = self._headers
        response = self._http_request('DELETE', f'projects/{self.project_id}/repository/branches/{branch}', headers=headers,
                                      resp_type='text', ok_codes=[200, 202, 204])
        return response

    def delete_merged_branches_request(self) -> dict:
        headers = self._headers
        response = self._http_request('DELETE', f'/projects/{self.project_id}/repository/merged_branches', headers=headers,
                                      ok_codes=[200, 202, 204])
        return response

    def version_get_request(self) -> dict:
        headers = self._headers
        suffix = '/version'
        response = self._http_request('GET', suffix, headers=headers, ok_codes=[200, 202])
        return response

    def issue_update_request(self, issue_id: str | Any, params: dict) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/issues/{issue_id}'
        response = self._http_request('PUT', suffix, headers=headers, params=params, ok_codes=[200, 202])
        return response

    def file_get_request(self, file_path: str, ref: str) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/repository/files/{file_path}'
        params = {'ref': ref}
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202])
        return response

    def file_create_request(self, file_path: str | None, branch: str | None, commit_msg: str,
                            author_email: str, author_name: str | None,
                            content: str | None, execute_filemode: str | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/repository/files/{file_path}'
        params = assign_params(author_email=author_email, author_name=author_name, execute_filemode=execute_filemode)
        body = assign_params(branch=branch, commit_message=commit_msg, content=content)
        response = self._http_request('POST', suffix, headers=headers, data=body, params=params, ok_codes=[201])
        return response

    def commit_single_request(self, commit_id: str) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/repository/commits/{commit_id}'
        response = self._http_request('GET', suffix, headers=headers, ok_codes=[200, 202], resp_type='json')
        return response

    def branch_single_request(self, branch_name: str) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/repository/branches/{branch_name}'
        response = self._http_request('GET', suffix, headers=headers, ok_codes=[200, 202], resp_type='json')
        return response

    def file_update_request(self, file_path: str, branch: str | None, start_branch: str | None, encoding: str | None,
                            author_email: str | None, author_name: str | None, commit_message: str | None,
                            last_commit_id: str | None, execute_filemode: str | None, content: str | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/repository/files/{file_path}'
        params = assign_params(start_branch=start_branch, encoding=encoding,
                               author_email=author_email, author_name=author_name,
                               last_commit_id=last_commit_id, execute_filemode=execute_filemode)
        body = assign_params(branch=branch, commit_message=commit_message, content=content)
        response = self._http_request('PUT', suffix, headers=headers, data=body, params=params, ok_codes=[200, 202])
        return response

    def file_delete_request(self, file_path: str, branch: str, commit_message: str) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/repository/files/{file_path}'
        params = assign_params(branch=branch, commit_message=commit_message)
        response = self._http_request('DELETE', suffix, headers=headers, params=params, ok_codes=[200, 202, 204],
                                      resp_type='text')

        return response

    def issue_note_create_request(self, issue_iid_: str, body_: str | Any, confidential_: str | Any) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/issues/{issue_iid_}/notes'
        params = assign_params(confidential=confidential_)
        data = assign_params(body=body_)
        response = self._http_request('POST', suffix, headers=headers, params=params, json_data=data, ok_codes=[201])
        return response

    def issue_note_delete_request(self, issue_iid: int | None, note_id: int | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/issues/{issue_iid}/notes/{note_id}'
        response = self._http_request('DELETE', suffix, headers=headers, ok_codes=[200, 202, 204], resp_type='text')
        return response

    def issue_note_update_request(self, issue_iid: int | None, note_id: int | None, body: str | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/issues/{issue_iid}/notes/{note_id}'
        data = assign_params(body=body)
        response = self._http_request('PUT', suffix, headers=headers, json_data=data, ok_codes=[200, 202])
        return response

    def merge_request_create_request(self, source_branch: str | None, target_branch: str | None,
                                     title: str | None, assignee_ids: str | None, reviewer_ids: str | None,
                                     description: str | None, target_project_id: str | None, labels: str | None,
                                     milestone_id: str | None, remove_source_branch: str | None,
                                     allow_collaboration: str | None, allow_maintainer_to_push: str | None,
                                     approvals_before_merge: str | None, squash: str | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/merge_requests'
        params = assign_params(assignee_ids=assignee_ids, reviewer_ids=reviewer_ids,
                               description=description,
                               target_project_id=target_project_id,
                               labels=labels,
                               milestone_id=milestone_id,
                               remove_source_branch=remove_source_branch,
                               allow_collaboration=allow_collaboration,
                               allow_maintainer_to_push=allow_maintainer_to_push,
                               approvals_before_merge=approvals_before_merge,
                               squash=squash)
        data = assign_params(source_branch=source_branch, target_branch=target_branch, title=title)
        response = self._http_request('POST', suffix, headers=headers, json_data=data, params=params, ok_codes=[201])
        return response

    def merge_request_update_request(self, merge_request_id: str | None,
                                     target_branch: str | None, title: str | None, assignee_ids: str | None,
                                     reviewer_ids: str | None, description: str | None, target_project_id: str | None,
                                     add_labels: str | None, remove_labels: str | None, milestone_id: str | None,
                                     state_event: str | None, remove_source_branch: str | None,
                                     allow_collaboration: str | None, allow_maintainer_to_push: str | None,
                                     approvals_before_merge: str | None, discussion_locked: str | None,
                                     squash: str | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/merge_requests/{merge_request_id}'
        params = assign_params(assignee_ids=assignee_ids, reviewer_ids=reviewer_ids,
                               description=description,
                               target_project_id=target_project_id,
                               add_labels=add_labels,
                               remove_labels=remove_labels,
                               milestone_id=milestone_id, state_event=state_event,
                               remove_source_branch=remove_source_branch,
                               allow_collaboration=allow_collaboration,
                               allow_maintainer_to_push=allow_maintainer_to_push,
                               approvals_before_merge=approvals_before_merge,
                               squash=squash, discussion_locked=discussion_locked)
        data = assign_params(target_branch=target_branch, title=title)
        response = self._http_request('PUT', suffix, headers=headers, json_data=data, params=params, ok_codes=[200, 202])
        return response

    def merge_request_note_create_request(self, merge_request_iid: str | Any, body: str | Any) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/merge_requests/{merge_request_iid}/notes'
        data = assign_params(body=body)
        response = self._http_request('POST', suffix, headers=headers, json_data=data, ok_codes=[201])
        return response

    def merge_request_note_update_request(self, merge_request_iid: str | Any, note_id: str | Any, body: str | Any) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/merge_requests/{merge_request_iid}/notes/{note_id}'
        data = assign_params(body=body)
        response = self._http_request('PUT', suffix, headers=headers, json_data=data, ok_codes=[200, 202])
        return response

    def merge_request_note_delete_request(self, merge_request_iid: str | Any, note_id: str | Any) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/merge_requests/{merge_request_iid}/notes/{note_id}'
        response = self._http_request('DELETE', suffix, headers=headers, ok_codes=[200, 202, 204], resp_type='text')
        return response

    def get_pipeline_request(self, project_id: str, pipeline_id: Optional[str], ref: Optional[str],
                             status: Optional[str]):
        headers = self._headers
        base_suffix = f'projects/{project_id}/pipelines'
        final_suffix = f'{base_suffix}/{pipeline_id}' if pipeline_id else base_suffix
        return self._http_request(
            'get',
            final_suffix,
            headers=headers,
            params=assign_params(ref=ref, status=status),
        )

    def get_pipeline_schedules_request(self, project_id: str, pipeline_schedule_id: Optional[str]):
        headers = self._headers
        base_suffix = f'projects/{project_id}/pipeline_schedules'
        final_suffix = f'{base_suffix}/{pipeline_schedule_id}' if pipeline_schedule_id else base_suffix
        return self._http_request(
            'get',
            final_suffix,
            headers=headers
        )

    def get_pipeline_job_request(self, project_id: str, pipeline_id: str):
        headers = self._headers
        suffix = f'projects/{project_id}/pipelines/{pipeline_id}/jobs'
        return self._http_request('get', suffix, headers=headers)

    def get_job_artifact_request(self, project_id: str, job_id: str, artifact_path_suffix: str):
        headers = self._headers
        suffix = f'projects/{project_id}/jobs/{job_id}/artifacts/{artifact_path_suffix}'
        return self._http_request('get', suffix, headers=headers, resp_type='text')

    def gitlab_trigger_pipeline(self, project_id: str, data: dict) -> dict:
        """Triggers a pipeline on GitLab.

        Args:
            project_id: Project ID on which to run the pipeline.
            data: The request body in JSON format.

        Returns:
            dict: The response in JSON format.
        """
        suffix = f'projects/{project_id}/trigger/pipeline'
        return self._http_request('POST', suffix, data=data)

    def gitlab_cancel_pipeline(self, project_id: str, pipeline_id: str) -> dict:
        """Cancel a pipeline on GitLab.

        Args:
            project_id: Project ID on which to cancel the pipeline.
            pipeline_id: Pipeline ID to cancel.

        Returns:
            dict: The response in JSON format.
        """
        suffix = f'/projects/{project_id}/pipelines/{pipeline_id}/cancel'
        return self._http_request('POST', suffix)


''' HELPER FUNCTIONS '''


def encode_file_path_if_needed(file_path: str) -> str:
    """Encode the file path if not already encoded.

    Args:
        file_path (str): The file path, can be URL encoded or not.

    Returns:
        str: Return the file path as is if already URL encoded, else, returns the encoding it.
    """
    file_path_prefix = './' if file_path.startswith('./') else ''
    # If starts with ./, then we don't want to encode the suffix, only the rest
    file_path_to_encode = file_path[2:] if file_path_prefix else file_path
    encoded_file_path = ''

    # To decode file_path_to_encode
    decoded_file_path = urllib.parse.unquote(file_path_to_encode)

    if decoded_file_path == file_path_to_encode:
        # If they are equal, that means file_path_to_encode is not encoded,
        # since we tried to decode it, and we got the same value
        # We can go ahead and encode it
        encoded_file_path = urllib.parse.quote(file_path_to_encode, safe='')
    else:
        # file_path_to_encode is already encoded, no need to encode it
        encoded_file_path = file_path_to_encode
    return f"{file_path_prefix}{encoded_file_path}"


def check_args_for_update(args: dict, optional_params: list) -> dict:
    '''
    This function checks that at least one argument from optional params is in args.
    input: optional params, args from user.
    output: if there isn't at least one argument then throw an exception.
            otherwise- dict of params for update and True boolean argument.
    '''
    params, args_valid = {}, False
    for optional_param in optional_params:
        if args.get(optional_param):
            params[optional_param] = args.get(optional_param)
            args_valid = True
    if not args_valid:
        raise DemistoException('At least one of arguments is required for the'
                               ' request to be successful\n')
    return params


def validate_pagination_values(limit: int, page_number: int) -> tuple[int, int, int]:
    if limit < 0 or page_number < 0:
        raise DemistoException('limit and page arguments must be positive')
    per_page = limit if limit < 100 else 100
    return limit, per_page, page_number


def response_according_pagination(client_function: Any, limit: int, page_number: int,
                                  params: dict, suffix_id: str | None):
    '''
    This function gets results according to the pagination values.
    input: 1. parameters for the client function
           2. suffix_id- if the suffix contain id(issue id for example) suffix_id would contain it,
            otherwise None.
           3. name of the client function.
    output: list(representing the pages) of list of raw dictionary results.
    '''
    limit, per_page, page_number = validate_pagination_values(limit, page_number)
    params.update({'per_page': per_page, 'page': page_number})
    items_count_total = 0
    response: list[dict[str, Any]] = []
    while items_count_total < limit:
        response_temp = client_function(params, suffix_id) if suffix_id else client_function(params)
        if not response_temp:
            break
        response.extend(response_temp)
        items_count_total += len(response_temp)
        params['per_page'] = 50 if (limit - items_count_total >= 50) else limit - items_count_total
        params['page'] = params['page'] + 1
    return response


def partial_response_fields(object_name: str):
    '''
    This function returns the fields for context data after filtering them. If a wanted field
    is inside a dict it the name of the dict would be his data, otherwise the data is empty,
    input: name of object
    returns: wanted fields.
    '''
    if object_name == 'Branch':
        return {
            'name': None,
            'commit': ['id', 'title', 'short_id', 'committed_date', 'author_name'],
            'merged': None,
            'protected': None
        }
    if object_name == 'Issue':
        return {
            'id': None,
            'iid': None,
            'title': None,
            'description': None,
            'author': ['name', 'id'],
            'assignee': ['name', 'id'],
            'created_at': None,
            'updated_at': None,
            'closed_at': None,
            'state': None,
            'severity': None
        }

    if object_name == 'Merge Request':
        return {
            'id': None,
            'iid': None,
            'title': None,
            'description': None,
            'state': None,
            'author': ['name', 'id'],
            'created_at': None,
            'closed_at': None,
            'source_branch': None,
            'target_branch': None
        }
    if object_name == 'Commit':
        return {
            'id': None,
            'short_id': None,
            'title': None,
            'message': None,
            'author': ['name'],
            'created_at': None
        }

    if object_name == 'Issue Note':
        return {
            'id': None,
            'created_at': None,
            'updated_at': None,
            'body': None,
            'noteable_iid': None,
            'author': ['name', 'id']
        }

    if object_name == 'Merge Request Note':
        return {
            'id': None,
            'created_at': None,
            'updated_at': None,
            'body': None,
            'noteable_iid': None,
            'author': ['name', 'id']
        }

    if object_name == 'Project':
        return {
            'id': None,
            'description': None,
            'name': None,
            'created_at': None,
            'default_branch': None,
            'namespace': ['name', 'id']
        }
    return {}


def partial_response(response: list, object_type: str):
    '''
    This function filters the raw response from the API according to the dict of fields given.
    input: raw response which is a list of dictionaries, fields for the context data display.
    output: partial dictionary results.
    '''
    partial_response: list[dict[str, Any]] = []
    fields = partial_response_fields(object_type)
    for raw_dict in response:
        partial_dict: dict[str, Any] = {}
        for field_key, field_dict_vals in fields.items():
            if not (field_dict_vals):
                partial_dict[field_key] = raw_dict.get(field_key, '')
            elif raw_dict.get(field_key):
                temp_dict_vals: dict[str, Any] = {}
                for val in field_dict_vals:
                    temp_dict_vals[val] = raw_dict.get(field_key, {}).get(val, '')
                partial_dict[field_key] = temp_dict_vals
        partial_response.append(partial_dict)
    return partial_response


def verify_project_id(client: Client, project_id: int) -> Boolean:
    '''
    This function verify that the user can access the project.
    input: project_id
    output: True is the project_id is valid, otherwise an error will occur.
    '''
    # This is a way to search the project_id api.
    params = assign_params(id_before=(project_id + 1), per_page=1)
    response = client.get_project_list_request(params)
    if response[0].get('id') != project_id:
        raise DemistoException(f'Project with project_id {project_id} does not exist')
    return True


def return_date_arg_as_iso(arg: str | None) -> str | None:
    '''
     This function converts timestamp format (<number> <time unit>, e.g., 12 hours, 7 days) to ISO format.
    input: arg in timestamp format
    output: returns the iso format for the timestamp if exist
    '''
    arg_to_iso = arg_to_datetime(arg)
    return arg_to_iso.isoformat() if arg_to_iso else None


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    client.version_get_request()
    return 'ok'


''' INTEGRATION COMMANDS '''


def group_project_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns a list of projects within a group.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'group_id' (Required): group ID to retrieve the projects from.
    Returns:
        (CommandResults).
    """
    response_to_hr, headers = [], ['Id', 'Name', 'Description', 'Path']
    page_number = arg_to_number(args.get('page')) or 1
    limit = arg_to_number(args.get('limit', '50')) or 50
    group_id = args.get('group_id')
    params: dict[str, Any] = {}
    response = response_according_pagination(client.group_projects_list_request, limit, page_number, params, group_id)
    for project in response:
        response_to_hr.append({'Id': project.get('id'),
                               'Name': project.get('name', ''),
                               'Description': project.get('description', ''),
                               'Path': project.get('path', '')})
    human_readable = tableToMarkdown('List Group Projects', response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.GroupProject',
        outputs_key_field='id',
        readable_output=human_readable,
        outputs=response,
        raw_response=response
    )


def get_project_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns a list of projects.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
    Returns:
        (CommandResults).
    """
    response_to_hr, headers, human_readable = [], ['Id', 'Name', 'Description', 'Path'], ''
    page_number = arg_to_number(args.get('page')) or 1
    limit = arg_to_number(args.get('limit')) or 50
    params = assign_params(membership=args.get('membership'), order_by=args.get('order_by'),
                           owned=args.get('owned'), search=args.get('search'), sort=args.get('sort'),
                           visibility=args.get('visibility'), with_issues_enabled=args.get('with_issues_enabled'),
                           with_merge_requests_enabled=args.get('with_merge_requests_enabled'))
    response = response_according_pagination(client.get_project_list_request, limit, page_number, params, None)
    for project in response:
        response_to_hr.append({'Id': project.get('id'),
                               'Name': project.get('name', ''),
                               'Description': project.get('description', ''),
                               'Path': project.get('path', '')})
    return_partial = argToBoolean(args.get('partial_response', True))
    outputs = partial_response(response, 'Project') if return_partial else response
    human_readable = tableToMarkdown('List Projects', response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.Project',
        outputs_key_field='id',
        readable_output=human_readable,
        outputs=outputs,
        raw_response=response
    )


def issue_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns a list of issues within the project.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:PRIVATE-TOKEN
    Returns:
        (CommandResults).
    """
    response_to_hr, human_readable = [], ''
    headers = ['Issue_iid', 'Title', 'Description', 'CreatedAt', 'CreatedBy', 'UpdatedAt', 'Milestone', 'State', ' Assignee']
    page_number = arg_to_number(args.get('page')) or 1
    limit = arg_to_number(args.get('limit')) or 50
    params = assign_params(assignee_id=args.get('assignee_id'), assignee_username=args.get('assignee_username'),
                           author_id=args.get('author_id'), author_username=args.get('author_username'),
                           confidential=args.get('confidential'), created_after=return_date_arg_as_iso(args.get('created_after')),
                           created_before=return_date_arg_as_iso(args.get('created_before')), due_date=args.get('due_date'),
                           epic_id=args.get('epic_id'), issue_type=args.get('issue_type'), content=args.get('content'),
                           labels=args.get('labels'), milestone=args.get('milestone'), order_by=args.get('order_by'),
                           scope=args.get('scope'), search=args.get('search'), sort=args.get('sort'),
                           state=args.get('state'), updated_after=return_date_arg_as_iso(args.get('updated_after')),
                           updated_before=return_date_arg_as_iso(args.get('updated_before')))
    response = response_according_pagination(client.issue_list_request, limit, page_number, params, None)
    for issue in response:
        issue_details = {'Issue_iid': issue.get('iid'),
                         'Title': issue.get('title', ''),
                         'Description': issue.get('description', ''),
                         'CreatedAt': issue.get('created_at'),
                         'UpdateAt': issue.get('update_at', ''),
                         'State': issue.get('state', ''),
                         'CreatedBy': issue.get('author', {}).get('created_by', '')}
        if issue.get('assignee'):
            issue_details['Assignee'] = issue.get('assignee', {}).get('name', '')
        if issue.get('milestone'):
            issue_details['Milestone'] = issue.get('milestone', {}).get('title', '')
        response_to_hr.append(issue_details)
    return_partial = argToBoolean(args.get('partial_response', True))
    outputs = partial_response(response, 'Issue') if return_partial else response
    human_readable = tableToMarkdown('List Issues', response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.Issue',
        outputs_key_field='iid',
        readable_output=human_readable,
        outputs=outputs,
        raw_response=response
    )


def create_issue_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Creates an issue.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'labels': Create issue with the given labels.
            - 'title': Create issue with given title.
            - 'description': Create issue with the given description.

    Returns:
        (CommandResults).
    """
    headers = ['Iid', 'Title', 'Description', 'CreatedAt', 'CreatedBy', 'UpdatedAt', 'Milestone', 'State', 'Assignee']
    labels = args.get('labels', '')
    title = args.get('title', '')
    description = args.get('description', '')
    response = client.create_issue_request(labels, title, description)
    human_readable_dict = {
        'Iid': response.get('iid'),
        'Title': response.get('title'),
        'Description': response.get('description', ''),
        'CreatedAt': response.get('created_at', ''),
        'CreatedBy': response.get('author', {}).get('name', ''),
        'UpdatedAt': response.get('updated_at', ''),
        'State': response.get('state', '')
    }
    if response.get('assignee'):
        human_readable_dict['Assignee'] = response.get('assignee', {}).get('name', '')
    if response.get('milestone'):
        human_readable_dict['Milestone'] = response.get('milestone', {}).get('title', '')
    return_partial = argToBoolean(args.get('partial_response', True))
    outputs = partial_response([response], 'Issue') if return_partial else response
    human_readable = tableToMarkdown('Created Issue', human_readable_dict, headers=headers, removeNull=True)
    return CommandResults(
        outputs_prefix='GitLab.Issue',
        outputs_key_field='iid',
        readable_output=human_readable,
        outputs=outputs,
        raw_response=response
    )


def branch_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Creates new branch.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'branch': The name of the new branch.
            - 'ref': The current branch.

    Returns:
        (CommandResults).
    """
    branch = args.get('branch', '')
    ref = args.get('ref', '')
    headers = ['Title', 'CommitShortId', 'CommitTitle', 'CreatedAt', 'IsMerge', 'IsProtected']
    response = client.create_branch_request(branch, ref)
    human_readable_dict = {
        'Title': response.get('name', ''),
        'CommitShortId': response.get('commit', '').get('short_id', ''),
        'CommitTitle': response.get('commit', '').get('title', ''),
        'CreatedAt': response.get('commit', '').get('created_at', ''),
        'IsMerge': response.get('merged', 'False'),
        'IsProtected': response.get('protected', 'False')
    }
    human_readable = tableToMarkdown('Created Branch', human_readable_dict, headers=headers)
    return_partial = argToBoolean(args.get('partial_response', True))
    outputs = partial_response([response], 'Branch') if return_partial else response
    command_results = CommandResults(
        outputs_prefix='GitLab.Branch',
        outputs_key_field='short_id',
        readable_output=human_readable,
        outputs=outputs,
        raw_response=response
    )
    return command_results


def branch_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Deletes branch.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
        - branch: branch name to delete.

    Returns:
        (CommandResults).
    """
    branch = str(args.get('branch', ''))
    response = client.branch_delete_request(branch)
    command_results = CommandResults(
        outputs_prefix='GitLab.Branch',
        outputs_key_field='short_id',
        readable_output='Branch deleted successfully',
        outputs=response,
        raw_response=response
    )

    return command_results


def merged_branch_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Deletes branches who had been merged.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:

    Returns:
        (CommandResults).
    """
    response = client.delete_merged_branches_request()
    command_results = CommandResults(
        readable_output='Merged branches Deleted successfully',
        outputs=response,
        raw_response=response
    )
    return command_results


def get_raw_file_command(client: Client, args: dict[str, Any]) -> list:
    """
    Returns the content of a given file.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'project_id' (Required): Project ID to get the file from.
            - 'file_path' (Required): The file path.
            - 'ref': The branch to retrieve the file from, default is master
            - `create_file_from_content` (Optional): bool, create file from the content data or not

    Returns:
        (CommandResults).
    """
    ref = args.get('ref', 'main')
    file_path = args.get('file_path', '')
    headers = ['path', 'reference', 'content']
    if file_path:
        file_path = encode_file_path_if_needed(file_path)
    response = client.get_raw_file_request(file_path, ref)
    outputs = {'path': file_path, 'content': response, 'ref': ref}
    human_readable = tableToMarkdown('Raw file', outputs, headers=headers)
    file_name = file_path.split('/')[-1]
    file_ = fileResult(filename=file_name, data=response, file_type=EntryType.ENTRY_INFO_FILE)
    results = CommandResults(
        outputs_prefix='GitLab.File',
        readable_output=human_readable,
        outputs=outputs,
        raw_response=response
    )
    return [results, file_]


def issue_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    updating an issue.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'issue_iid': The iid of the issue.

        [at least one of the following args is needed for the operation to be successful:
            'add_labels', 'assignee_ids', 'confidential', 'description', 'discussion_locked',
            'due_date', 'epic_id', 'epic_iid', 'issue_type', 'milestone_id', 'remove_labels',
            'state_event', 'title']

    Returns:
        (CommandResults).
    """
    issue_iid = args.get('issue_iid')
    params_optional = ['add_labels', 'assignee_ids', 'confidential', 'description', 'discussion_locked',
                       'due_date', 'epic_id', 'epic_iid', 'issue_type', 'milestone_id', 'remove_labels',
                       'state_event', 'title']
    headers = ['Iid', 'Title', 'Description', 'CreatedAt', 'CreatedBy', 'UpdatedAt', 'Milestone', 'State', 'Assignee']
    params = check_args_for_update(args, params_optional)
    response = client.issue_update_request(issue_iid, params)
    human_readable_dict = {'Iid': response.get('iid', ''),
                           'Title': response.get('title', ''),
                           'Description': response.get('description', ''),
                           'CreatedAt': response.get('created_at', ''),
                           'UpdatedAt': response.get('updated_at', ''),
                           'State': response.get('state', ''),
                           'Assignee': response.get('assignee', ''),
                           'CreatedBy': response.get('author', {}).get('name', '')}
    if response.get('author'):
        human_readable_dict['CreatedBy'] = response['author'].get('name', '')
    if response.get('milestone'):
        human_readable_dict['Milestone'] = response['milestone'].get('title', '')
    return_partial = argToBoolean(args.get('partial_response', True))
    outputs = partial_response([response], 'Issue') if return_partial else response
    human_readable = tableToMarkdown('Update Issue', human_readable_dict, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.Issue',
        outputs_key_field='iid',
        readable_output=human_readable,
        outputs=outputs,
        raw_response=response
    )


def version_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Gets the current version.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - No arguments needed.
    Returns:
        (CommandResults).
        'GitLab \n version:
    """
    response = client.version_get_request()
    version = response.get('version', '')
    revision = response.get('revision', '')
    command_results = CommandResults(
        outputs_prefix='GitLab.Version',
        readable_output=f'GitLab version {version}\n reversion: {revision} ',
        outputs_key_field='revision',
        outputs=response,
        raw_response=response
    )

    return command_results


def file_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Allows to receive information about file in repository like name, size, content..
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'file_path' (Required): The file path.
            - 'ref': The branch to retrieve the file from, default is main

    Returns:
        (CommandResults).
    """
    branch = args.get('ref', 'master')
    file_path = args.get('file_path', '')
    headers = ['FileName', 'FilePath', 'Ref', 'ContentSha', 'CommitId', 'LastCommitId', 'Size']
    if file_path:
        file_path = encode_file_path_if_needed(file_path)
    response = client.file_get_request(file_path, branch)
    human_readable_dict = {'FileName': response.get('file_name', ''),
                           'FilePath': response.get('file_path', ''),
                           'Ref': response.get('ref', ''),
                           'ContentSha': response.get('content_sha256', ''),
                           'CommitId': response.get('commit_id', ''),
                           'LastCommitId': response.get('last_commit_id', ''),
                           'Size': response.get('size', '')}
    human_readable = tableToMarkdown('Get File', human_readable_dict, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.File',
        outputs_key_field='path',
        readable_output=human_readable,
        outputs=response,
        raw_response=response
    )


def file_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Allows to create file in repository.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'file_path' (Required): The file path.
            - 'branch': The branch to retrieve the file from, default is main
    Returns:
        (CommandResults).
    """
    file_path = args.get('file_path')
    branch = args.get('branch')
    commit_msg = args.get('commit_message', '')
    entry_id = args.get('entry_id', '')
    author_email = args.get('author_email', '')
    author_name = args.get('author_name', '')
    file_content = args.get('file_content', '')
    execute_filemode = args.get('execute_filemode', '')
    if not entry_id and not file_content and not file_path:
        raise DemistoException('You must specify either the "file_content" and "file_path" or the "entry_id" of the file.')
    elif entry_id:
        file_path_entry_id = demisto.getFilePath(entry_id).get('path')
        with open(file_path_entry_id, 'rb') as f:
            file_content = f.read()
    elif file_path:
        file_path = encode_file_path_if_needed(file_path)
    response = client.file_create_request(file_path, branch, commit_msg, author_email, author_name,
                                          file_content, execute_filemode)
    return CommandResults(
        outputs_prefix='GitLab.File',
        outputs_key_field='file_path',
        readable_output='File created successfully.',
        outputs=response,
        raw_response=response
    )


def file_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Updating a file.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR required arguments:
            - 'file_path': Url parameter- URL-encoded full path to new file.
            - 'branch': Retrieve file from the given branch.
            - 'commit_message': message regarding the update.
            - 'entry_id' OR 'file_content' for the update.

    Returns:
        (CommandResults).
    """
    file_path = args.get('file_path', '')
    entry_id = args.get('entry_id')
    file_content = args.get('file_content', '')
    branch = args.get('branch')
    start_branch = args.get('start_branch')
    encoding = args.get('encoding')
    author_email = args.get('author_email')
    author_name = args.get('author_name')
    commit_message = args.get('commit_message')
    last_commit_id = args.get('last_commit_id')
    execute_filemode = args.get('execute_filemode')
    if not entry_id and not file_content and not file_path:
        raise DemistoException('You must specify either the "file_content" and "file_path" or the "entry_id" of the file.')
    elif entry_id:
        file_path_entry_id = demisto.getFilePath(entry_id).get('path')
        with open(file_path_entry_id, 'rb') as f:
            file_content = f.read()
    elif file_path:
        file_path = urllib.parse.quote(file_path, safe='')
    response = client.file_update_request(file_path, branch, start_branch, encoding, author_email, author_name, commit_message,
                                          last_commit_id, execute_filemode, file_content)

    return CommandResults(
        outputs_prefix='GitLab.File',
        outputs_key_field='file_path',
        readable_output='File updated successfully.',
        outputs=response,
        raw_response=response
    )


def file_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Deletes a file from branch.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
        - branch: the name of the branch.
        - file_path: the file path.
    Returns:
        (CommandResults).
    """
    branch = args.get('branch', '')
    file_path = args.get('file_path', '')
    commit_message = args.get('commit_message', '')
    response = client.file_delete_request(file_path, branch, commit_message)
    command_results = CommandResults(
        outputs_prefix='GitLab.File',
        outputs_key_field='path',
        readable_output='File deleted successfully',
        outputs=response,
        raw_response=response
    )

    return command_results


def commit_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns a list of commits OR a single commit by commit_id.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments
    Returns:
        (CommandResults).
    """
    response_to_hr, human_readable = [], ''
    headers = ['Title', 'Message', 'ShortId', 'Author', 'CreatedAt']
    commit_id = args.get('commit_id')
    if commit_id:
        response_title = 'Commit details'
        response = [client.commit_single_request(commit_id)]
    else:
        response_title = 'List Commits'
        page_number = arg_to_number(args.get('page')) or 1
        limit = arg_to_number(args.get('limit')) or 50
        params = assign_params(ref_name=args.get('ref_name'), until=return_date_arg_as_iso(args.get('created_before')),
                               since=return_date_arg_as_iso(args.get('created_after')), path=args.get('path'),
                               with_stats=args.get('with_stats'), first_parent=args.get('first_parent'),
                               order=args.get('order'), all_=args.get('all'))
        response = response_according_pagination(client.commit_list_request, limit, page_number, params, None)

    for commit in response:
        response_to_hr.append({'Title': commit.get('title', ''),
                               'Message': commit.get('message', ''),
                               'ShortId': commit.get('short_id', ''),
                               'Author': commit.get('author_name', ''),
                               'CreatedAt': commit.get('created_at', '')})
    return_partial = argToBoolean(args.get('partial_response', True))
    outputs = partial_response(response, 'Commit') if return_partial else response
    human_readable = tableToMarkdown(response_title, response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.Commit',
        outputs_key_field='short_id',
        readable_output=human_readable,
        outputs=outputs,
        raw_response=response
    )


def branch_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns a list of branches OR a single commit by branch_id.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments
    Returns:
        (CommandResults).
    """
    response_to_hr, human_readable = [], ''
    headers = ['Title', 'CommitShortId', 'CommitTitle', 'CreatedAt', 'IsMerge', 'IsProtected']
    branch_id = args.get('branch_name')
    if branch_id:
        response_title = 'Branch details'
        response = [client.branch_single_request(branch_id)]

    else:
        response_title = 'List Branches'
        page_number = arg_to_number(args.get('page')) or 1
        limit = arg_to_number(args.get('limit')) or 50
        params = assign_params(search=args.get('search'))
        response = response_according_pagination(client.branch_list_request, limit, page_number, params, None)

    for branch in response:
        response_to_hr.append({'Title': branch.get('name'),
                               'IsMerge': branch.get('merged'),
                               'IsProtected': branch.get('protected'),
                               'CreatedAt': branch.get('commit', {}).get('created_at', ''),
                               'CommitShortId': branch.get('commit', {}).get('short_id', ''),
                               'CommitTitle': branch.get('commit', {}).get('title', '')})
    return_partial = argToBoolean(args.get('partial_response', True))
    outputs = partial_response(response, 'Branch') if return_partial else response
    human_readable = tableToMarkdown(response_title, response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.Branch',
        outputs_key_field='short_id',
        readable_output=human_readable,
        outputs=outputs,
        raw_response=response
    )


def group_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns a list of visible groups for the authenticated user.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments
    Returns:
        (CommandResults).
    """
    response_to_hr, human_readable, response_title = [], '', 'List Groups'
    headers = ['Id', 'Name', 'Path', 'Description', 'CreatedAt', 'Visibility']
    page_number = arg_to_number(args.get('page')) or 1
    limit = arg_to_number(args.get('limit')) or 50
    params = assign_params(skip_groups=args.get('skip_groups'), all_available=args.get('all_available'),
                           search=args.get('search'), order_by=args.get('order_by'), sort=args.get('sort'),
                           owned=args.get('owned'), min_access_level=args.get('min_access_level'),
                           top_level_only=args.get('top_level_only'))
    response = response_according_pagination(client.group_list_request, limit, page_number, params, None)

    for group in response:
        response_to_hr.append({'Id': group.get('id'),
                               'Name': group.get('name', ''),
                               'Path': group.get('path', ''),
                               'Description': group.get('description', ''),
                               'CreatedAt': group.get('created_at', ''),
                               'Visibility': group.get('visibility', '')})
    human_readable = tableToMarkdown(response_title, response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.Group',
        outputs_key_field='id',
        readable_output=human_readable,
        outputs=response,
        raw_response=response
    )


def issue_note_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Creates an issue note.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'issue_iid': the IID of the issue.
            - 'body': Retrieve only issues with the given labels.
            - 'confidential': If the thread is confidential.

    Returns:
        (CommandResults).
    """
    issue_iid = args.get('issue_iid', '')
    body = args.get('body', '')
    confidential = args.get('confidential')
    response = client.issue_note_create_request(issue_iid, body, confidential)
    return_partial = argToBoolean(args.get('partial_response', True))
    outputs = partial_response([response], 'Issue Note') if return_partial else response
    return CommandResults(
        outputs_prefix='GitLab.IssueNote',
        outputs_key_field='id',
        readable_output='Issue note created successfully',
        outputs=outputs,
        raw_response=response
    )


def issue_note_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Deletes an issue note.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'issue_iid': the IID of the issue.
            - 'note_id': the ID of the issue note.

    Returns:
        (CommandResults).
    """
    issue_iid = arg_to_number(args.get('issue_iid'))
    note_id = arg_to_number(args.get('note_id'))
    client.issue_note_delete_request(issue_iid, note_id)
    return CommandResults(
        readable_output='Issue note deleted successfully'
    )


def issue_note_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Updating an issue note.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'state': The state of the issue.
            - 'labels': Retrieve only issues with the given labels.
            - 'assignee_username': Retrieve issues by assignee username.

    Returns:
        (CommandResults).
    """
    issue_iid = args.get('issue_iid')
    note_id = args.get('note_id')
    body = args.get('body')
    response = client.issue_note_update_request(issue_iid, note_id, body)
    return_partial = argToBoolean(args.get('partial_response', True))
    outputs = partial_response([response], 'Issue Note') if return_partial else response
    return CommandResults(
        outputs_prefix='GitLab.IssueNote',
        outputs_key_field='id',
        readable_output='Issue note updated was updated successfully.',
        outputs=outputs,
        raw_response=response
    )


def issue_note_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns a list of issue's notes.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments
    Returns:
        (CommandResults).
    """
    response_to_hr = []
    headers = ['Id', 'Author', 'Text', 'CreatedAt', 'UpdatedAt']
    page_number = arg_to_number(args.get('page')) or 1
    limit = arg_to_number(args.get('limit')) or 50
    issue_iid = args.get('issue_iid')
    params = assign_params(sort=args.get('sort'), order_by=args.get('order_by'))
    response = response_according_pagination(client.issue_note_list_request, limit, page_number, params, issue_iid)

    for issue_note in response:
        issue_note_edit = {'Id': issue_note.get('id'),
                           'Text': issue_note.get('body', ''),
                           'Author': issue_note.get('author', {}).get('name', ''),
                           'UpdatedAt': issue_note.get('updated_at', ''),
                           'CreatedAt': issue_note.get('created_at', ''),
                           }
        response_to_hr.append(issue_note_edit)
    return_partial = argToBoolean(args.get('partial_response', True))
    outputs = partial_response(response, 'Issue Note') if return_partial else response
    human_readable = tableToMarkdown('List Issue notes', response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.IssueNote',
        outputs_key_field='id',
        readable_output=human_readable,
        outputs=outputs,
        raw_response=response
    )


def merge_request_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns a list of merge requests .
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments
    Returns:
        (CommandResults).
    """
    response_to_hr = []
    headers = ['Iid', 'Title', 'CreatedAt', 'CreatedBy', 'UpdatedAt', 'Status', 'MergeBy', 'MergedAt', 'Reviewers']
    page_number = arg_to_number(args.get('page')) or 1
    limit = arg_to_number(args.get('limit')) or 50
    params = assign_params(state=args.get('state'),
                           order_by=args.get('order_by'),
                           sort=args.get('sort'),
                           milestone=args.get('milestone'),
                           labels=args.get('labels'),
                           created_after=return_date_arg_as_iso(args.get('created_after')),
                           created_before=return_date_arg_as_iso(args.get('created_before')),
                           updated_after=return_date_arg_as_iso(args.get('updated_after')),
                           updated_before=return_date_arg_as_iso(args.get('updated_before')),
                           scope=args.get('scope'),
                           author_id=args.get('author_id'),
                           author_username=args.get('author_username'),
                           assignee_id=args.get('assignee_id'),
                           reviewer_id=args.get('reviewer_id'),
                           reviewer_username=args.get('reviewer_username'), source_branch=args.get('source_branch'),
                           target_branch=args.get('target_branch'), search=args.get('search'))

    response = response_according_pagination(client.merge_request_list_request, limit, page_number, params, None)
    for merge_request in response:
        merge_request_edit = {'Iid': merge_request.get('iid', ''),
                              'Title': merge_request.get('Title', ''),
                              'CreatedAt': merge_request.get('created_at', ''),
                              'UpdatedAt': merge_request.get('updated_at', ''),
                              'Status': merge_request.get('state', ''),
                              'MergeAt': merge_request.get('merged_at'),
                              'Reviewers': merge_request.get('reviewers', ''),
                              'CreatedBy': merge_request.get('author', {}).get('name', '')}
        if merge_request.get('merge_user'):
            merge_request_edit['MergeBy'] = merge_request.get('merge_user', {}).get('username', '')
        response_to_hr.append(merge_request_edit)
    return_partial = argToBoolean(args.get('partial_response', True))
    outputs = partial_response(response, 'Merge Request') if return_partial else response
    human_readable = tableToMarkdown('List Merge requests', response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.MergeRequest',
        outputs_key_field='iid',
        readable_output=human_readable,
        outputs=outputs,
        raw_response=response
    )


def merge_request_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Creates a merge request note.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'source_branch': the IID of the issue.
            - 'target_branch': Retrieve only issues with the given labels.
            - 'title': If the thread is confidential.

    Returns:
        (CommandResults).
    """
    source_branch = args.get('source_branch')
    target_branch = args.get('target_branch')
    title = args.get('title')
    assignee_ids = args.get('assignee_ids')
    reviewer_ids = args.get('reviewer_ids')
    description = args.get('description')
    target_project_id = args.get('target_project_id')
    labels = args.get('labels')
    milestone_id = args.get('milestone_id')
    remove_source_branch = args.get('remove_source_branch')
    allow_collaboration = args.get('allow_collaboration')
    allow_maintainer_to_push = args.get('allow_maintainer_to_push')
    approvals_before_merge = args.get('approvals_before_merge')
    squash = args.get('squash')
    response = client.merge_request_create_request(source_branch, target_branch, title, assignee_ids,
                                                   reviewer_ids, description, target_project_id, labels,
                                                   milestone_id, remove_source_branch, allow_collaboration,
                                                   allow_maintainer_to_push, approvals_before_merge, squash)
    return_partial = argToBoolean(args.get('partial_response', True))
    outputs = partial_response([response], 'Merge Request') if return_partial else response
    return CommandResults(
        outputs_prefix='GitLab.MergeRequest',
        outputs_key_field='iid',
        readable_output='Merge request created successfully.',
        outputs=outputs,
        raw_response=response
    )


def merge_request_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Updating an merge request.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'merge_request_id': The id of the merge request to update.

    Returns:
        (CommandResults).
    """
    merge_request_id = args.get('merge_request_id')
    target_branch = args.get('target_branch')
    title = args.get('title')
    assignee_ids = args.get('assignee_ids')
    reviewer_ids = args.get('reviewer_ids')
    description = args.get('description')
    target_project_id = args.get('target_project_id')
    remove_labels = args.get('remove_labels')
    add_labels = args.get('add_labels')
    milestone_id = args.get('milestone_id')
    state_event = args.get('state_event')
    remove_source_branch = args.get('remove_source_branch')
    allow_collaboration = args.get('allow_collaboration')
    allow_maintainer_to_push = args.get('allow_maintainer_to_push')
    approvals_before_merge = args.get('approvals_before_merge')
    squash = args.get('squash')
    discussion_locked = args.get('discussion_locked')
    response = client.merge_request_update_request(merge_request_id, target_branch, title, assignee_ids, reviewer_ids,
                                                   description, target_project_id, add_labels, remove_labels,
                                                   milestone_id, state_event, remove_source_branch, allow_collaboration,
                                                   allow_maintainer_to_push, approvals_before_merge, discussion_locked,
                                                   squash)
    return_partial = argToBoolean(args.get('partial_response', True))
    outputs = partial_response([response], 'Merge Request') if return_partial else response
    return CommandResults(
        outputs_prefix='GitLab.MergeRequest',
        outputs_key_field='iid',
        readable_output='Merge request was updated successfully.',
        outputs=outputs,
        raw_response=response
    )


def merge_request_note_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns a list of merge request's notes.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments
    Returns:
        (CommandResults).
    """
    response_to_hr = []
    headers = ['Id', 'Author', 'Text', 'CreatedAt', 'UpdatedAt']
    page_number = arg_to_number(args.get('page')) or 1
    limit = arg_to_number(args.get('limit')) or 50
    merge_request_iid = args.get('merge_request_iid')

    params = assign_params(sort=args.get('sort'), order_by=args.get('order_by'))
    response = response_according_pagination(client.merge_request_note_list_request, limit, page_number, params,
                                             merge_request_iid)

    for merge_request_note in response:
        merge_request_note_edit = {'Id': merge_request_note.get('id', ''),
                                   'Text': merge_request_note.get('body', ''),
                                   'UpdatedAt': merge_request_note.get('updated_at', ''),
                                   'CreatedAt': merge_request_note.get('created_at', '')}
        if merge_request_note.get('author'):
            merge_request_note_edit['Author'] = merge_request_note.get('author', {}).get('name', '')
        response_to_hr.append(merge_request_note_edit)
    return_partial = argToBoolean(args.get('partial_response', True))
    outputs = partial_response(response, 'Merge Request Note') if return_partial else response
    human_readable = tableToMarkdown('List Merge Issue Notes', response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.MergeRequestNote',
        outputs_key_field='id',
        readable_output=human_readable,
        outputs=outputs,
        raw_response=response
    )


def merge_request_note_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Creates a merge request note.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'merge_request_iid: the IID of the merge request.
            - 'body':  Create notes with a description.
    Returns:
        (CommandResults).
    """
    merge_request_iid = args.get('merge_request_iid')
    body = args.get('body')
    response = client.merge_request_note_create_request(merge_request_iid, body)
    return_partial = argToBoolean(args.get('partial_response', True))
    outputs = partial_response([response], 'Merge Request Note') if return_partial else response
    return CommandResults(
        outputs_prefix='GitLab.MergeRequestNote',
        outputs_key_field='id',
        readable_output='Merge request note created successfully.',
        outputs=outputs,
        raw_response=response
    )


def merge_request_note_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    updating a merge request note.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'merge_request_iid: the IID of the merge request.
            - 'note_id': The ID of an issue note.
            - 'body':  Update the notes with a description.

    Returns:
        (CommandResults).
    """
    merge_request_iid = args.get('merge_request_iid')
    note_id = args.get('note_id')
    body = args.get('body')
    response = client.merge_request_note_update_request(merge_request_iid, note_id, body)
    return_partial = argToBoolean(args.get('partial_response', True))
    outputs = partial_response([response], 'Merge Request Note') if return_partial else response
    return CommandResults(
        outputs_prefix='GitLab.MergeRequestNote',
        outputs_key_field='id',
        readable_output='Merge request note was updated successfully',
        outputs=outputs,
        raw_response=response
    )


def merge_request_note_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    deletes a merge request note.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'issue_iid': the IID of the issue.
            - 'note_id': the ID of the issue note.

    Returns:
        (CommandResults).
    """
    merge_request_iid = args.get('merge_request_iid')
    note_id = args.get('note_id')
    client.merge_request_note_delete_request(merge_request_iid, note_id)
    return CommandResults(
        readable_output='Merge request note deleted successfully'
    )


def group_member_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Gets a list of group or project members viewable by the authenticated user.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - group_id
    Returns:
        (CommandResults).
    """
    response_to_hr = []
    headers = ['Id', 'Name', 'UserName', 'MembershipState', 'ExpiresAt']
    group_id = args.get('group_id')
    response = client.group_member_list_request(group_id)
    for group_member in response:
        group_member_edit = {'Id': group_member.get('id', ''),
                             'Name': group_member.get('name', ''),
                             'UserName': group_member.get('username', ''),
                             'MembershipState': group_member.get('membership_state', ''),
                             'ExpiresAt': group_member.get('expires_at', '')}
        response_to_hr.append(group_member_edit)
    human_readable = tableToMarkdown('List Group Members', response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.GroupMember',
        outputs_key_field='id',
        readable_output=human_readable,
        outputs=response,
        raw_response=response
    )


def code_search_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns a results of code search.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments.
    Returns:
        (CommandResults).
    """
    page_number = arg_to_number(args.get('page')) or 1
    limit = arg_to_number(args.get('limit')) or 50
    headers = ['id', 'basename', 'ref', 'filename', 'path', 'startline', 'data']
    params = assign_params(search=args.get('search'), scope='blobs')
    response = response_according_pagination(client.codes_search_request, limit, page_number, params,
                                             None)
    human_readable = tableToMarkdown('Code Search Results', response, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.Code',
        readable_output=human_readable,
        outputs=response,
        raw_response=response
    )


def project_user_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns a results of all the project's users.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments
    Returns:
        (CommandResults).
    """
    headers = ['Id', 'UserName', 'Name', 'State', 'WebLink']
    response_to_hr = []
    page_number = arg_to_number(args.get('page')) or 1
    limit = arg_to_number(args.get('limit')) or 50
    params = assign_params(search=args.get('search'))
    response = response_according_pagination(client.project_user_list_request, limit, page_number, params, None)

    for user in response:
        response_to_hr.append({'Id': user.get('id', ''),
                               'UserName': user.get('username', ''),
                               'Name': user.get('name', ''),
                               'State': user.get('state', ''),
                               'WebLink': user.get('web_url', '')})
    human_readable = tableToMarkdown('List Users', response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.User',
        outputs_key_field='id',
        readable_output=human_readable,
        outputs=response,
        raw_response=response
    )


def gitlab_pipelines_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns pipelines corresponding to given arguments.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'project_id' (Required): Project ID to retrieve pipeline schedules from.
            - 'pipeline_id': ID of specific pipeline to retrieve its details.

    Returns:
        (CommandResults).
    """
    project_id = args.get('project_id', '') or client.project_id
    pipeline_id = args.get('pipeline_id')
    ref = args.get('ref')
    status = args.get('status')
    response = client.get_pipeline_request(project_id, pipeline_id, ref, status)
    response = response if isinstance(response, list) else [response]
    outputs = [{k: v for k, v in output.items() if k in PIPELINE_FIELDS_TO_EXTRACT} for output in response]

    return CommandResults(
        outputs_prefix='GitLab.Pipeline',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response,
        readable_output=tableToMarkdown('GitLab Pipelines', outputs, removeNull=True)
    )


def gitlab_pipelines_schedules_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns pipeline schedules corresponding to given arguments.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'project_id' (Required): Project ID to retrieve pipeline schedules from.
            - 'pipeline_schedule_id': ID of specific pipeline schedule to retrieve its details.

    Returns:
        (CommandResults).
    """
    project_id = args.get('project_id', '') or client.project_id
    pipeline_schedule_id = args.get('pipeline_schedule_id')
    response = client.get_pipeline_schedules_request(project_id, pipeline_schedule_id)
    response = response if isinstance(response, list) else [response]
    outputs = [{k: v for k, v in output.items() if k in PIPELINE_SCHEDULE_FIELDS_TO_EXTRACT} for output in response]

    return CommandResults(
        outputs_prefix='GitLab.PipelineSchedule',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response,
        readable_output=tableToMarkdown('GitLab Pipeline Schedules', outputs, removeNull=True)
    )


def gitlab_jobs_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns pipeline jobs corresponding to given arguments.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'project_id' (Required): Project ID to retrieve pipeline schedules from.
            - 'pipeline_id': ID of specific pipeline to retrieve its jobs.

    Returns:
        (CommandResults).
    """
    project_id = args.get('project_id', '') or client.project_id
    pipeline_id = args.get('pipeline_id', '')
    response = client.get_pipeline_job_request(project_id, pipeline_id)
    response = response if isinstance(response, list) else [response]
    outputs = [{k: v for k, v in output.items() if k in JOB_FIELDS_TO_EXTRACT} for output in response]

    return CommandResults(
        outputs_prefix='GitLab.Job',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response,
        readable_output=tableToMarkdown('GitLab Jobs', outputs, removeNull=True)
    )


def gitlab_artifact_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns artifact corresponding to given artifact path suffix of the given job ID.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'project_id' (Required): Project ID to retrieve pipeline schedules from.
            - 'job_id': ID of specific job to retrieve artifact from.
            - 'artifact_path_suffix': Suffix to artifact in the artifacts directory of the job.

    Returns:
        (CommandResults).
    """
    project_id = args.get('project_id', '') or client.project_id
    job_id = args.get('job_id', '')
    artifact_path_suffix = args.get('artifact_path_suffix', '')
    response = client.get_job_artifact_request(project_id, job_id, artifact_path_suffix)
    outputs = {
        'job_id': job_id,
        'artifact_path_suffix': artifact_path_suffix,
        'artifact_data': response
    }
    if len(response) <= 100:
        human_readable = tableToMarkdown(f'Artifact {artifact_path_suffix} From Job {job_id}', outputs, removeNull=True)
    else:
        human_readable = f'## Data for artifact {artifact_path_suffix} From Job {job_id} Has Been Retrieved.'

    return CommandResults(
        outputs_prefix='GitLab.Artifact',
        outputs_key_field=['job_id', 'artifact_path_suffix'],
        readable_output=human_readable,
        outputs=outputs,
        raw_response=response
    )


def gitlab_trigger_pipeline_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Triggers a GitLab pipeline on a selected project and branch.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (dict) XSOAR arguments:
            - 'project_id': Project ID on which to run the pipeline.
            - 'ref_branch': The branch on which to run the pipeline. Default is 'master'

    Returns:
        (CommandResults).
    """
    project_id = args.get('project_id') or client.project_id
    if not client.trigger_token:
        return_error("A trigger token is required in the integration instance configuration")
    data = {
        'token': client.trigger_token,
        'ref': args.get('ref_branch', 'master'),
    }
    for key, value in json.loads(args.get('trigger_variables', '{}')).items():
        data[f'variables[{key}]'] = value

    response = client.gitlab_trigger_pipeline(project_id, data)

    outputs = {k: v for k, v in response.items() if k in PIPELINE_FIELDS_TO_EXTRACT}
    human_readable = tableToMarkdown('GitLab Pipeline', outputs, removeNull=True)

    return CommandResults(
        outputs_prefix='GitLab.Pipeline',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response,
        readable_output=human_readable
    )


def gitlab_cancel_pipeline_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Cancels a GitLab pipeline.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (dict) XSOAR arguments:
            - 'project_id': Project ID on which to cancel the pipeline.
            - 'pipeline_id': The pipline ID to cancel.

    Returns:
        (CommandResults).
    """
    project_id = args.get('project_id') or client.project_id
    if not (pipeline_id := args.get('pipeline_id', '')):
        return_error("The pipline id is required in order to cancel it")

    response = client.gitlab_cancel_pipeline(project_id, pipeline_id)

    outputs = {k: v for k, v in response.items() if k in PIPELINE_FIELDS_TO_EXTRACT}
    human_readable = tableToMarkdown('GitLab Pipeline', outputs, removeNull=True)

    return CommandResults(
        outputs_prefix='GitLab.Pipeline',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response,
        readable_output=human_readable
    )


def check_for_html_in_error(e: str):
    """
    Args:
        e(str): The string of the error
    Returns:
        True if an html doc was retured in the error message.
        else Flse
    """
    match = re.search(r'<!DOCTYPE html>', e)
    return bool(match)


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    headers = {}
    headers['PRIVATE-TOKEN'] = params.get('credentials', {}).get('password')
    LOG(f'Command being called is {command}')
    server_url = params.get('url', '')
    project_id = arg_to_number(params.get('project_id'), required=True)
    trigger_token = params.get('trigger_token', {}).get('password')
    commands = {'gitlab-group-project-list': group_project_list_command,
                'gitlab-issue-create': create_issue_command,
                'gitlab-branch-create': branch_create_command,
                'gitlab-branch-delete': branch_delete_command,
                'gitlab-merged-branch-delete': merged_branch_delete_command,
                'gitlab-raw-file-get': get_raw_file_command,
                'gitlab-project-list': get_project_list_command,
                'gitlab-version-get': version_get_command,
                'gitlab-issue-list': issue_list_command,
                'gitlab-file-get': file_get_command,
                'gitlab-commit-list': commit_list_command,
                'gitlab-branch-list': branch_list_command,
                'gitlab-group-list': group_list_command,
                'gitlab-issue-update': issue_update_command,
                'gitlab-merge-request-list': merge_request_list_command,
                'gitlab-issue-note-list': issue_note_list_command,
                'gitlab-issue-note-create': issue_note_create_command,
                'gitlab-issue-note-delete': issue_note_delete_command,
                'gitlab-issue-note-update': issue_note_update_command,
                'gitlab-merge-request-create': merge_request_create_command,
                'gitlab-merge-request-update': merge_request_update_command,
                'gitlab-merge-request-note-create': merge_request_note_create_command,
                'gitlab-merge-request-note-list': merge_request_note_list_command,
                'gitlab-merge-request-note-update': merge_request_note_update_command,
                'gitlab-merge-request-note-delete': merge_request_note_delete_command,
                'gitlab-group-member-list': group_member_list_command,
                'gitlab-file-create': file_create_command,
                'gitlab-file-update': file_update_command,
                'gitlab-file-delete': file_delete_command,
                'gitlab-code-search': code_search_command,
                'gitlab-project-user-list': project_user_list_command,
                'gitlab-pipelines-list': gitlab_pipelines_list_command,
                'gitlab-pipelines-schedules-list': gitlab_pipelines_schedules_list_command,
                'gitlab-jobs-list': gitlab_jobs_list_command,
                'gitlab-artifact-get': gitlab_artifact_get_command,
                'gitlab-trigger-pipeline': gitlab_trigger_pipeline_command,
                'gitlab-cancel-pipeline': gitlab_cancel_pipeline_command,
                }

    try:
        client = Client(project_id, urljoin(server_url, ""), verify_certificate, proxy, headers, trigger_token)
        if project_id and verify_project_id(client, project_id):
            if demisto.command() == 'test-module':
                return_results(test_module(client))

            elif demisto.command() in commands:
                return_results(commands[demisto.command()](client, demisto.args()))

    except Exception as e:
        error_message = str(e)
        if check_for_html_in_error(error_message):
            error_message = 'Try checking your Sever Url integration parameter (e.g. base_path_to_your_gitlab/api/v4).'
        return_error(
            f'Failed to execute {demisto.command()} command. Error: {error_message}'
        )


''' ENTRY POINT '''


if __name__ in ("builtins", "__builtin__", "__main__"):
    main()
