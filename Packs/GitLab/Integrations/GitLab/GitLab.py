import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Dict, Any, List

'''--------------------- CLIENT CLASS --------------------'''


class Client(BaseClient):
    def __init__(self, project_id, base_url, verify, proxy, headers):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)
        self.project_id = project_id

    def group_projects_list_request(self, per_page: int, page: int, group_id: int) -> dict:
        headers = self._headers
        suffix = f'/groups/{group_id}/projects'
        params = assign_params(per_page=per_page, page=page)
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
        self._http_request('DELETE', f'projects/{self.project_id}/repository/branches/{branch}', headers=headers,
                           resp_type='text', ok_codes=[200, 202, 204])
        response = {
            'message': f'Branch \'{branch}\' is deleted.',
        }
        return response

    def delete_merged_branches_request(self) -> dict:
        headers = self._headers
        response = self._http_request('DELETE', f'/projects/{self.project_id}/repository/merged_branches', headers=headers,
                                      ok_codes=[200, 202, 204])
        return response

    def get_raw_file_request(self, file_path: str, ref: str) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/repository/files/{file_path}/raw'
        params = {'ref': ref}
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202], resp_type='text')
        return response

    def get_project_list_request(self, per_page: int, page: int, membership: str | None,
                                 order_by: str | None, owned: str | None, search: str | None,
                                 sort: str | None, visibility: str | None, with_issues_enabled: str | None,
                                 with_merge_requests_enabled: str | None) -> dict:
        headers = self._headers
        suffix = '/projects'
        params = assign_params(membership=membership, order_by=order_by,
                               owned=owned, search=search, sort=sort,
                               visibility=visibility, with_issues_enabled=with_issues_enabled,
                               with_merge_requests_enabled=with_merge_requests_enabled,
                               per_page=per_page, page=page)

        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202])
        return response

    def issue_list_request(self, per_page: int, page: int, assignee_id: str | None, assignee_username: str | None,
                           author_id: str | None, author_username: str | None, confidential: str | None,
                           created_after: str | None, created_before: str | None, due_date: str | None,
                           epic_id: str | None, issue_type: str | None, content: str | None, labels: str | None,
                           milestone: str | None, order_by: str | None, scope: str | None, search: str | None,
                           sort: str | None, state: str | None, updated_after: str | None,
                           updated_before: str | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/issues'
        params = assign_params(assignee_id=assignee_id, assignee_username=assignee_username,
                               author_id=author_id, author_username=author_username,
                               confidential=confidential, created_after=created_after,
                               created_before=created_before, due_date=due_date,
                               epic_id=epic_id, issue_type=issue_type, content=content,
                               labels=labels, milestone=milestone, order_by=order_by,
                               scope=scope, search=search, sort=sort, state=state,
                               updated_after=updated_after, updated_before=updated_before,
                               per_page=per_page, page=page)
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202])
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

    def commit_single_request(self, commit_id) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/repository/commits/{commit_id}'
        response = self._http_request('GET', suffix, headers=headers, ok_codes=[200, 202], resp_type='json')
        return response

    def commit_list_request(self, per_page: int, page: int,
                            ref_name: str | None, created_before: str | None, created_after: str | None,
                            path: str | None, with_stats: str | None, first_parent: str | None,
                            order: str | None, all: str | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/repository/commits'
        params = assign_params(ref_name=ref_name,
                               created_before=created_before, created_after=created_after,
                               path=path, all=all,
                               with_stats=with_stats, first_parent=first_parent, order=order,
                               per_page=per_page, page=page)
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202], resp_type='json')
        return response

    def branch_single_request(self, branch_name: str) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/repository/branches/{branch_name}'
        response = self._http_request('GET', suffix, headers=headers, ok_codes=[200, 202], resp_type='json')
        return response

    def branch_list_request(self, per_page: int, page: int, search: str | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/repository/branches'
        params = assign_params(search=search, per_page=per_page, page=page)
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202], resp_type='json')
        return response

    def group_list_request(self, per_page: int, page: int, skip_groups: str | None,
                           all_available: str | None, search: str | None, order_by: str | None,
                           sort: str | None, owned: str | None, min_access_level: str | None,
                           top_level_only: str | None) -> dict:
        headers = self._headers
        suffix = '/groups'
        params = assign_params(skip_groups=skip_groups, all_available=all_available,
                               search=search, order_by=order_by, sort=sort, owned=owned,
                               min_access_level=min_access_level, top_level_only=top_level_only,
                               per_page=per_page, page=page)
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202], resp_type='json')
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

    def issue_note_list_request(self, per_page: int, page: int, issue_iid: str | None,
                                sort: str | None, order_by: str | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/issues/{issue_iid}/notes'
        params = assign_params(per_page=per_page, page=page, sort=sort, order_by=order_by)
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202])
        return response

    def merge_request_list_request(self, per_page: int, page: int, state: str | None, order_by: str | None,
                                   sort: str | None, milestone: str | None, labels: str | None, created_after: str | None,
                                   created_before: str | None, updated_after: str | None, updated_before: str | None,
                                   scope: str | None, author_id: str | None, author_username: str | None, reviewer_id: str | None,
                                   assignee_id: str | None, reviewer_username: str | None, target_branch: str | None,
                                   source_branch: str | None, search: str | None) -> dict:
        headers = self._headers
        params = assign_params(state=state, order_by=order_by,
                               sort=sort, milestone=milestone, labels=labels,
                               created_after=created_after, created_before=created_before,
                               updated_after=updated_after, updated_before=updated_before,
                               scope=scope, author_id=author_id,
                               author_username=author_username, assignee_id=assignee_id,
                               reviewer_id=reviewer_id, reviewer_username=reviewer_username,
                               source_branch=source_branch, target_branch=target_branch,
                               search=search, per_page=per_page, page=page)
        suffix = f'/projects/{self.project_id}/merge_requests'
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202], resp_type='json')
        return response

    def merge_request_create_request(self, optional_args: dict, source_branch: str | None, target_branch: str | None,
                                     title: str | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/merge_requests'
        params = assign_params(assignee_ids=optional_args.get('assignee_ids'), reviewer_ids=optional_args.get('reviewer_ids'),
                               description=optional_args.get('description'),
                               target_project_id=optional_args.get('target_project_id'),
                               labels=optional_args.get('labels'),
                               milestone_id=optional_args.get('milestone_id'),
                               remove_source_branch=optional_args.get('remove_source_branch'),
                               allow_collaboration=optional_args.get('allow_collaboration'),
                               allow_maintainer_to_push=optional_args.get('allow_maintainer_to_push'),
                               approvals_before_merge=optional_args.get('approvals_before_merge'),
                               squash=optional_args.get('squash'))
        data = assign_params(source_branch=source_branch, target_branch=target_branch, title=title)
        response = self._http_request('POST', suffix, headers=headers, json_data=data, params=params, ok_codes=[201])
        return response

    def merge_request_update_request(self, optional_args: dict, merge_request_id: int,
                                     target_branch: str | None, title: str | None) -> dict:
        headers = self._headers
        suffix = f'/projects/{self.project_id}/merge_requests/{merge_request_id}'
        params = assign_params(assignee_ids=optional_args.get('assignee_ids'), reviewer_ids=optional_args.get('reviewer_ids'),
                               description=optional_args.get('description'),
                               target_project_id=optional_args.get('target_project_id'),
                               remove_labels=optional_args.get('remove_labels'),
                               milestone_id=optional_args.get('milestone_id'), state_event=optional_args.get('state_event'),
                               remove_source_branch=optional_args.get('remove_source_branch'),
                               allow_collaboration=optional_args.get('allow_collaboration'),
                               allow_maintainer_to_push=optional_args.get('allow_maintainer_to_push'),
                               approvals_before_merge=optional_args.get('approvals_before_merge'),
                               squash=optional_args.get('squash'), discussion_locked=optional_args.get('discussion_locked'))
        data = assign_params(target_branch=target_branch, title=title)
        response = self._http_request('PUT', suffix, headers=headers, json_data=data, params=params, ok_codes=[200, 202])
        return response

    def merge_request_note_list_request(self, args: dict, per_page: int, page: int) -> dict:
        headers = self._headers
        merge_request_iid = args.get('merge_request_iid')
        sort = args.get('sort')
        order_by = args.get('order_by')
        params = assign_params(sort=sort, per_page=per_page, page=page, order_by=order_by)
        suffix = f'/projects/{self.project_id}/merge_requests/{merge_request_iid}/notes'
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202])
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

    def group_member_list_request(self, group_id: int | Any) -> dict:
        headers = self._headers
        suffix = f'/groups/{group_id}/members'
        response = self._http_request('GET', suffix, headers=headers, ok_codes=[200, 202])
        return response

    def codes_search_request(self, args: dict, per_page: int, page: int) -> dict:
        headers = self._headers
        search = args.get('search')
        params = assign_params(search=search, scope='blobs', page=page, per_page=per_page)
        suffix = f'/projects/{self.project_id}/search'
        response = self._http_request('GET', suffix, headers=headers, params=params, ok_codes=[200, 202])
        return response


''' HELPER FUNCTIONS '''


def get_branch_details(branch: dict) -> dict:
    '''
    This function return branch details according to the human_readable desgin.
    input: a dict of project as return after a request
    output: Dict with the feilds: Title ,CommitShortId ,CommitTitle ,CreatedAt ,IsMerge, IsProtected
    '''
    branch_after_edit = {'Title': branch.get('name'),
                         'IsMerge': branch.get('merged'),
                         'IsProtected': branch.get('protected')}
    if branch.get('commit'):
        branch_after_edit['CommitShortId'] = branch['commit'].get('short_id'),
        branch_after_edit['CommitTitle'] = branch['commit'].get('title'),
    return branch_after_edit


def check_args_for_update(args: dict, optinal_params: list) -> dict:
    '''
    This function checks that at least one argument from optinal params is in args.
    input: optinal params, args from user.
    output: if there isn't at least one argument then throw an exception.
            otherwise- dict of params for update and True boolean argument.
    '''
    params, args_valid = {}, False
    for optinal_param in optinal_params:
        if args.get(optinal_param):
            params[optinal_param] = args.get(optinal_param)
            args_valid = True
    if not args_valid:
        raise DemistoException('At least one of arguments is required for the'
                               ' request to be successful\n')
    return params


def validate_pagination_values(args) -> tuple[int, int, int]:
    per_page = int(args.get('per_page', '50'))
    page_number = int(args.get('page', '1'))
    limit = int(args.get('limit', '50'))
    if limit < 0 or page_number < 0:
        raise DemistoException('Pagination values must be positive')

    if limit < 100:
        per_page = limit

    else:
        per_page = 100

    return limit, per_page, page_number


def response_according_pagination(client_function, args) -> List[Any]:
    '''
    This function gets results accoring to the pagination values.
    input: The arguments needed to call the function,general args to extract pagination args and the name of the client function.
    output: list(representing the pages) of list of raw dictonary results.
    '''
    per_page, limit, page_number = validate_pagination_values(args)
    items_count_total, page, response = 0, page_number, []
    while items_count_total < limit:
        response_temp = client_function(args, per_page, page)
        if not response_temp:
            break
        response.extend(response_temp)
        items_count_total += len(response_temp)
        page += 1
    return response


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


def group_project_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Returns a list of projects within a group.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'group_id' (Required): group ID to retrieve the projects from.
    Returns:
        (CommandResults).
    """
    response_to_hr, headers, human_readable = [], ['Id', 'Name', 'Description', 'Path'], ''
    per_page, limit, page = validate_pagination_values(args)
    items_count_total = 0
    group_id = args.get('group_id', '')
    response: List[Dict[str, Any]] = []
    while items_count_total < limit:
        response_temp = client.group_projects_list_request(per_page, page, group_id)
        if not response_temp:
            break
        response.extend(response_temp)
        items_count_total += len(response_temp)
        page += 1

    for project in response:
        response_to_hr.append({'Id': project.get('id'),
                               'Name': project.get('name'),
                               'Description': project.get('description'),
                               'Path': project.get('path')})
    human_readable = tableToMarkdown('List Group Projects', response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.GroupProject',
        outputs_key_field='id',
        readable_output=human_readable,
        outputs=response,
        raw_response=response
    )


def get_project_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Returns a list of projects.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
    Returns:
        (CommandResults).
    """
    response_to_hr, headers, human_readable = [], ['Id', 'Name', 'Description', 'Path'], ''
    per_page, limit, page = validate_pagination_values(args)
    items_count_total = 0
    membership = args.get('membership')
    order_by = args.get('order_by')
    owned = args.get('owned')
    search = args.get('search')
    sort = args.get('sort')
    visibility = args.get('visibility')
    with_issues_enabled = args.get('with_issues_enabled')
    with_merge_requests_enabled = args.get('with_merge_requests_enabled')
    response: List[Dict[str, Any]] = []
    while items_count_total < limit:
        response_temp = client.get_project_list_request(per_page, page, membership, order_by, owned, search,
                                                        sort, visibility, with_issues_enabled, with_merge_requests_enabled)
        if not response_temp:
            break
        response.extend(response_temp)
        items_count_total += len(response_temp)
        page += 1

    for project in response:
        response_to_hr.append({'Id': project.get('id'),
                               'Name': project.get('name'),
                               'Description': project.get('description'),
                               'Path': project.get('path')})
    human_readable = tableToMarkdown('List Projects', response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.Project',
        outputs_key_field='id',
        readable_output=human_readable,
        outputs=response,
        raw_response=response
    )


def issue_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Returns a list of issues within the project.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:PRIVATE-TOKEN
    Returns:
        (CommandResults).
    """
    response_to_hr, human_readable = [], ''
    headers = ['Id', 'Issue_id', 'Title', 'CreatedAt', 'CreatedBy', 'UpdatedAt', 'Milstone', 'State', ' Assignee']
    per_page, limit, page = validate_pagination_values(args)
    items_count_total = 0
    assignee_id = args.get('assignee_id')
    assignee_username = args.get('assignee_username')
    author_id = args.get('author_id')
    author_username = args.get('author_username')
    confidential = args.get('confidential')
    created_after = args.get('created_after')
    created_before = args.get('created_before')
    due_date = args.get('due_date')
    epic_id = args.get('epic_id')
    issue_type = args.get('issue_type')
    content = args.get('content')
    labels = args.get('labels')
    milestone = args.get('milestone')
    order_by = args.get('order_by')
    scope = args.get('scope')
    search = args.get('search')
    sort = args.get('sort')
    state = args.get('state')
    updated_after = args.get('updated_after')
    updated_before = args.get('updated_before')
    response: List[Dict[str, Any]] = []

    while items_count_total < limit:
        response_temp = client.issue_list_request(per_page, page, assignee_id, assignee_username,
                                                  author_id, author_username, confidential,
                                                  created_after, created_before, due_date,
                                                  epic_id, issue_type, content, labels, milestone,
                                                  order_by, scope, search, sort, state,
                                                  updated_after, updated_before)
        if not response_temp:
            break
        response.extend(response_temp)
        items_count_total += len(response_temp)
        page += 1

    for issue in response:
        issue_details = {'Id': issue.get('id'),
                         'Issue_id': issue.get('iid'),
                         'Title': issue.get('title'),
                         'CreatedAt': issue.get('created_at'),
                         'UpdateAt': issue.get('update_at'),
                         'State': issue.get('state'),
                         'CreatedBy': issue.get('author', {}).get('created_by')
                         }
        if issue.get('assignee'):
            issue_details['Assignee'] = issue.get('assignee', {}).get('name')
        if issue.get('milestone'):
            issue_details['Milestone'] = issue.get('milestone', {}).get('title')
        response_to_hr.append(issue_details)
    human_readable = tableToMarkdown('List Issues', response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.Issue',
        outputs_key_field='id',
        readable_output=human_readable,
        outputs=response,
        raw_response=response
    )


def create_issue_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Creates an issue.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'state': The state of the issue.
            - 'labels': Retrieve only issues with the given labels.
            - 'assignee_username': Retrieve issues by assignee username.

    Returns:
        (CommandResults).
    """
    labels = args.get('labels', '')
    headers = ['Iid', 'Title', 'CreatedAt', 'CreatedBy', 'UpdatedAt', 'Milstone', 'State', 'Assignee']
    title = args.get('title', '')
    description = args.get('description', '')
    response = client.create_issue_request(labels, title, description)
    human_readable_dict = {
        'Iid': response.get('iid'),
        'Title': response.get('title'),
        'CreatedAt': response.get('created_at', ''),
        'CreatedBy': response.get('autor.name', ''),
        'UpdatedAt': response.get('updated_at', ''),
        'Milstone': response.get('milestone.title', ''),
        'State': response.get('state', ''),
        'Assignee': response.get('assignee.name', '')
    }
    human_readable = tableToMarkdown('Created Issue', human_readable_dict, headers=headers, removeNull=True)
    return CommandResults(
        outputs_prefix='GitLab.Issue',
        outputs_key_field='Iid',
        readable_output=human_readable,
        outputs=response,
        raw_response=response
    )


def branch_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    human_readable = tableToMarkdown('Create Branch', human_readable_dict, headers=headers)
    command_results = CommandResults(
        outputs_prefix='GitLab.Branch',
        outputs_key_field='CommitShortId',
        readable_output=human_readable,
        outputs=response,
        raw_response=response
    )
    return command_results


def branch_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    branch = str(args.get('branch', ''))
    response = client.branch_delete_request(branch)
    human_readable_string = 'Branch deleted successfully'
    command_results = CommandResults(
        readable_output=human_readable_string,
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def merged_branch_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    response = client.delete_merged_branches_request()
    human_readable_string = f'Deleation Result:\n {response}'
    command_results = CommandResults(
        readable_output=human_readable_string,
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )
    return command_results


def get_raw_file_command(client: Client, args: Dict[str, Any]) -> List:
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
    headers = ['path', 'refrence', 'content']
    response = client.get_raw_file_request(file_path, ref)
    file_ = response
    outputs = {'path': file_path, 'content': response, 'ref': ref}
    human_readable = tableToMarkdown(f'Raw file {file_path} on branch {ref}', outputs, headers=headers)
    file_name = file_path.split('/')[-1]
    file_ = fileResult(filename=file_name, data=response, file_type=EntryType.ENTRY_INFO_FILE)
    results = CommandResults(
        outputs_prefix='GitLab.File',
        readable_output=human_readable,
        outputs=outputs,
        raw_response=response
    )
    return [results, file_]


def issue_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    updating an issue.
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
    params_optional = ['add_labels', 'assignee_ids', 'confidential', 'description', 'discussion_locked',
                       'due_date', 'epic_id', 'epic_iid', 'issue_type', 'milestone_id', 'remove_labels',
                       'state_event', 'title']
    headers = ['Iid', 'Title', 'CreatedAt', 'CreatedBy', 'UpdatedAt', 'Milstone', 'State', 'Assignee']
    params = check_args_for_update(args, params_optional)
    response = client.issue_update_request(issue_iid, params)
    human_readable_dict = {'Iid': response.get('iid', ''),
                           'Title': response.get('title', ''),
                           'CreatedAt': response.get('created_at', ''),
                           'UpdatedAt': response.get('updated_at', ''),
                           'State': response.get('state', ''),
                           'Assignee': response.get('assignee', ''),
                           'CreatedBy': response.get('author', {}).get('name', '')}
    if response.get('author'):
        human_readable_dict['CreatedBy'] = response['author'].get('name', '')
    if response.get('milestone'):
        human_readable_dict['Milstone'] = response['milestone'].get('title', '')
    human_readable = tableToMarkdown('Update Issue', human_readable_dict, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.Issue',
        outputs_key_field='Iid',
        readable_output=human_readable,
        outputs=response,
        raw_response=response
    )


def version_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    human_readable_string = f'GitLab version {version}\n reversion: {revision} '
    command_results = CommandResults(
        outputs_prefix='GitLab.Version',
        readable_output=human_readable_string,
        outputs_key_field='revision',
        outputs=response,
        raw_response=response
    )

    return command_results


def file_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    response = client.file_get_request(file_path, branch)
    human_readable_dict = {'FileName': response.get('file_name', ''),
                           'FilePath': response.get('file_path', ''),
                           'Ref': response.get('ref'),
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


def file_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    if not entry_id and not file_content:
        raise DemistoException('You must specify either the "file_content" or the "entry_id" of the file.')
    elif entry_id:
        file_path_entry_id = demisto.getFilePath(entry_id).get('path')
        with open(file_path_entry_id, 'rb') as f:
            file_content = f.read()
    else:
        file_content = bytes(file_content, encoding='utf8')
    response = client.file_create_request(file_path, branch, commit_msg, author_email, author_name,
                                          file_content, execute_filemode)
    human_readable_string = 'File created successfully'
    return CommandResults(
        outputs_prefix='GitLab.File',
        readable_output=human_readable_string,
        outputs=response,
        raw_response=response
    )


def file_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    updating a file.
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
    encoding = args.get('endcoding')
    author_email = args.get('author_email')
    author_name = args.get('author_name')
    commit_message = args.get('commit_message')
    last_commit_id = args.get('last_commit_id')
    execute_filemode = args.get('execute_filemode')
    if not entry_id and not file_content:
        raise DemistoException('You must specify either the "file_text" or the "entry_id" of the file.')
    elif entry_id:
        file_path_entry_id = demisto.getFilePath(entry_id).get('path')
        with open(file_path_entry_id, 'rb') as f:
            file_content = f.read()
    else:
        file_content = bytes(file_content, encoding='utf8')
    response = client.file_update_request(file_path, branch, start_branch, encoding, author_email, author_name, commit_message,
                                          last_commit_id, execute_filemode, file_content)

    human_readable_str = 'File updated successfully'
    return CommandResults(
        outputs_prefix='GitLab.File',
        readable_output=human_readable_str,
        outputs=response,
        raw_response=response
    )


def file_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    human_readable_string = 'File deleted successfully'
    command_results = CommandResults(
        outputs_prefix='GitLab.File',
        readable_output=human_readable_string,
        outputs=response,
        raw_response=response
    )

    return command_results


def commit_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
        per_page, limit, page = validate_pagination_values(args)
        items_count_total, response = 0, []
        ref_name = args.get('ref_name')
        created_before = args.get('created_before')
        created_after = args.get('created_after')
        path = args.get('path')
        with_stats = args.get('with_stats')
        first_parent = args.get('first_parent')
        order = args.get('order')
        all_ = args.get('all')
        while items_count_total < limit:
            response_temp = client.commit_list_request(per_page, page, ref_name, created_before,
                                                       created_after, path, with_stats, first_parent, order, all_)
            if not response_temp:
                break
            response.extend(response_temp)
            items_count_total += len(response_temp)
            page += 1
    for commit in response:
        response_to_hr.append({'Title': commit.get('name', ''),
                               'Message': commit.get('message', ''),
                               'ShortId': commit.get('short_id', ''),
                               'Author': commit.get('author_name', ''),
                               'CreatedAt': commit.get('committed_date', '')})
    human_readable = tableToMarkdown(response_title, response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.Commit',
        outputs_key_field='ShortId',
        readable_output=human_readable,
        outputs=response,
        raw_response=response
    )


def branch_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
        per_page, limit, page = validate_pagination_values(args)
        items_count_total, response = 0, []
        search = args.get('search')
        while items_count_total < limit:
            response_temp = client.branch_list_request(per_page, page, search)
            if not response_temp:
                break
            response.extend(response_temp)
            items_count_total += len(response_temp)
            page += 1

    for branch in response:
        response_to_hr.append({'Title': branch.get('name'),
                               'IsMerge': branch.get('merged'),
                               'IsProtected': branch.get('protected'),
                               'CommitShortId': branch.get('commit', {}).get('short_id', ''),
                               'CommitTitle': branch.get('commit', {}).get('title', '')})

    human_readable = tableToMarkdown(response_title, response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.Branch',
        outputs_key_field='ShortId',
        readable_output=human_readable,
        outputs=response,
        raw_response=response
    )


def group_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Returns a list of visible groups for the authenticated user.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments
    Returns:
        (CommandResults).
    """
    response_to_hr, human_readable, response_title = [], '', 'List Group'
    headers = ['Id', 'Name', 'Path', 'Description', 'CreatedAt', 'Visibility']
    per_page, limit, page = validate_pagination_values(args)
    items_count_total = 0
    response: List[Dict[str, Any]] = []
    skip_groups = args.get('skip_groups')
    all_available = args.get('all_available')
    search = args.get('search')
    order_by = args.get('order_by')
    sort = args.get('sort')
    owned = args.get('owned')
    min_access_level = args.get('min_access_level')
    top_level_only = args.get('top_level_only')
    while items_count_total < limit:
        response_temp = client.group_list_request(per_page, page, skip_groups, all_available, search, order_by,
                                                  sort, owned, min_access_level, top_level_only)
        if not response_temp:
            break
        response.extend(response_temp)
        items_count_total += len(response_temp)
        page += 1
    for group in response:
        response_to_hr.append({'Id': group.get('id'),
                               'Name': group.get('name'),
                               'Path': group.get('path'),
                               'Description': group.get('descrition', ''),
                               'CreatedAt': group.get('created_at', ''),
                               'Visibility': group.get('visibility', '')})
    human_readable = tableToMarkdown(response_title, response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.Group',
        outputs_key_field='Id',
        readable_output=human_readable,
        outputs=response,
        raw_response=response
    )


def issue_note_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    human_readable_str = 'Issue note created successfully'
    return CommandResults(
        outputs_prefix='GitLab.IssueNote',
        readable_output=human_readable_str,
        outputs=response,
        raw_response=response
    )


def issue_note_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    deletes an issue note.
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
    human_readable_str = 'Issue note deleted successfully'
    return CommandResults(
        readable_output=human_readable_str
    )


def issue_note_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    updating an issue note.
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
    if not issue_iid or not note_id or not body:
        raise DemistoException('You must specify the "issue_iid" and the "note_id" and the updated body of the file.')
    response = client.issue_note_update_request(issue_iid, note_id, body)
    human_readable_str = 'Issue note updated was updated successfully.'
    return CommandResults(
        outputs_prefix='GitLab.IssueNote',
        outputs_key_field='issue_id',
        readable_output=human_readable_str,
        outputs=response,
        raw_response=response
    )


def issue_note_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    per_page, limit, page = validate_pagination_values(args)
    items_count_total = 0
    response: List[Dict[str, Any]] = []
    issue_iid = args.get('issue_iid')
    sort = args.get('sort')
    order_by = args.get('order_by')
    while items_count_total < limit:
        response_temp = client.issue_note_list_request(per_page, page, issue_iid, sort, order_by)
        if not response_temp:
            break
        response.extend(response_temp)
        items_count_total += len(response_temp)
        page += 1

    for issue_note in response:
        issue_note_edit = {'Id': issue_note.get('id'),
                           'Text': issue_note.get('body', ''),
                           'Autor': issue_note.get('author', {}).get('name', ''),
                           'UpdatedAt': issue_note.get('updated_at', ''),
                           'CreatedAt': issue_note.get('created_at', ''),
                           }
        response_to_hr.append(issue_note_edit)
    human_readable = tableToMarkdown('List Issue notes', response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.IssueNote',
        outputs_key_field='Id',
        readable_output=human_readable,
        outputs=response,
        raw_response=response
    )


def merge_request_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    per_page, limit, page = validate_pagination_values(args)
    items_count_total = 0
    response: List[Dict[str, Any]] = []
    state = args.get('state')
    order_by = args.get('order_by')
    sort = args.get('sort')
    milestone = args.get('milestone')
    labels = args.get('labels')
    created_after = args.get('created_after')
    created_before = args.get('created_before)')
    updated_after = args.get('updated_after')
    updated_before = args.get('updated_before)')
    scope = args.get('scope')
    author_id = args.get('author_id')
    author_username = args.get('author_username')
    assignee_id = args.get('assignee_id')
    reviewer_id = args.get('reviewer_id')
    reviewer_username = args.get('reviewer_username')
    source_branch = args.get('source_branch')
    target_branch = args.get('target_branch')
    search = args.get('search')
    while items_count_total < limit:
        response_temp = client.merge_request_list_request(per_page, page, state, order_by, sort, milestone, labels,
                                                          created_after, created_before, updated_after,
                                                          updated_before, scope, author_id, author_username, reviewer_id,
                                                          assignee_id, reviewer_username, target_branch, source_branch, search)
        if not response_temp:
            break
        response.extend(response_temp)
        items_count_total += len(response_temp)
        page += 1
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

    human_readable = tableToMarkdown('List Merge requests', response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.MergeRequest',
        outputs_key_field='Iid',
        readable_output=human_readable,
        outputs=response,
        raw_response=response
    )


def merge_request_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Creates an merge request note.
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
    response = client.merge_request_create_request(args, source_branch, target_branch, title)
    merge_request_iid = response.get('iid')
    human_readable_str = f'Merge request created successfully with merge_request_iid:\n{merge_request_iid}'
    return CommandResults(
        outputs_prefix='GitLab.MergeRequest',
        readable_output=human_readable_str,
        outputs=response,
        raw_response=response
    )


def merge_request_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    updating an merge request.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments:
            - 'state': The state of the issue.
            - 'labels': Retrieve only issues with the given labels.
            - 'assignee_username': Retrieve issues by assignee username.

    Returns:
        (CommandResults).
    """
    merge_request_id = args.get('merge_request_id')
    target_branch = args.get('target_branch')
    title = args.get('title')
    if not merge_request_id or not target_branch or not title:
        raise DemistoException('You must specify the "merge_request_id" and the "target_branch" and "title" of the file.')
    response = client.merge_request_update_request(args, merge_request_id, target_branch, title)
    human_readable_str = f'Merge request number {merge_request_id} was updated successfully.'
    return CommandResults(
        outputs_prefix='GitLab.MergeRequest',
        outputs_key_field='merge_request_id',
        readable_output=human_readable_str,
        outputs=response,
        raw_response=response
    )


def merge_request_note_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Returns a list of merge request's notes.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments
    Returns:
        (CommandResults).
    """
    if not args.get('merge_request_iid'):
        raise DemistoException('You must specify the "merge_request_iid"')
    response_to_hr = []
    headers = ['Id', 'Author', 'Text', 'CreatedAt', 'UpdatedAt']
    response = response_according_pagination(client.merge_request_note_list_request, args)
    for merge_request_note in response:
        merge_request_note_edit = {'Id': merge_request_note.get('id', ''),
                                   'Text': merge_request_note.get('body', ''),
                                   'UpdatedAt': merge_request_note.get('updated_at', ''),
                                   'CreatedAt': merge_request_note.get('created_at', '')}
        if merge_request_note.get('author'):
            merge_request_note_edit['Autor'] = merge_request_note['author'].get('name', '')
        response_to_hr.append(merge_request_note_edit)
    human_readable = tableToMarkdown('List Merge Issue Notes', response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.MergeRequestNote',
        outputs_key_field='Id',
        readable_output=human_readable,
        outputs=response,
        raw_response=response
    )


def merge_request_note_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Creates an merge request note.
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
    human_readable_str = 'Merge request note created successfully.'
    return CommandResults(
        outputs_prefix='GitLab.MergeRequestNote',
        outputs_key_field='Id',
        readable_output=human_readable_str,
        outputs=response,
        raw_response=response
    )


def merge_request_note_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    updating an merge request note.
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
    human_readable_str = 'Merge request note was updated successfully'
    return CommandResults(
        outputs_prefix='GitLab.MergeRequestNote',
        outputs_key_field='Id',
        readable_output=human_readable_str,
        outputs=response,
        raw_response=response
    )


def merge_request_note_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    deletes an issue note.
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
    human_readable_str = 'Merge request note deleted successfully'
    return CommandResults(
        readable_output=human_readable_str
    )


def group_member_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    human_readable = tableToMarkdown('List Group Member', response_to_hr, removeNull=True, headers=headers)
    return CommandResults(
        outputs_prefix='GitLab.GroupMember',
        outputs_key_field='Id',
        readable_output=human_readable,
        outputs=response,
        raw_response=response
    )


def code_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Returns a results of code search.
    Args:
        client (Client): Client to perform calls to GitLab services.
        args (Dict[str, Any]): XSOAR arguments
    Returns:
        (CommandResults).
    """
    response = response_according_pagination(client.codes_search_request, args)
    return CommandResults(
        outputs_prefix='GitLab.Code',
        # readable_output=response,
        outputs=response,
        raw_response=response
    )


''' MAIN FUNCTION '''


def main() -> None:
    command = demisto.command()
    params = demisto.params()
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    headers = {}
    headers['PRIVATE-TOKEN'] = params.get('credentials', {}).get('password')
    LOG(f'Command being called is {command}')
    server_url = params.get('url', '')
    project_id = params.get('project_id')
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
                'gitlab-code-search': code_search_command
                }

    try:
        client = Client(project_id, urljoin(server_url, ""), verify_certificate, proxy, headers=headers)

        if demisto.command() == 'test-module':
            return_results(test_module(client))

        elif demisto.command() in commands:
            return_results(commands[demisto.command()](client, demisto.args()))

    except Exception as e:
        return_error(
            f'Failed to execute {demisto.command()} command. Error: {str(e)}'
        )


''' ENTRY POINT '''


if __name__ in ("builtins", "__builtin__", "__main__"):
    main()
