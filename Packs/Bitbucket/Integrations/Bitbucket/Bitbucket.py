"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""
import json

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
from typing import Dict, Any, Tuple

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, workspace: str, server_url: str, auth: tuple, repository: str,
                 proxy: bool = False, verify: bool = True):
        self.repository = repository
        self.workspace = workspace
        self.serverUrl = server_url
        super().__init__(base_url=server_url, auth=auth, proxy=proxy, verify=verify)

    # TODO: Optional - add a function that prints the errors in a more human readable form

    def get_full_url(self, full_url: str, params: Dict = None) -> Dict:
        return self._http_request(method='GET', full_url=full_url, params=params)

    def check_repo(self, repo: str) -> str:
        if repo:
            return f'/repositories/{self.workspace}/{repo}'
        else:
            if not self.repository:
                raise Exception("Please provide a repository name")
            return f'/repositories/{self.workspace}/{self.repository}'

    def get_project_list_request(self, params: Dict, project_key: str = None) -> Dict:
        if not project_key:
            full_url = f'{self.serverUrl}/workspaces/{self.workspace}/projects/'
        else:
            project_key = project_key.upper()
            full_url = f'{self.serverUrl}/workspaces/{self.workspace}/projects/{project_key}'

        return self._http_request(method='GET', full_url=full_url, params=params)

    def get_open_branch_list_request(self, repo: str, params: Dict) -> Dict:
        url_suffix = self.check_repo(repo) + '/refs/branches'
        return self._http_request(method='GET', url_suffix=url_suffix, params=params)

    def get_branch_request(self, branch_name: str, repo: str = None) -> Dict:
        url_suffix = self.check_repo(repo) + f'/refs/branches/{branch_name}'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def branch_create_request(self, name: str, target_branch: str, repo: str = None) -> Dict:
        url_suffix = self.check_repo(repo) + '/refs/branches'
        body = {
            "target": {
                "hash": target_branch
            },
            "name": name
        }
        return self._http_request(method='POST', url_suffix=url_suffix, json_data=body)

    def branch_delete_request(self, branch_name: str, repo: str = None) -> str:
        url_suffix = self.check_repo(repo) + f'/refs/branches/{branch_name}'
        try:
            self._http_request(method='DELETE', url_suffix=url_suffix)
        except DemistoException as e:
            status_code = e.res.status_code
            if status_code == 204:
                return str(204)
            else:
                return e.message

    def commit_create_request(self, body: Dict, repo: str = None):
        url_suffix = self.check_repo(repo) + '/src'
        return self._http_request(method='POST',
                                  url_suffix=url_suffix,
                                  data=body,
                                  resp_type='response')

    def add_branches_url(self, action: str, l: list, url: str) -> str:
        url = url + '?'
        for branch in l:
            url = url + f'{action}={branch}&'
        return url[:-1]

    def commit_list_request(self, repo: str, params: Dict, excluded_list: list = None,
                            included_list: list = None) -> Dict:
        url_suffix = self.check_repo(repo) + '/commits'
        if excluded_list:
            url_suffix = self.add_branches_url('exclude', excluded_list, url_suffix)
        if included_list:
            url_suffix = self.add_branches_url('include', included_list, url_suffix)
        response = self._http_request(method='POST',
                                      url_suffix=url_suffix,
                                      params=params)
        return response

    def file_delete_request(self, body: Dict, repo: str = None) -> Dict:
        url_suffix = self.check_repo(repo) + '/src'
        return self._http_request(method='POST',
                                  url_suffix=url_suffix,
                                  data=body,
                                  resp_type='response')

    def raw_file_get_request(self, repo: str, file_path: str, commit_hash: str) -> Dict:
        url_suffix = self.check_repo(repo) + f'/src/{commit_hash}/{file_path}'
        return self._http_request(method='GET', url_suffix=url_suffix, resp_type='response')

    def issue_create_request(self, repo: str, body: dict) -> Dict:
        url_suffix = self.check_repo(repo) + '/issues'
        return self._http_request(method='POST', url_suffix=url_suffix, json_data=body)

    def issue_list_request(self, repo: str, params: Dict, issue_id: str) -> Dict:
        """ Makes a GET request /repositories/workspace/repository/issues/issue_id endpoint to get
            A list of all the issues or 1 issue a specific id is added to the api call.
            :param repo: str - The repository the user entered if he did.
            :param params: Dict - the params to the api call
            :param issue_id: str - an id to a specific issue to get.

            Creates the url and makes the api call
            :return JSON response from /repositories/workspace/repository/issues/issue_id endpoint
            :rtype Dict[str, Any]
        """
        url_suffix = self.check_repo(repo) + '/issues/'
        if issue_id:
            url_suffix = f'{url_suffix}{issue_id}'
        return self._http_request(method='GET', url_suffix=url_suffix, params=params)

    def issue_update_request(self, repo: str, body: dict, issue_id: int) -> Dict:
        """ Makes a PUT request /repositories/workspace/repository/issues/issue_id endpoint to update an issue.
            :param repo: str - The repository the user entered if he did.
            :param body: Dict - the params to the api call
            :param issue_id: str - an id to a specific issue to update.

            Creates the url and makes the api call
            :return JSON response from /repositories/workspace/repository/issues/issue_id endpoint
            :rtype Dict[str, Any]
        """
        url_suffix = self.check_repo(repo) + f'/issues/{issue_id}/'
        return self._http_request(method='PUT', url_suffix=url_suffix, json_data=body)

    def pull_request_create_request(self, repo: str, body: Dict) -> Dict:
        """ Makes a POST request /repositories/workspace/repository/pullrequests endpoint to create a pull request.
            :param repo: str - The repository the user entered if he did.
            :param body: Dict - the params to the api call

            Creates the url and makes the api call
            :return JSON response from /repositories/workspace/repository/pullrequests endpoint
            :rtype Dict[str, Any]
        """
        url_suffix = self.check_repo(repo) + f'/pullrequests'
        return self._http_request(method='POST', url_suffix=url_suffix, json_data=body)

    def pull_request_update_request(self, repo: str, body: Dict, pr_id: str) -> Dict:
        """ Makes a PUT request /repositories/workspace/repository/pullrequests/{pr_id} endpoint to update a pull request.
            :param repo: str - The repository the user entered if he did.
            :param body: Dict - the params to the api call
            :param pr_id: str - an id to a specific pull request to update.

            Creates the url and makes the api call
            :return JSON response from /repositories/workspace/repository/pullrequests/{pr_id} endpoint
            :rtype Dict[str, Any]
        """
        url_suffix = self.check_repo(repo) + f'/pullrequests/{pr_id}'
        return self._http_request(method='PUT', url_suffix=url_suffix, json_data=body)

    def pull_request_list_request(self, repo: str, pr_id: str, params: Dict) -> Dict:
        """ Makes a GET request to /repositories/workspace/repository/pullrequests/{pr_id} endpoint to get information
            about a specific pull request. if there isn't a pull request id, makes a GET request to
             /repositories/workspace/repository/pullrequests endpoint to get a list of pull requests.
            :param repo: str - The repository the user entered if he did.
            :param params: Dict - the params to the api call
            :param pr_id: str - an id to a specific pull request to update.

            Creates the url and makes the api call
            :return JSON response from /repositories/workspace/repository/pullrequests/{pr_id} endpoint
            :rtype Dict[str, Any]
        """
        url_suffix = self.check_repo(repo) + '/pullrequests'
        if pr_id:
            url_suffix = f'{url_suffix}/{pr_id}'
        return self._http_request(method='GET', url_suffix=url_suffix, params=params)

    def issue_comment_create_request(self, repo: str, issue_id: str, body: Dict) -> Dict:
        """ Makes a POST request /repositories/workspace/repository/issues/{issue_id}/comments endpoint to create
            a comment on an issue.
            :param repo: str - The repository the user entered if he did.
            :param body: Dict - The content of the comment, in a dictionary form.
            :param issue_id: str - an id to a specific issue to comment on.

            Creates the url and makes the api call
            :return JSON response from /repositories/workspace/repository/issues/{issue_id}/comments endpoint
            :rtype Dict[str, Any]
        """
        url_suffix = self.check_repo(repo) + f'/issues/{issue_id}/comments'
        return self._http_request(method='POST', url_suffix=url_suffix, json_data=body)

    def issue_comment_delete_request(self, repo: str, issue_id: str, comment_id: str) -> Dict:
        """ Makes a DELETE request /repositories/workspace/repository/issues/{issue_id}/comments/{comment_id} endpoint to delete
            a comment in an issue.
            :param repo: str - The repository the user entered, if he did.
            :param issue_id: str - an id to a specific issue to delete one of its comments.
            :param comment_id: str - an id of a specific comment to delete.

            Creates the url and makes the api call
            :return JSON response from /repositories/workspace/repository/issues/{issue_id}/comments/{comment_id} endpoint
            :rtype Dict[str, Any]
        """
        url_suffix = self.check_repo(repo) + f'/issues/{issue_id}/comments/{comment_id}'
        return self._http_request(method='DELETE', url_suffix=url_suffix, resp_type='response')

    def issue_comment_update_request(self, repo: str, issue_id: str, comment_id: str, body: Dict) -> Dict:
        """ Makes a PUT request /repositories/workspace/repository/issues/{issue_id}/comments/{comment_id} endpoint to
            update a comment in an issue.
            :param repo: str - The repository the user entered, if he did.
            :param issue_id: str - an id to a specific issue to update one of its comments.
            :param comment_id: str - an id of a specific comment to update.
            :param body: Dict - an id of a specific comment to update.

            Creates the url and makes the api call
            :return JSON response from /repositories/workspace/repository/issues/{issue_id}/comments/{comment_id} endpoint
            :rtype Dict[str, Any]
        """
        url_suffix = self.check_repo(repo) + f'/issues/{issue_id}/comments/{comment_id}'
        return self._http_request(method='PUT', url_suffix=url_suffix, json_data=body)

    def issue_comment_list_request(self, repo: str, issue_id: str, comment_id: str, params: Dict) -> Dict:
        """ Makes a GET request /repositories/workspace/repository/issues/{issue_id}/comments/{comment_id} endpoint to get
            information about a specific comment to an issue. if there is no comment_id than Makes a GET request
            /repositories/workspace/repository/issues/{issue_id}/comments/ to get all the comments of a specific issue.
            :param repo: str - The repository the user entered, if he did.
            :param issue_id: str - an id to a specific issue to get its comments.
            :param comment_id: str - an id of a specific comment.
            :param params: Dict - a dictionary containing the information about the pagination if needed.

            Creates the url and makes the api call
            :return JSON response from /repositories/workspace/repository/issues/{issue_id}/{comment_id} endpoint
            :rtype Dict[str, Any]
        """
        url_suffix = self.check_repo(repo) + f'/issues/{issue_id}/comments/'
        if comment_id:
            url_suffix = f'{url_suffix}{comment_id}'
        return self._http_request(method='GET', url_suffix=url_suffix, params=params)

    def pull_request_comment_create_request(self, repo: str, pr_id: int, body: Dict) -> Dict:
        """ Makes a GET request /repositories/workspace/repository/pullrequests/{pr_id}/comments endpoint to get
            information about a specific comment to an issue. if there is no comment_id than Makes a GET request
            /repositories/workspace/repository/issues/{issue_id}/comments/ to get all the comments of a specific issue.
            :param repo: str - The repository the user entered, if he did.
            :param pr_id: str - an id to a specific pull request to add a comment to.
            :param body: Dict - a dictionary containing information about the content of the comment.

            Creates the url and makes the api call
            :return JSON response from /repositories/workspace/repository/pullrequests/{pr_id}/comments endpoint
            :rtype Dict[str, Any]
        """
        url_suffix = self.check_repo(repo) + f'/pullrequests/{pr_id}/comments'
        return self._http_request(method='POST', url_suffix=url_suffix, json_data=body)


''' HELPER FUNCTIONS '''


def check_pagination(client: Client, response: Dict, limit: int) -> List:
    arr: List[Dict] = response.get('values', [])
    isNext = response.get('next', None)
    if isNext and limit > response.get('pagelen'):
        return get_paged_results(client, response, limit)
    else:
        return arr


def get_paged_results(client: Client, response: Dict, limit: int) -> List:
    results = []
    arr: List[Dict] = response.get('values', [])
    isNext = response.get('next', None)
    while response:
        for value in arr:
            if limit > 0:
                results.append(value)
                limit = limit - 1
            else:
                break
        if limit > 0 and isNext:
            response = client.get_full_url(full_url=isNext)
            isNext = response.get('next', None)
            arr = response.get('values', [])
        else:
            return results
    return results


def check_args(limit: int, page: int):
    if limit is not None and limit < 1:
        raise Exception('The limit value must be equal to 1 or bigger.')
    if page is not None and page < 1:
        raise Exception('The page value must be equal to 1 or bigger.')


def create_pull_request_body(title: str, source_branch: str, destination_branch: str, reviewer_id: str,
                             description: str, close_source_branch: str) -> Dict:
    body = {
        "title": title,
        "source": {
            "branch": {
                "name": source_branch
            }
        }
    }
    if destination_branch:
        body["destination"] = {
            "branch": {
                "name": destination_branch
            }
        }
    if reviewer_id:
        body["reviewers"] = [
            {
                "account_id": reviewer_id
            }
        ]
    if description:
        body["description"] = description
    if close_source_branch:
        body["close_source_branch"] = argToBoolean(close_source_branch)
    return body


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    params = {'pagelen': 1}
    try:
        client.get_project_list_request(params=params)
        return "ok"
    except Exception as e:
        raise Exception('There was a problem in the authentication process.')


# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client

def project_list_command(client: Client, args: Dict) -> CommandResults:
    limit: int = arg_to_number(args.get('limit', 50))
    project_key = args.get('project_key')
    page: int = arg_to_number(args.get('page', 1))
    check_args(limit, page)
    page_size = min(100, limit)
    params = {
        'page': page,
        'pagelen': page_size
    }
    response = client.get_project_list_request(params, project_key)

    if project_key:
        results = [response]
        readable_name = f'The information about project {project_key.upper()}'
    else:
        results = check_pagination(client, response, limit)
        readable_name = f'List of the projects in {client.workspace}'

    human_readable = []

    for value in results:
        d = {'Key': value.get('key'),
             'Name': value.get('name'),
             'Description': value.get('description'),
             'IsPrivate': value.get('is_private')}
        human_readable.append(d)

    headers = ['Key', 'Name', 'Description', 'IsPrivate']

    readable_output = tableToMarkdown(
        name=readable_name,
        t=human_readable,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Bitbucket.Project',
        outputs=results,
        raw_response=results
    )


def open_branch_list_command(client: Client, args: Dict) -> CommandResults:
    limit = arg_to_number(args.get('limit', 50))
    repo = args.get('repo', None)
    page: int = arg_to_number(args.get('page', 1))
    check_args(limit, page)
    page_size = min(100, limit)
    params = {'page': page,
              'pagelen': page_size}
    response = client.get_open_branch_list_request(repo, params)
    results = check_pagination(client, response, limit)

    human_readable = []
    for value in results:
        d = {'Name': value.get('name'),
             'LastCommitHash': demisto.get(value, 'target.hash'),
             'LastCommitCreatedBy': demisto.get(value, 'target.author.user.display_name'),
             'LastCommitCreatedAt': demisto.get(value, 'target.date')}
        human_readable.append(d)

    headers = ['Name', 'LastCommitCreatedBy', 'LastCommitCreatedAt', 'LastCommitHash']
    readable_output = tableToMarkdown(
        name='The list of open branches',
        t=human_readable,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Bitbucket.Branch',
        outputs=results,
        raw_response=results
    )


def branch_get_command(client: Client, args: Dict) -> CommandResults:
    repo = args.get('repo', None)
    branch_name = args.get('branch_name', None)
    response = client.get_branch_request(branch_name, repo)
    human_readable = {'Name': response.get('name'),
                      'LastCommitHash': demisto.get(response, 'target.hash'),
                      'LastCommitCreatedBy': demisto.get(response, 'target.author.user.display_name'),
                      'LastCommitCreatedAt': demisto.get(response, 'target.date')}
    headers = ['Name', 'LastCommitCreatedBy', 'LastCommitCreatedAt', 'LastCommitHash']
    readable_output = tableToMarkdown(
        name=f'Information about the branch {branch_name}',
        t=human_readable,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Bitbucket.Branch',
        outputs=response,
        raw_response=response
    )


def branch_create_command(client: Client, args: Dict) -> CommandResults:
    repo = args.get('repo', None)
    name = args.get('name', None)
    target_branch = args.get('target_branch', None)
    response = client.branch_create_request(name, target_branch, repo)
    return CommandResults(
        readable_output=f'The branch {name} was created successfully.',
        outputs_prefix='Bitbucket.Branch',
        outputs=response,
        raw_response=response
    )


def branch_delete_command(client: Client, args: Dict) -> CommandResults:
    repo = args.get('repo', None)
    branch_name = args.get('branch_name', None)
    response = client.branch_delete_request(branch_name, repo)
    if response == '204':
        return CommandResults(readable_output=f'The branch {branch_name} was deleted successfully.')
    else:
        return CommandResults(readable_output=response)


def commit_create_command(client: Client, args: Dict) -> CommandResults:
    repo = args.get('repo', None)
    message = args.get('message', None)
    branch = args.get('branch', None)
    file_name = args.get('file_name', None)
    file_content = args.get('file_content', None)
    entry_id = args.get('entry_id', None)
    author_name = args.get('author_name', None)
    author_email = args.get('author_email', None)

    if not file_name and not entry_id:
        raise Exception('You must specify either the "file_name" and "file_content" or the "entry_id" of the file.')
    elif file_name and entry_id:
        raise Exception('You must specify the "file_name" and "file_content" or the "entry_id" of the file, not both.')
    elif entry_id:
        file_path = demisto.getFilePath(entry_id).get('path')
        file_name = demisto.getFilePath(entry_id).get('name')
        with open(file_path, 'rb') as f:
            file_content = f.read()
    body = {
        "message": message,
        "branch": branch,
        file_name: file_content
    }
    if author_name and author_email:
        body["author"] = f'{author_name} <{author_email}>'
    response = client.commit_create_request(body, repo)
    if response.status_code == 201:
        return CommandResults(readable_output=f'The commit was created successfully.')
    else:
        return CommandResults(readable_output=response)


def commit_list_command(client: Client, args: Dict) -> CommandResults:
    repo = args.get('repo', None)
    file_path = args.get('file_path', None)
    excluded_branches = args.get('excluded_branches', None)
    included_branches = args.get('included_branches', None)
    limit = arg_to_number(args.get('limit', 50))
    page: int = arg_to_number(args.get('page', 1))
    check_args(limit, page)
    page_size = min(100, limit)
    params = {
        'path': file_path,
        'page': page,
        'pagelen': page_size
    }
    excluded_list = None
    included_list = None
    if excluded_branches:
        excluded_list = excluded_branches.split(',')
    if included_branches:
        included_list = included_branches.split(',')

    response = client.commit_list_request(repo, params, excluded_list, included_list)
    results = check_pagination(client, response, limit)
    human_readable = []
    for value in results:
        d = {'Author': demisto.get(value, 'author.raw'),
             'Commit': value.get('hash'),
             'Message': value.get('message'),
             'CreatedAt': value.get('date')}
        human_readable.append(d)

    headers = ['Author', 'Commit', 'Message', 'CreatedAt']
    readable_output = tableToMarkdown(
        name='The list of commits',
        t=human_readable,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Bitbucket.Commit',
        outputs=results,
        raw_response=results
    )


def file_delete_command(client: Client, args: Dict) -> CommandResults:
    repo = args.get('repo', None)
    message = args.get('message', None)
    branch = args.get('branch', None)
    file_name = args.get('file_name', None)
    author_name = args.get('author_name', None)
    author_email = args.get('author_email', None)
    body = {
        'message': message,
        'branch': branch,
        'files': file_name
    }
    if author_name and author_email:
        body['author'] = f'{author_name} <{author_email}>'
    response = client.file_delete_request(body, repo)
    if response.status_code == 201:
        return CommandResults(readable_output=f'The file was deleted successfully.')
    else:
        return CommandResults(readable_output=response)


def raw_file_get_command(client: Client, args: Dict) -> CommandResults:
    repo = args.get('repo', None)
    file_path = args.get('file_path', None)
    params = {
        'path': file_path
    }
    commit_list = client.commit_list_request(repo=repo, params=params)

    if len(commit_list.get('values')) == 0:
        return CommandResults(readable_output=f'The file {file_path} does not exist')

    commit_hash = commit_list.get('values')[0].get('hash')
    response = client.raw_file_get_request(repo, file_path, commit_hash)
    output = {
        'file_path': file_path,
        'file_content': response.text
    }
    if response.status_code == 200:
        return CommandResults(readable_output=f'The file {file_path} content is: {response.text}',
                              outputs_prefix='Bitbucket.RawFile',
                              outputs=output)
    else:
        return CommandResults(readable_output='The command failed.',
                              outputs_prefix='Bitbucket.RawFile',
                              outputs=output)


def issue_create_command(client: Client, args: Dict) -> CommandResults:
    repo = args.get('repo', None)
    title = args.get('title', None)
    state = args.get('state', 'new')
    issue_type = args.get('type', 'bug')
    priority = args.get('priority', 'major')
    content = args.get('content', None)
    assignee_id = args.get('assignee_id', None)
    assignee_user_name = args.get('assignee_user_name', None)
    body = {
        "title": title,
        "state": state,
        "kind": issue_type,
        "priority": priority
    }
    if content:
        body["content"] = {
            "raw": content
        }
    if assignee_id:
        body["assignee"] = {
            "account_id": assignee_id,
            "username": assignee_user_name
        }
    response = client.issue_create_request(repo, body)
    return CommandResults(readable_output=f'The issue "{title}" was created successfully',
                          outputs_prefix='Bitbucket.Issue',
                          outputs=response,
                          raw_response=response)


def issue_list_command(client: Client, args: Dict) -> CommandResults:
    """ Retrieves issues from Bitbucket.
        Args:
            client: A Bitbucket client.
            args: Demisto args.
        Returns:
            A CommandResult object with the array of issues as output.
        """
    repo = args.get('repo', None)
    issue_id = args.get('issue_id', None)
    limit = arg_to_number(args.get('limit', 50))
    page: int = arg_to_number(args.get('page', 1))
    check_args(limit, page)
    page_size = min(100, limit)
    params = {
        'page': page,
        'pagelen': page_size
    }
    response = client.issue_list_request(repo, params, issue_id)
    if issue_id:
        results = [response]
        hr_title = f'The information about issue "{issue_id}"'
    else:
        results = check_pagination(client, response, limit)
        hr_title = f'List of the issues'
    human_readable = []
    for value in results:
        d = {'Title': value.get('title'),
             'Type': value.get('kind'),
             'Priority': value.get('priority'),
             'Status': value.get('state'),
             'Votes': value.get('votes'),
             'Assignee': demisto.get(value, 'assignee.display_name'),
             'CreatedAt': value.get('created_on'),
             'UpdatedAt': value.get('updated_on')
             }
        human_readable.append(d)

    headers = ['Title', 'Type', 'Priority', 'Status', 'Votes', 'Assignee', 'CreatedAt', 'UpdatedAt']
    readable_output = tableToMarkdown(
        name=hr_title,
        t=human_readable,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Bitbucket.Issue',
        outputs=results,
        raw_response=results
    )


def issue_update_command(client: Client, args: Dict) -> CommandResults:
    """ Updates issues from Bitbucket. If a certain argument isn't given, don't update it on the issue
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a dictionary contains the updated issue.
    """
    repo = args.get('repo', None)
    issue_id = arg_to_number(args.get('issue_id', None))
    title = args.get('title', None)
    state = args.get('state')
    issue_type = args.get('type')
    priority = args.get('priority')
    content = args.get('content', None)
    assignee_id = args.get('assignee_id', None)
    assignee_user_name = args.get('assignee_user_name', None)
    body = {
        "title": title
    }
    if state:
        body['state'] = state
    if issue_type:
        body['kind'] = issue_type
    if priority:
        body['priority'] = priority
    if content:
        body["content"] = {
            "raw": content
        }
    if assignee_id:
        body["assignee"] = {
            "account_id": assignee_id,
            "username": assignee_user_name
        }
    response = client.issue_update_request(repo, body, issue_id)
    return CommandResults(readable_output=f'The issue with id "{issue_id}" was updated successfully',
                          outputs_prefix='Bitbucket.Issue',
                          outputs=response,
                          raw_response=response)


def pull_request_create_command(client: Client, args: Dict) -> CommandResults:
    """ Updates issues from Bitbucket. If a certain argument isn't given, don't update it on the issue
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a dictionary contains information about the new pull request.
    """
    repo = args.get('repo', None)
    title = args.get('title', None)
    source_branch = args.get('source_branch')
    destination_branch = args.get('destination_branch', None)
    reviewer_id = args.get('reviewer_id', None)
    description = args.get('description', None)
    close_source_branch = args.get('close_source_branch', None)
    body = create_pull_request_body(title, source_branch, destination_branch, reviewer_id, description, close_source_branch)
    response = client.pull_request_create_request(repo, body)
    return CommandResults(readable_output=f'The pull request was created successfully',
                          outputs_prefix='Bitbucket.PullRequest',
                          outputs=response,
                          raw_response=response)


def pull_request_update_command(client: Client, args: Dict) -> CommandResults:
    """ Updates issues from Bitbucket. If a certain argument isn't given, don't update it on the issue
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a dictionary contains information about the updated pull request.
    """
    repo = args.get('repo', None)
    pull_request_id = args.get('pull_request_id', None)
    title = args.get('title', None)
    source_branch = args.get('source_branch')
    destination_branch = args.get('destination_branch', None)
    reviewer_id = args.get('reviewer_id', None)
    description = args.get('description', None)
    close_source_branch = args.get('close_source_branch', None)
    body = create_pull_request_body(title, source_branch, destination_branch, reviewer_id, description, close_source_branch)
    response = client.pull_request_update_request(repo, body, pull_request_id)
    return CommandResults(readable_output=f'The pull request {pull_request_id} was updated successfully',
                          outputs_prefix='Bitbucket.PullRequest',
                          outputs=response,
                          raw_response=response)


def pull_request_list_command(client: Client, args: Dict) -> CommandResults:
    """ Returns a list of pull requests.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a dictionary contains a list of pull request.
        If a state is provided than the list will contain only PR with the wanted status.
        If a state is not provided, by default a list of the open pull requests will return.
    """
    repo = args.get('repo', None)
    pull_request_id = args.get('pull_request_id', None)
    state = args.get('state', None)
    limit = arg_to_number(args.get('limit', 50))
    page: int = arg_to_number(args.get('page', 1))
    check_args(limit, page)
    page_size = min(100, limit)
    params = {
        'page': page,
        'pagelen': page_size
    }
    if state:
        params["state"] = state
    response = client.pull_request_list_request(repo, pull_request_id, params)
    if pull_request_id:
        results = [response]
        hr_title = f'The information about pull request "{pull_request_id}"'
    else:
        results = check_pagination(client, response, limit)
        hr_title = f'List of the pull requests'
    human_readable = []
    for value in results:
        d = {'Title': value.get('title'),
             'Description': value.get('description'),
             'SourceBranch': demisto.get(value, 'source.branch.name'),
             'DestinationBranch': demisto.get(value, 'destination.branch.name'),
             'State': value.get('state'),
             'CreatedBy': demisto.get(value, 'author.display_name'),
             'CreatedAt': value.get('created_on'),
             'UpdatedAt': value.get('updated_on')
             }
        human_readable.append(d)

    headers = ['Title', 'Description', 'SourceBranch', 'DestinationBranch', 'State', 'CreatedBy', 'CreatedAt', 'UpdatedAt']
    readable_output = tableToMarkdown(
        name=hr_title,
        t=human_readable,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Bitbucket.PullRequest',
        outputs=results,
        raw_response=results
    )


def issue_comment_create_command(client: Client, args: Dict) -> CommandResults:
    """ Creates a comment on a specific issue in Bitbucket.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a dictionary contains information about .
        If a state is provided than the list will contain only PR with the wanted status.
        If a state is not provided, by default a list of the open pull requests will return.
    """
    repo = args.get('repo', None)
    issue_id = args.get('issue_id', None)
    content = args.get('content', None)
    body = {
        "content": {
            "raw": content
        }
    }
    response = client.issue_comment_create_request(repo, issue_id, body)
    return CommandResults(readable_output=f'The comment on the issue {issue_id} was created successfully',
                          outputs_prefix='Bitbucket.IssueComment',
                          outputs=response,
                          raw_response=response)


def issue_comment_delete_command(client: Client, args: Dict) -> CommandResults:
    """ Deletes a comment on a specific issue in Bitbucket.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a success message, in case of a successful deletion.
    """
    repo = args.get('repo', None)
    issue_id = args.get('issue_id', None)
    comment_id = args.get('comment_id', None)
    response = client.issue_comment_delete_request(repo, issue_id, comment_id)
    return CommandResults(readable_output=f'The comment number {comment_id} on the issue number {issue_id} was deleted successfully',
                          outputs_prefix='Bitbucket.IssueComment',
                          outputs={},
                          raw_response={})


def issue_comment_update_command(client: Client, args: Dict) -> CommandResults:
    """ Updates a comment on a specific issue in Bitbucket.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a success message, in case of a successful update.
    """
    repo = args.get('repo', None)
    issue_id = args.get('issue_id', None)
    comment_id = args.get('comment_id', None)
    content = args.get('content', None)
    body = {
        'content': {
            'raw': content
        }
    }
    response = client.issue_comment_update_request(repo, issue_id, comment_id, body)
    return CommandResults(readable_output=f'The comment "{comment_id}" on issue "{issue_id}" was updated successfully',
                          outputs_prefix='Bitbucket.IssueComment',
                          outputs=response,
                          raw_response=response)


def issue_comment_list_command(client: Client, args: Dict) -> CommandResults:
    """ Returns a list of comments.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a list of the comments or a single comment on a specific issue.
    """
    repo = args.get('repo', None)
    issue_id = args.get('issue_id', None)  # TODO make sure that it is ok to make it a required field
    comment_id = args.get('comment_id', None)
    limit = arg_to_number(args.get('limit', 50))
    page: int = arg_to_number(args.get('page', 1))
    check_args(limit, page)
    page_size = min(100, limit)
    params = {
        'page': page,
        'pagelen': page_size
    }
    response = client.issue_comment_list_request(repo, issue_id, comment_id, params)
    if comment_id:
        results = [response]
        hr_title = f'The information about the comment "{comment_id}"'
    else:
        results = check_pagination(client, response, limit)
        hr_title = f'List of the comments on issue "{issue_id}"'
    human_readable = []
    for value in results:
        d = {'Id': value.get('id'),
             'Content': demisto.get(value, 'content.raw'),
             'CreatedBy': demisto.get(value, 'user.display_name'),
             'CreatedAt': value.get('created_on'),
             'UpdatedAt': value.get('updated_on'),
             'IssueId': demisto.get(value, 'issue.id'),
             'IssueTitle': demisto.get(value, 'issue.title'),
             }
        human_readable.append(d)

    headers = ['Id', 'Content', 'CreatedBy', 'CreatedAt', 'UpdatedAt', 'IssueId', 'IssueTitle']
    readable_output = tableToMarkdown(
        name=hr_title,
        t=human_readable,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Bitbucket.IssueComment',
        outputs=results,
        raw_response=results
    )


def pull_request_comment_create_command(client: Client, args: Dict) -> CommandResults:
    """ Returns a list of comments.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a success message, in case of a successful deletion.
    """
    repo = args.get('repo', None)
    pr_id = arg_to_number(args.get('pull_request_id', None))
    content = args.get('content', None)
    body = {
        'content': {
            'raw': content
        }
    }
    response = client.pull_request_comment_create_request(repo, pr_id, body)
    return CommandResults(readable_output=f'The comment on the pull request "{pr_id}" was created successfully',
                          outputs_prefix='Bitbucket.PullRequestComment',
                          outputs=[response],
                          raw_response=[response])


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    workspace = demisto.params().get('Workspace', "")
    server_url = demisto.params().get('ServerUrl', "")
    user_name = demisto.params().get('UserName', "").get('identifier', "")
    app_password = demisto.params().get('UserName', "").get('password', "")
    repository = demisto.params().get('Repository', "")
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    auth = (user_name, app_password)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            workspace=workspace,
            server_url=server_url,
            auth=auth,
            proxy=proxy,
            verify=verify_certificate,
            repository=repository
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif demisto.command() == 'bitbucket-project-list':
            result = project_list_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-open-branch-list':
            result = open_branch_list_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-branch-get':
            result = branch_get_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-branch-create':
            result = branch_create_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-branch-delete':
            result = branch_delete_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-commit-create':
            result = commit_create_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-commit-list':
            result = commit_list_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-file-delete':
            result = file_delete_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-raw-file-get':
            result = raw_file_get_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-issue-create':
            result = issue_create_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-issue-list':
            result = issue_list_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-issue-update':
            result = issue_update_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-pull-request-create':
            result = pull_request_create_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-pull-request-update':
            result = pull_request_update_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-pull-request-list':
            result = pull_request_list_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-issue-comment-create':
            result = issue_comment_create_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-issue-comment-delete':
            result = issue_comment_delete_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-issue-comment-update':
            result = issue_comment_update_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-issue-comment-list':
            result = issue_comment_list_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-pull-request-comment-create':
            result = pull_request_comment_create_command(client, demisto.args())
            return_results(result)
        else:
            raise NotImplementedError('This command is not implemented yet.')
        # TODO: ADD command cases for the commands you will implement

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
