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

    def get_project_list_request(self, params: Dict, project_key: str = None) -> Dict:
        if not project_key:
            full_url = f'{self.serverUrl}/workspaces/{self.workspace}/projects/'
        else:
            project_key = project_key.upper()
            full_url = f'{self.serverUrl}/workspaces/{self.workspace}/projects/{project_key}'

        return self._http_request(method='GET', full_url=full_url, params=params)

    def get_open_branch_list_request(self, repo: str, params: Dict) -> Dict:
        if repo:
            full_url = f'{self.serverUrl}/repositories/{self.workspace}/{repo}/refs/branches'
        else:
            if not self.repository:
                raise Exception("Please provide a repository name")
            full_url = f'{self.serverUrl}/repositories/{self.workspace}/{self.repository}/refs/branches'

        return self._http_request(method='GET', full_url=full_url, params=params)

    def get_branch_request(self, branch_name: str, repo: str = None) -> Dict:
        if repo:
            url_suffix = f'/repositories/{self.workspace}/{repo}/refs/branches/{branch_name}'
        else:
            if not self.repository:
                raise Exception("Please provide a repository name")
            url_suffix = f'/repositories/{self.workspace}/{self.repository}/refs/branches/{branch_name}'

        return self._http_request(method='GET', url_suffix=url_suffix)

    def branch_create_request(self, name: str, target_branch: str, repo: str = None) -> Dict:
        if repo:
            url_suffix = f'/repositories/{self.workspace}/{repo}/refs/branches'
        else:
            if not self.repository:
                raise Exception("Please provide a repository name")
            url_suffix = f'/repositories/{self.workspace}/{self.repository}/refs/branches'
        body = {
            "target": {
                "hash": target_branch
            },
            "name": name
        }
        return self._http_request(method='POST', url_suffix=url_suffix, json_data=body)

    def branch_delete_request(self, branch_name: str, repo: str = None) -> str:
        if repo:
            url_suffix = f'/repositories/{self.workspace}/{repo}/refs/branches/{branch_name}'
        else:
            if not self.repository:
                raise Exception("Please provide a repository name")
            url_suffix = f'/repositories/{self.workspace}/{self.repository}/refs/branches/{branch_name}'

        try:
            self._http_request(method='DELETE', url_suffix=url_suffix)
        except DemistoException as e:
            status_code = e.res.status_code
            if status_code == 204:
                return str(204)
            else:
                return e.message

    def commit_create_request(self, body: Dict, repo: str = None):
        if repo:
            url_suffix = f'/repositories/{self.workspace}/{repo}/src'
        else:
            if not self.repository:
                raise Exception("Please provide a repository name")
            url_suffix = f'/repositories/{self.workspace}/{self.repository}/src'
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
        if repo:
            url_suffix = f'/repositories/rotemamit/{repo}/commits'
        else:
            if not self.repository:
                raise Exception("Please provide a repository name")
            url_suffix = f'/repositories/rotemamit/{self.repository}/commits'
        if excluded_list:
            url_suffix = self.add_branches_url('exclude', excluded_list, url_suffix)
        if included_list:
            url_suffix = self.add_branches_url('include', included_list, url_suffix)
        response = self._http_request(method='POST',
                                      url_suffix=url_suffix,
                                      params=params)
        return response

    def file_delete_request(self, body: Dict, repo: str = None) -> Dict:
        if repo:
            url_suffix = f'/repositories/{self.workspace}/{repo}/src'
        else:
            if not self.repository:
                raise Exception("Please provide a repository name")
            url_suffix = f'/repositories/{self.workspace}/{self.repository}/src'
        return self._http_request(method='POST',
                                  url_suffix=url_suffix,
                                  data=body,
                                  resp_type='response')

    def raw_file_get_request(self, repo: str, file_path: str, commit_hash: str) -> Dict:
        if repo:
            url_suffix = f'/repositories/{self.workspace}/{repo}/src/{commit_hash}/{file_path}'
        else:
            url_suffix = f'/repositories/{self.workspace}/{self.repository}/src/{commit_hash}/{file_path}'
        return self._http_request(method='GET', url_suffix=url_suffix, resp_type='response')


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

    if response.status_code == 200:
        return CommandResults(readable_output=f'The file {file_path} content is: {response.text}')
    else:
        return CommandResults(readable_output='The command failed.')


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
        else:
            raise NotImplementedError('This command is not implemented yet.')
        # TODO: ADD command cases for the commands you will implement

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
