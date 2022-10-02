from requests import Response

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
from typing import Dict

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
        self.server_url = server_url
        super().__init__(base_url=server_url, auth=auth, proxy=proxy, verify=verify)

    def get_full_url(self, full_url: str) -> Dict:
        """ Makes a general GET request according to the given full_url.
        Args:
            full_url: str - The full url for the GET method.
        Returns:
            A dictionary, response object from the given full_url.
        """
        return self._http_request(method='GET', full_url=full_url)

    def get_project_list_request(self, page: int | None, page_size: int, project_key: str = None) -> Dict:
        """ Makes a GET request to Bitbucket in order to get a list of all the project in Bitbucket.
            If a specific project_key is given, it will return the information about this project.
        Args:
            project_key: str - A key to a specific project.
            page: int - The specific result's page.
            page_size: int - The number of wanted results in a results page.
        Returns:
            A response object in a form of a dictionary.
        """
        params = {
            'page': page,
            'pagelen': page_size
        }
        if not project_key:
            full_url = f'{self.server_url}/workspaces/{self.workspace}/projects/'
        else:
            project_key = project_key.upper()
            full_url = f'{self.server_url}/workspaces/{self.workspace}/projects/{project_key}'
        return self._http_request(method='GET', full_url=full_url, params=params)

    def get_open_branch_list_request(self, repo: str, page: int | None, page_size: int) -> Dict:
        """ Makes a GET request to Bitbucket in order to get a list of all the open branches in Bitbucket.
        Args:
            repo: str - The repository the user entered if he did.
            page: int - The specific result's page.
            page_size: int - The number of wanted results in a results page.
        Returns:
            A response object in a form of a dictionary.
        """
        params = {'page': page,
                  'pagelen': page_size}
        url_suffix = f'/repositories/{self.workspace}/{repo}/refs/branches'
        return self._http_request(method='GET', url_suffix=url_suffix, params=params)

    def get_branch_request(self, branch_name: str, repo: str) -> Dict:
        """ Makes a GET request to Bitbucket in order to get the information of a specific branch in Bitbucket.
        Args:
            repo: str - The repository the user entered if he did.
            branch_name: str - The name of the branch to create.
        Returns:
            A response object in a form of a dictionary.
        """
        url_suffix = f'/repositories/{self.workspace}/{repo}/refs/branches/{branch_name}'
        return self._http_request(method='GET', url_suffix=url_suffix)

    def branch_create_request(self, name: str, target_branch: str, repo: str) -> Dict:
        """ Makes a POST request to bitbucket, in order to create a branch in Bitbucket.
        Args:
            repo: str - The repository the user entered if he did.
            name: str - The name of the branch to create.
            target_branch: str - The branch from which to create the new branch.
        Returns:
            A response object in a form of a dictionary.
        """
        url_suffix = f'/repositories/{self.workspace}/{repo}/refs/branches'
        body = {
            "target": {
                "hash": target_branch
            },
            "name": name
        }
        return self._http_request(method='POST', url_suffix=url_suffix, json_data=body)

    def branch_delete_request(self, branch_name: str, repo: str) -> Response:
        """ Makes a Delete request to Bitbucket in order to delete a branch in Bitbucket.
        Args:
            repo: str - The repository the user entered if he did.
            branch_name: str - The name of the branch to delete.
        Returns:
            A response object.
        """
        url_suffix = f'/repositories/{self.workspace}/{repo}/refs/branches/{branch_name}'
        return self._http_request(method='DELETE', url_suffix=url_suffix, resp_type='response')

    def commit_create_request(self, body: Dict, repo: str) -> Response:
        """ Makes a POST request to Bitbucket in order to create a commit in Bitbucket.
        Args:
            repo: str - The repository the user entered if he did.
            body: Dict - additional information to the api call.
        Returns:
            A Response object.
        """
        url_suffix = f'/repositories/{self.workspace}/{repo}/src'
        return self._http_request(method='POST',
                                  url_suffix=url_suffix,
                                  data=body,
                                  resp_type='response')

    def commit_list_request(self, repo: str, file_path: str, page: int | None, page_size: int, excluded_list: list,
                            included_list: list) -> Dict:
        """ Makes a POST request to Bitbucket, in order to get a list of commits from Bitbucket.
        Args:
            repo: str - The repository the user entered if he did.
            file_path: str - A file name, in order to return commits that are relevant to this file (if given).
            page: int - The specific result's page.
            page_size: int - The number of wanted results in a results page.
            excluded_list: list - A list of branches that the user wants to filter there related commits away from the
                list.
            included_list: list - A list of branches that the user wants to have in the list of commits.
        Returns:
            A response object in a form of a dictionary.
        """
        params = {
            'path': file_path,
            'page': page,
            'pagelen': page_size
        }
        url_suffix = f'/repositories/{self.workspace}/{repo}/commits'
        param_list = ""
        for branch in excluded_list:
            param_list = f'{param_list}exclude={branch}&'
        for branch in included_list:
            param_list = f'{param_list}include={branch}&'
        if excluded_list or included_list:
            url_suffix = f'{url_suffix}?{param_list[:-1]}'
        return self._http_request(method='POST', url_suffix=url_suffix, params=params)

    def file_delete_request(self, body: Dict, repo: str) -> Response:
        """ Makes a POST request to Bitbucket, in order to delete a file in Bitbucket.
        Args:
            repo: str - The repository the user entered if he did.
            body: Dict - additional information to the api call.
        Returns:
            A Response object.
        """
        url_suffix = f'/repositories/{self.workspace}/{repo}/src'
        return self._http_request(method='POST',
                                  url_suffix=url_suffix,
                                  data=body,
                                  resp_type='response')

    def raw_file_get_request(self, repo: str, file_path: str, commit_hash: str) -> Response:
        """ Makes a GET request to Bitbucket, in order to get a content of a file in Bitbucket.
        Args:
            repo: str - The repository the user entered, if he did.
            file_path: str - The name of the file
            commit_hash: str - The hash of the relevant commit.
        Returns:
            A Response object.
        """
        url_suffix = f'/repositories/{self.workspace}/{repo}/src/{commit_hash}/{file_path}'
        return self._http_request(method='GET', url_suffix=url_suffix, resp_type='response')

    def issue_create_request(self, repo: str, body: dict) -> Dict:
        """ Makes a POST request to Bitbucket, in order to create an issue in Bitbucket.
        Args:
            repo: str - The repository the user entered if he did.
            body: Dict - additional information to the api call
        Returns:
            A response object in a form of a dictionary.
        """
        url_suffix = f'/repositories/{self.workspace}/{repo}/issues'
        return self._http_request(method='POST', url_suffix=url_suffix, json_data=body)

    def issue_list_request(self, repo: str, page: int | None, page_size: int, issue_id: str) -> Dict:
        """ Makes a GET request to Bitbucket, in order to get a list of all the issues, or in case that issue_id
            has been given, it will return the information of the specific issue.
        Args:
            repo: str - The repository the user entered if he did.
            page: int - The specific result's page.
            page_size: int - The number of wanted results in a results page.
            issue_id: str - an id to a specific issue to get.
        Returns:
            A response object in a form of a dictionary.
        """
        params = {
            'page': page,
            'pagelen': page_size
        }
        url_suffix = f'/repositories/{self.workspace}/{repo}/issues/'
        if issue_id:
            url_suffix = f'{url_suffix}{issue_id}'
        return self._http_request(method='GET', url_suffix=url_suffix, params=params)

    def issue_update_request(self, repo: str, body: dict, issue_id: str) -> Dict:
        """ Makes a PUT request to Bitbucket, in order to update an issue.
        Args:
            repo: str - The repository the user entered if he did.
            body: Dict - the params to the api call
            issue_id: str - an id to a specific issue to update.
        Returns:
            A response object in a form of a dictionary.
        """
        url_suffix = f'/repositories/{self.workspace}/{repo}/issues/{issue_id}/'
        return self._http_request(method='PUT', url_suffix=url_suffix, json_data=body)

    def pull_request_create_request(self, repo: str, body: Dict) -> Dict:
        """ Makes a POST request to Bitbucket in order to create a pull request.
        Args:
            repo: str - The repository the user entered if he did.
            body: Dict - the params to the api call
        Returns:
            A response object in a form of a dictionary.
        """
        url_suffix = f'/repositories/{self.workspace}/{repo}/pullrequests'
        return self._http_request(method='POST', url_suffix=url_suffix, json_data=body)

    def pull_request_update_request(self, repo: str, body: Dict, pr_id: str) -> Dict:
        """ Makes a PUT request to Bitbucket in order to update a pull request.
        Args:
            repo: str - The repository the user entered if he did.
            body: Dict - the params to the api call
            pr_id: str - an id to a specific pull request to update.
        Returns:
            A response object in a form of a dictionary.
        """
        url_suffix = f'/repositories/{self.workspace}/{repo}/pullrequests/{pr_id}'
        return self._http_request(method='PUT', url_suffix=url_suffix, json_data=body)

    def pull_request_list_request(self, repo: str, pr_id: str, page: int | None, page_size: int, state: str) -> Dict:
        """ Makes a GET request to Bitbicket in order to get information about a specific pull request. if there isn't
            a pull request id, makes a GET request to get a list of pull requests.
        Args:
            repo: str - The repository the user entered if he did.
            pr_id: str - an id to a specific pull request to update.
            page: int - The specific result's page.
            page_size: int - The number of wanted results in a results page.
            state: str - If a state is provided than the list will contain only PR with the wanted status.
        Returns:
            A response object in a form of a dictionary.
        """
        params: Dict = {
            'page': page,
            'pagelen': page_size
        }
        if state:
            params['state'] = state
        url_suffix = f'/repositories/{self.workspace}/{repo}/pullrequests'
        if pr_id:
            url_suffix = f'{url_suffix}/{pr_id}'
        return self._http_request(method='GET', url_suffix=url_suffix, params=params)

    def issue_comment_create_request(self, repo: str, issue_id: str, body: Dict) -> Dict:
        """ Makes a POST request to Bitbucket in order to create a comment on an issue.
        Args:
            repo: str - The repository the user entered if he did.
            body: Dict - The content of the comment, in a dictionary form.
            issue_id: str - an id to a specific issue to comment on.
        Returns:
            A response object in a form of a dictionary.
        """
        url_suffix = f'/repositories/{self.workspace}/{repo}/issues/{issue_id}/comments'
        return self._http_request(method='POST', url_suffix=url_suffix, json_data=body)

    def issue_comment_delete_request(self, repo: str, issue_id: str, comment_id: str) -> Response:
        """ Makes a DELETE request to Bitbucket in order to delete a comment in an issue.
        Args:
            repo: str - The repository the user entered, if he did.
            issue_id: str - an id to a specific issue to delete one of its comments.
            comment_id: str - an id of a specific comment to delete.
        Returns:
            A Response object.
        """
        url_suffix = f'/repositories/{self.workspace}/{repo}/issues/{issue_id}/comments/{comment_id}'
        return self._http_request(method='DELETE', url_suffix=url_suffix, resp_type='response')

    def issue_comment_update_request(self, repo: str, issue_id: str, comment_id: str, body: Dict) -> Dict:
        """ Makes a PUT request to Bitbucket in order to update a comment in an issue.
        Args:
            repo: str - The repository the user entered, if he did.
            issue_id: str - an id to a specific issue to update one of its comments.
            comment_id: str - an id of a specific comment to update.
            body: Dict - an id of a specific comment to update.
        Returns:
            A response object in a form of a dictionary.
        """
        url_suffix = f'/repositories/{self.workspace}/{repo}/issues/{issue_id}/comments/{comment_id}'
        return self._http_request(method='PUT', url_suffix=url_suffix, json_data=body)

    def issue_comment_list_request(self, repo: str, issue_id: str, comment_id: str, page: int | None, page_size: int) -> Dict:
        """ Makes a GET request to bitbucket in order to get information about a specific comment to an issue.
            if there is no comment_id, then Makes a GET request to get all the comments of a specific issue.
        Args:
            repo: str - The repository the user entered, if he did.
            issue_id: str - an id to a specific issue to get its comments.
            comment_id: str - an id of a specific comment.
            page: int - The specific result's page.
            page_size: int - The number of wanted results in a results page.
        Returns:
            A response object in a form of a dictionary.
        """
        params = {
            'page': page,
            'pagelen': page_size
        }
        url_suffix = f'/repositories/{self.workspace}/{repo}/issues/{issue_id}/comments/'
        if comment_id:
            url_suffix = f'{url_suffix}{comment_id}'
        return self._http_request(method='GET', url_suffix=url_suffix, params=params)

    def pull_request_comment_create_request(self, repo: str, pr_id: str, body: Dict) -> Dict:
        """ Makes a POST request to Bitbucket in order to create a new pull request.
        Args:
            repo: str - The repository the user entered, if he did.
            pr_id: str - an id to a specific pull request to add a comment to.
            body: Dict - a dictionary containing information about the content of the comment.
        Returns:
            A response object in a form of a dictionary.
        """
        url_suffix = f'/repositories/{self.workspace}/{repo}/pullrequests/{pr_id}/comments'
        return self._http_request(method='POST', url_suffix=url_suffix, json_data=body)

    def pull_request_comment_list_request(self, repo: str, pr_id: str, page: int | None, page_size: int, comment_id: str) -> Dict:
        """ Makes a GET request to Bitbucket in order to get information about a specific comment of a pull request.
            If there isn't a comment_id than Makes a GET request to get all the comments of a specific pull request.
        Args:
            repo: str - The repository the user entered, if he did.
            pr_id: str - an id to a specific pull request to add a comment to.
            page: int - The specific result's page.
            page_size: int - The number of wanted results in a results page.
            comment_id: str - an id to a specific comment, in order to get info about it.
        Returns:
            A response object in a form of a dictionary.
        """

        params = {
            'page': page,
            'pagelen': page_size
        }
        url_suffix = f'/repositories/{self.workspace}/{repo}/pullrequests/{pr_id}/comments'
        if comment_id:
            url_suffix = f'{url_suffix}/{comment_id}'
        return self._http_request(method='GET', url_suffix=url_suffix, params=params)

    def pull_request_comment_update_request(self, repo: str, pr_id: str, body: Dict, comment_id: str) -> Dict:
        """ Makes a PUT request to Bitbucket in order to update a specific comment in a pull request.
        Args:
            repo: str - The repository the user entered, if he did.
            pr_id: str - an id to a specific pull.
            body: Dict - a dictionary with the updated content of the comment.
            comment_id: str - an id to a specific comment to update.
        Returns:
            A response object in a form of a dictionary.
        """
        url_suffix = f'/repositories/{self.workspace}/{repo}/pullrequests/{pr_id}/comments/{comment_id}'
        return self._http_request(method='PUT', url_suffix=url_suffix, json_data=body)

    def pull_request_comment_delete_request(self, repo: str, pr_id: str, comment_id: str) -> Response:
        """ Makes a DELETE request to Bitbucket in order to delete a specific comment in a pull request.
            Args:
                repo: str - The repository the user entered, if he did.
                pr_id: str - an id to a specific pull request to add a comment to.
                comment_id: str - an id to a specific comment to delete.
            Returns:
                a Response object.
        """
        url_suffix = f'/repositories/{self.workspace}/{repo}/pullrequests/{pr_id}/comments/{comment_id}'
        return self._http_request(method='DELETE', url_suffix=url_suffix, resp_type='response')

    def workspace_member_list_request(self, page: int | None, page_size: int) -> Dict:
        """ Makes a GET request to Bitbucket in order to return a list of the members in the workspace.
            Args:
                page: int - The specific result's page.
                page_size: int - The number of wanted results in a results page.
            Returns:
                A response object in a form of a dictionary.
        """
        params = {
            'page': page,
            'pagelen': page_size
        }
        url_suffix = f'/workspaces/{self.workspace}/members'
        return self._http_request(method='GET', url_suffix=url_suffix, params=params)


''' HELPER FUNCTIONS '''


def check_pagination(client: Client, response: Dict, limit: int) -> List:
    """ Test the connection to bitbucket.
    Args:
        client: A Bitbucket client.
        response: A response from the API call.
        limit: A limit to the list
    Returns:
        'ok' if the connection was successful, else throws exception.
    """
    arr: List[Dict] = response.get('values', [])
    is_next = response.get('next', None)
    pagelen = response.get('pagelen')
    if is_next and pagelen and limit > int(pagelen):
        return get_paged_results(client, response, limit)
    else:
        return arr


def get_paged_results(client: Client, response: Dict, limit: int) -> List:
    """ Test the connection to bitbucket.
    Args:
        client: A Bitbucket client.
        response: A response from the API call.
        limit: A limit to the list
    Returns:
        'ok' if the connection was successful, else throws exception.
    """
    results = []
    arr: List[Dict] = response.get('values', [])
    is_next = response.get('next', None)
    while response:
        for value in arr:
            if limit > 0:
                results.append(value)
                limit = limit - 1
            else:
                break
        if limit > 0 and is_next:
            response = client.get_full_url(full_url=is_next)
            is_next = response.get('next', None)
            arr = response.get('values', [])
        else:
            return results
    return results


def create_pull_request_body(title: str, source_branch: str, destination_branch: str, reviewer_id: str,
                             description: str, close_source_branch: str) -> Dict:
    """ Test the connection to bitbucket.
    Args:
        title: the title of the pull request.
        source_branch: the source branch in Bitbucket.
        destination_branch: the destination branch in Bitbucket.
        reviewer_id: a list of account_id of the people who should make a review to the pull request.
        description: the description of the pull request.
        close_source_branch: should the branch close after the merging of the pull request.
    Returns:
        'ok' if the connection was successful, else throws exception.
    """
    body: Dict = {}
    if title:
        body["title"] = title
    if source_branch:
        body["source"] = {
            "branch": {
                "name": source_branch
            }
        }
    if destination_branch:
        body["destination"] = {
            "branch": {
                "name": destination_branch
            }
        }
    if reviewer_id:
        reviewers_arr = reviewer_id.split(',')
        account_id_list = []
        for id in reviewers_arr:
            dict = {
                "account_id": id
            }
            account_id_list.append(dict)
        body["reviewers"] = account_id_list
    if description:
        body["description"] = description
    if close_source_branch:
        body["close_source_branch"] = argToBoolean(close_source_branch)
    return body


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """ Test the connection to bitbucket.
    Args:
        client: A Bitbucket client.
    Returns:
        'ok' if the connection was successful, else throws exception.
    """
    try:
        client.get_project_list_request(page=1, page_size=1)
        return "ok"
    except DemistoException as e:
        raise Exception(e.message)


def project_list_command(client: Client, args: Dict) -> CommandResults:
    """ Returns a list of all the projects in Bitbucket.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a success message, in case of a successful action.
    """
    arg_limit = arg_to_number(args.get('limit', 50))
    limit = arg_limit if arg_limit else 50
    project_key = args.get('project_key')
    page = arg_to_number(args.get('page', 1))
    page_size = min(limit, 100)
    response = client.get_project_list_request(page, page_size, project_key)

    if project_key:
        results = [response]
        readable_name = f'The information about project {project_key.upper()}'
    else:
        results = check_pagination(client, response, limit)
        readable_name = f'List of projects in {client.workspace}'

    human_readable = []
    key_list = []

    for value in results:
        d = {'Key': value.get('key'),
             'Name': value.get('name'),
             'Description': value.get('description'),
             'IsPrivate': value.get('is_private')}
        human_readable.append(d)
        key_list.append(value.get('key'))

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
        raw_response=results,
        outputs_key_field=key_list
    )


def open_branch_list_command(client: Client, args: Dict) -> CommandResults:
    """ Returns a list of all the open branches in Bitbucket.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with the list of the branches.
    """
    arg_limit = arg_to_number(args.get('limit', 50))
    limit = arg_limit if arg_limit else 50
    repo = args.get('repo', client.repository)
    page = arg_to_number(args.get('page', 1))
    page_size = min(limit, 100)
    response = client.get_open_branch_list_request(repo, page, page_size)
    results = check_pagination(client, response, limit)

    human_readable = []
    key_list = []
    for value in results:
        d = {'Name': value.get('name'),
             'LastCommitHash': value.get('target').get('hash'),
             'LastCommitCreatedAt': value.get('target').get('date')}
        user = value.get('target').get('author').get('user')
        if user:
            d['LastCommitCreatedBy'] = user.get('display_name')
        else:
            d['LastCommitCreatedBy'] = value.get('target').get('author').get('raw')
        human_readable.append(d)
        key_list.append(value.get('name'))

    headers = ['Name', 'LastCommitCreatedBy', 'LastCommitCreatedAt', 'LastCommitHash']
    readable_output = tableToMarkdown(
        name='Open Branches',
        t=human_readable,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Bitbucket.Branch',
        outputs=results,
        raw_response=results,
        outputs_key_field=key_list
    )


def branch_get_command(client: Client, args: Dict) -> CommandResults:
    """ Returns the information on a given branch in Bitbucket.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with the information about the branch.
    """
    repo = args.get('repo', client.repository)
    branch_name = args.get('branch_name', '')
    response: Dict = client.get_branch_request(branch_name, repo)
    human_readable = {'Name': response.get('name'),
                      'LastCommitHash': response.get('target', {}).get('hash'),
                      'LastCommitCreatedBy': response.get('target', {}).get('author', {}).get('user', {})
                      .get('display_name'),
                      'LastCommitCreatedAt': response.get('target', {}).get('date')}
    headers = ['Name', 'LastCommitCreatedBy', 'LastCommitCreatedAt', 'LastCommitHash']
    readable_output = tableToMarkdown(
        name=f'Information about the branch: {branch_name}',
        t=human_readable,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Bitbucket.Branch',
        outputs=response,
        raw_response=response,
        outputs_key_field=response.get('name')
    )


def branch_create_command(client: Client, args: Dict) -> CommandResults:
    """ creates a branch in Bitbucket.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a success message, in case of a successful action.
    """
    repo = args.get('repo', client.repository)
    name = args.get('name', '')
    target_branch = args.get('target_branch', '')
    response = client.branch_create_request(name, target_branch, repo)
    return CommandResults(
        readable_output=f'The branch "{name}" was created successfully.',
        outputs_prefix='Bitbucket.Branch',
        outputs=response,
        raw_response=response,
        outputs_key_field=name
    )


def branch_delete_command(client: Client, args: Dict) -> CommandResults:
    """ Deletes a branch in Bitbucket.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a success message, in case of a successful action.
    """
    repo = args.get('repo', client.repository)
    branch_name = args.get('branch_name', '')
    try:
        client.branch_delete_request(branch_name, repo)
        return CommandResults(readable_output=f'The branch {branch_name} was deleted successfully.')
    except DemistoException as e:
        message_arr = e.message.split('\n')
        m_json = json.loads(message_arr[1])
        raise Exception(f'{message_arr[0]} , branch "{m_json.get("error").get("message")}"')


def commit_create_command(client: Client, args: Dict) -> CommandResults:
    """ creates a commit in Bitbucket.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a success message, in case of a successful action.
    """
    repo = args.get('repo', client.repository)
    message = args.get('message', '')
    branch = args.get('branch', '')
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
    elif author_name and not author_email:
        raise Exception('Please enter an email as well.')
    elif not author_name and author_email:
        raise Exception('Please enter a name as well.')
    client.commit_create_request(body, repo)
    return CommandResults(readable_output='The commit was created successfully.')


def commit_list_command(client: Client, args: Dict) -> CommandResults:
    """ Returns a list of all the commits according to the given params.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with the list of commits.
    """
    repo = args.get('repo', client.repository)
    file_path = args.get('file_path', None)
    excluded_branches = args.get('excluded_branches', None)
    included_branches = args.get('included_branches', None)
    arg_limit = arg_to_number(args.get('limit'))
    limit = arg_limit if arg_limit else 50
    page = arg_to_number(args.get('page', 1))
    page_size = min(limit, 100)
    excluded_list = argToList(arg=excluded_branches)
    included_list = argToList(arg=included_branches)
    response = client.commit_list_request(repo, file_path, page, page_size, excluded_list, included_list)
    results = check_pagination(client, response, limit)
    human_readable = []
    key_list = []
    for value in results:
        d = {'Author': value.get('author').get('raw'),
             'Commit': value.get('hash'),
             'Message': value.get('message'),
             'CreatedAt': value.get('date')}
        human_readable.append(d)
        key_list.append(value.get('hash'))

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
        raw_response=results,
        outputs_key_field=key_list
    )


def file_delete_command(client: Client, args: Dict) -> CommandResults:
    """ Deletes a file in Bitbucket.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a success message, in case of a successful action.
    """
    repo = args.get('repo', client.repository)
    message = args.get('message', '')
    branch = args.get('branch', '')
    file_name = args.get('file_name', '')
    author_name = args.get('author_name', None)
    author_email = args.get('author_email', None)
    body = {
        'message': message,
        'branch': branch,
        'files': file_name
    }
    if author_name and author_email:
        body['author'] = f'{author_name} <{author_email}>'
    elif author_name and not author_email:
        raise Exception('Please enter an email as well.')
    elif not author_name and author_email:
        raise Exception('Please enter a name as well.')
    client.file_delete_request(body, repo)
    return CommandResults(readable_output='The file was deleted successfully.')


def raw_file_get_command(client: Client, args: Dict) -> List[CommandResults]:
    """ Returns the content of a given file.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A list containing a CommandResult object and a fileResult object.
    """
    repo = args.get('repo', client.repository)
    file_path = args.get('file_path', '')
    branch = args.get('branch', None)
    if branch:
        including_list = [branch]
    else:
        including_list = []
    try:
        commit_list = client.commit_list_request(repo=repo, file_path=file_path, page=1, page_size=100,
                                                 excluded_list=[], included_list=including_list)
    except DemistoException as e:
        message_arr = e.message.split('\n')
        m_json = json.loads(message_arr[1])
        raise Exception(f'{message_arr[0]} , branch {m_json.get("data").get("shas")}')
    values: List = commit_list.get('values', [])
    if len(values) == 0:
        raise Exception(f'The file {file_path} does not exist')

    commit_hash = values[0].get('hash')
    response = client.raw_file_get_request(repo, file_path, commit_hash)
    output = {
        'file_path': file_path,
        'file_content': response.text
    }
    file_ = fileResult(filename=file_path, data=response.text)
    return [CommandResults(readable_output=f'The content of the file "{file_path}" is: {response.text}',
                           outputs_prefix='Bitbucket.RawFile',
                           outputs=output), file_]


def issue_create_command(client: Client, args: Dict) -> CommandResults:
    """ creates an issue in Bitbucket.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a success message, in case of a successful action.
    """
    repo = args.get('repo', client.repository)
    title = args.get('title', '')
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
                          raw_response=response,
                          outputs_key_field=str(response.get('id')))


def issue_list_command(client: Client, args: Dict) -> CommandResults:
    """ Retrieves issues from Bitbucket.
        Args:
            client: A Bitbucket client.
            args: Demisto args.
        Returns:
            A CommandResult object with the array of issues as output.
        """
    repo = args.get('repo', client.repository)
    issue_id = args.get('issue_id', None)
    arg_limit = arg_to_number(args.get('limit', 50))
    limit = arg_limit if arg_limit else 50
    page = arg_to_number(args.get('page', 1))
    page_size = min(limit, 100)
    response = client.issue_list_request(repo, page, page_size, issue_id)
    if issue_id:
        results = [response]
        hr_title = f'The information about issue "{issue_id}"'
    else:
        results = check_pagination(client, response, limit)
        hr_title = 'List of the issues'
    human_readable = []
    key_list = []
    for value in results:
        d = {'Id': value.get('id'),
             'Title': value.get('title'),
             'Type': value.get('kind'),
             'Priority': value.get('priority'),
             'Status': value.get('state'),
             'Votes': value.get('votes'),
             'CreatedAt': value.get('created_on'),
             'UpdatedAt': value.get('updated_on')}
        assignee = value.get('assignee', {})
        if assignee:
            d["assignee"] = assignee.get('display_name')
        else:
            d["assignee"] = None
        human_readable.append(d)
        key_list.append(str(value.get('id')))

    headers = ['Id', 'Title', 'Type', 'Priority', 'Status', 'Votes', 'Assignee', 'CreatedAt', 'UpdatedAt']
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
        raw_response=results,
        outputs_key_field=key_list
    )


def issue_update_command(client: Client, args: Dict) -> CommandResults:
    """ Updates issues from Bitbucket. If a certain argument isn't given, don't update it on the issue
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a dictionary contains the updated issue.
    """
    repo = args.get('repo', client.repository)
    issue_id = args.get('issue_id', '')
    title = args.get('title', '')
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
                          raw_response=response,
                          outputs_key_field=str(response.get('id')))


def pull_request_create_command(client: Client, args: Dict) -> CommandResults:
    """ Updates issues from Bitbucket. If a certain argument isn't given, don't update it on the issue
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a dictionary contains information about the new pull request.
    """
    repo = args.get('repo', client.repository)
    title = args.get('title', '')
    source_branch = args.get('source_branch', '')
    destination_branch = args.get('destination_branch', '')
    reviewer_id = args.get('reviewer_id', None)
    description = args.get('description', None)
    close_source_branch = args.get('close_source_branch', None)
    body = create_pull_request_body(title, source_branch, destination_branch, reviewer_id, description,
                                    close_source_branch)
    response = client.pull_request_create_request(repo, body)
    return CommandResults(readable_output='The pull request was created successfully',
                          outputs_prefix='Bitbucket.PullRequest',
                          outputs=response,
                          raw_response=response,
                          outputs_key_field=str(response.get('id')))


def pull_request_update_command(client: Client, args: Dict) -> CommandResults:
    """ Updates issues from Bitbucket. If a certain argument isn't given, don't update it on the issue
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a dictionary contains information about the updated pull request.
    """
    repo = args.get('repo', client.repository)
    pull_request_id = args.get('pull_request_id', '')
    title = args.get('title', None)
    source_branch = args.get('source_branch', None)
    destination_branch = args.get('destination_branch', None)
    reviewer_id = args.get('reviewer_id', None)
    description = args.get('description', None)
    close_source_branch = args.get('close_source_branch', None)
    body = create_pull_request_body(title, source_branch, destination_branch, reviewer_id, description,
                                    close_source_branch)
    response = client.pull_request_update_request(repo, body, pull_request_id)
    return CommandResults(readable_output=f'The pull request {pull_request_id} was updated successfully',
                          outputs_prefix='Bitbucket.PullRequest',
                          outputs=response,
                          raw_response=response,
                          outputs_key_field=str(response.get('id')))


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
    repo = args.get('repo', client.repository)
    pull_request_id = args.get('pull_request_id', None)
    state = args.get('state', None)
    arg_limit = arg_to_number(args.get('limit', 50))
    limit = arg_limit if arg_limit else 50
    page = arg_to_number(args.get('page', 1))
    page_size = min(limit, 100)
    response = client.pull_request_list_request(repo, pull_request_id, page, page_size, state)
    if pull_request_id:
        results = [response]
        hr_title = f'The information about pull request "{pull_request_id}"'
    else:
        results = check_pagination(client, response, limit)
        hr_title = 'List of the pull requests'
    human_readable = []
    key_list = []
    for value in results:
        d = {'Id': value.get('id'),
             'Title': value.get('title'),
             'Description': value.get('description'),
             'SourceBranch': value.get('source', {}).get('branch', {}).get('name'),
             'DestinationBranch': value.get('destination', {}).get('branch', {}).get('name'),
             'State': value.get('state'),
             'CreatedBy': value.get('author', {}).get('display_name'),
             'CreatedAt': value.get('created_on'),
             'UpdatedAt': value.get('updated_on')
             }
        human_readable.append(d)
        key_list.append(str(value.get('id')))

    headers = ['Id', 'Title', 'Description', 'SourceBranch', 'DestinationBranch', 'State', 'CreatedBy', 'CreatedAt',
               'UpdatedAt']
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
        raw_response=results,
        outputs_key_field=key_list
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
    repo = args.get('repo', client.repository)
    issue_id = args.get('issue_id', '')
    content = args.get('content', '')
    body = {
        "content": {
            "raw": content
        }
    }
    response = client.issue_comment_create_request(repo, issue_id, body)
    return CommandResults(readable_output='The comment was created successfully',
                          outputs_prefix='Bitbucket.IssueComment',
                          outputs=response,
                          raw_response=response,
                          outputs_key_field=str(response.get('id')))


def issue_comment_delete_command(client: Client, args: Dict) -> CommandResults:
    """ Deletes a comment on a specific issue in Bitbucket.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a success message, in case of a successful deletion.
    """
    repo = args.get('repo', client.repository)
    issue_id = args.get('issue_id', '')
    comment_id = args.get('comment_id', '')
    client.issue_comment_delete_request(repo, issue_id, comment_id)
    return CommandResults(
        readable_output='The comment was deleted successfully',
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
    repo = args.get('repo', client.repository)
    issue_id = args.get('issue_id', '')
    comment_id = args.get('comment_id', '')
    content = args.get('content', '')
    body = {
        'content': {
            'raw': content
        }
    }
    response = client.issue_comment_update_request(repo, issue_id, comment_id, body)
    return CommandResults(readable_output='The comment was updated successfully',
                          outputs_prefix='Bitbucket.IssueComment',
                          outputs=response,
                          raw_response=response,
                          outputs_key_field=str(response.get('id')))


def issue_comment_list_command(client: Client, args: Dict) -> CommandResults:
    """ Returns a list of comments.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a list of the comments or a single comment on a specific issue.
    """
    repo = args.get('repo', client.repository)
    issue_id = args.get('issue_id', '')
    comment_id = args.get('comment_id', None)
    arg_limit = arg_to_number(args.get('limit', 50))
    limit = arg_limit if arg_limit else 50
    page = arg_to_number(args.get('page', 1))
    page_size = min(limit, 100)
    response = client.issue_comment_list_request(repo, issue_id, comment_id, page, page_size)
    if comment_id:
        results = [response]
        hr_title = f'The information about the comment "{comment_id}"'
    else:
        results = check_pagination(client, response, limit)
        hr_title = f'List of the comments on issue "{issue_id}"'
    human_readable = []
    key_list = []
    for value in results:
        d = {'Id': value.get('id'),
             'Content': value.get('content', {}).get('raw'),
             'CreatedBy': value.get('user', {}).get('display_name'),
             'CreatedAt': value.get('created_on'),
             'UpdatedAt': value.get('updated_on'),
             'IssueId': value.get('issue', {}).get('id'),
             'IssueTitle': value.get('issue', {}).get('title')}
        human_readable.append(d)
        key_list.append(str(value.get('id')))

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
        raw_response=results,
        outputs_key_field=key_list
    )


def pull_request_comment_create_command(client: Client, args: Dict) -> CommandResults:
    """ Creates a comment in a pull request.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a success message, in case of a successful creation of a comment.
    """
    repo = args.get('repo', client.repository)
    pr_id = args.get('pull_request_id', '')
    content = args.get('content', '')
    body = {
        'content': {
            'raw': content
        }
    }
    response = client.pull_request_comment_create_request(repo, pr_id, body)
    return CommandResults(readable_output='The comment was created successfully',
                          outputs_prefix='Bitbucket.PullRequestComment',
                          outputs=[response],
                          raw_response=[response],
                          outputs_key_field=str(response.get('id')))


def pull_request_comment_list_command(client: Client, args: Dict) -> CommandResults:
    """ Returns a list of pull request comments.
    Args:
        client: A Bitbucket client.
        args: Demisto args.
    Returns:
        A CommandResult object with a list of the comments or a single comment on a specific issue.
    """
    repo = args.get('repo', client.repository)
    pr_id = args.get('pull_request_id', '')
    comment_id = args.get('comment_id', None)
    arg_limit = arg_to_number(args.get('limit', 50))
    limit = arg_limit if arg_limit else 50
    page = arg_to_number(args.get('page', 1))
    page_size = min(limit, 100)
    response = client.pull_request_comment_list_request(repo, pr_id, page, page_size, comment_id)
    if comment_id:
        results = [response]
        hr_title = f'The information about the comment "{comment_id}"'
    else:
        results = check_pagination(client, response, limit)
        hr_title = f'List of the comments on pull request "{pr_id}"'
    human_readable = []
    # After a comment on a pull request is deleted it will still appear on the response from the api.
    # Those comments can be recognized when their raw content is an empty string.
    # In order not to show the deleted comments, they are saved in records_to_delete array, and then are deleted.
    records_to_delete = []
    key_list = []
    for value in results:
        if not value.get('content', {}).get('raw') == "":
            d = {'Id': value.get('id'),
                 'Content': value.get('content', {}).get('raw'),
                 'CreatedBy': value.get('user', {}).get('display_name'),
                 'CreatedAt': value.get('created_on'),
                 'UpdatedAt': value.get('updated_on'),
                 'PullRequestIdIssueId': value.get('pullrequest', {}).get('id'),
                 'PullRequestTitle': value.get('pullrequest', {}).get('title')}
            human_readable.append(d)
            key_list.append(str(value.get('id')))
        else:
            records_to_delete.append(value)
    if len(records_to_delete) > 0:
        for item in records_to_delete:
            results.remove(item)

    headers = ['Id', 'Content', 'CreatedBy', 'CreatedAt', 'UpdatedAt', 'IssueId', 'IssueTitle']
    readable_output = tableToMarkdown(
        name=hr_title,
        t=human_readable,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Bitbucket.PullRequestComment',
        outputs=results,
        raw_response=results,
        outputs_key_field=key_list
    )


def pull_request_comment_update_command(client: Client, args: Dict) -> CommandResults:
    """ Updates a comment in a pull request.
        Args:
            client: A Bitbucket client.
            args: Demisto args.
        Returns:
            A CommandResult object with a success message.
    """
    repo = args.get('repo', client.repository)
    pr_id = args.get('pull_request_id', '')
    comment_id = args.get('comment_id', '')
    content = args.get('content')
    body = {
        'content': {
            'raw': content
        }
    }
    response = client.pull_request_comment_update_request(repo, pr_id, body, comment_id)
    return CommandResults(
        readable_output='The comment was updated successfully',
        outputs_prefix='Bitbucket.PullRequestComment',
        outputs=response,
        raw_response=response,
        outputs_key_field=str(response.get('id')))


def pull_request_comment_delete_command(client: Client, args: Dict) -> CommandResults:
    """ Deletes a comment in a pull request.
        Args:
            client: A Bitbucket client.
            args: Demisto args.
        Returns:
            A CommandResult object with a success message.
    """
    repo = args.get('repo', client.repository)
    pr_id = args.get('pull_request_id', '')
    comment_id = args.get('comment_id', '')
    try:
        client.pull_request_comment_delete_request(repo, pr_id, comment_id)
        return CommandResults(readable_output='The comment was deleted successfully.')
    except DemistoException as e:
        raise Exception(f'The command pull-request-comment-delete failed. {e.message}')


def workspace_member_list_command(client: Client, args: Dict) -> CommandResults:
    """ Returns a list of all the members in the requested workspace.
        Args:
            client: A Bitbucket client.
            args: Demisto args.
        Returns:
            A CommandResult object with the requested list.
    """
    arg_limit = arg_to_number(args.get('limit', 50))
    limit = arg_limit if arg_limit else 50
    page = arg_to_number(args.get('page', 1))
    page_size = min(limit, 100)
    response = client.workspace_member_list_request(page, page_size)
    results = check_pagination(client, response, limit)
    human_readable = []
    key_list = []
    for value in results:
        d = {'Name': value.get('user').get('display_name'),
             'AccountId': value.get('user').get('account_id')}
        human_readable.append(d)
        key_list.append(value.get('user').get('account_id'))
    headers = ['Name', 'AccountId']
    readable_output = tableToMarkdown(
        name='The list of all the workspace members',
        t=human_readable,
        removeNull=True,
        headers=headers
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Bitbucket.WorkspaceMember',
        outputs=results,
        raw_response=results,
        outputs_key_field=key_list
    )


''' MAIN FUNCTION '''


def main() -> None:
    workspace = demisto.params().get('workspace')
    server_url = demisto.params().get('server_url')
    user_name = demisto.params().get('credentials', {}).get('identifier', "")
    app_password = demisto.params().get('credentials', {}).get('password', "")
    repository = demisto.params().get('repository', "")
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
            str_result: str = test_module(client)
            return_results(str_result)
        elif demisto.command() == 'bitbucket-project-list':
            result: CommandResults = project_list_command(client, demisto.args())
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
            result_list = raw_file_get_command(client, demisto.args())
            return_results(result_list)
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
        elif demisto.command() == 'bitbucket-pull-request-comment-list':
            result = pull_request_comment_list_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-pull-request-comment-update':
            result = pull_request_comment_update_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-pull-request-comment-delete':
            result = pull_request_comment_delete_command(client, demisto.args())
            return_results(result)
        elif demisto.command() == 'bitbucket-workspace-member-list':
            result = workspace_member_list_command(client, demisto.args())
            return_results(result)
        else:
            raise NotImplementedError('This command is not implemented yet.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
