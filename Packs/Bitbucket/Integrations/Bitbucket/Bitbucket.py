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

    # TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API

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


''' HELPER FUNCTIONS '''


def check_pagination(client: Client, response: Dict, limit: int, params: Dict) -> List:
    arr: List[Dict] = response.get('values', [])
    results_number = len(arr)
    isNext = response.get('next', None)
    results = []
    if limit < results_number:
        for res in arr:
            if limit > 0:
                results.append(res)
                limit = limit - 1
            else:
                return results
    elif limit == results_number or params.get('page', None) or (not isNext):
        return arr
    else:
        return get_paged_results(client, response, limit)
    return results


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


def check_args(limit: int, page: int, page_size: int):
    if limit is not None and limit < 1:
        raise Exception('The limit value must be equal to 1 or bigger.')
    if page is not None and page < 1:
        raise Exception('The page value must be equal to 1 or bigger.')
    if page_size is not None and page_size < 1:
        raise Exception('The page_size value must be equal to 1 or bigger.')


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
    params = {'page': arg_to_number(args.get('page')),
              'pagelen': arg_to_number(args.get('page_size', 50))}
    limit: int = arg_to_number(args.get('limit', 50))
    project_key = args.get('project_key')
    page: int = params.get('page', None)
    page_size: int = params.get('page_size', None)
    check_args(limit, page, page_size)

    response = client.get_project_list_request(params, project_key)

    if project_key:
        results = [response]
        readable_name = f'The information about project {project_key.upper()}'
    else:
        results = check_pagination(client, response, limit, params)
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
    params = {'page': arg_to_number(args.get('page')),
              'pagelen': arg_to_number(args.get('page_size', 50))}
    limit = arg_to_number(args.get('limit', 50))
    repo = args.get('repo', None)
    page: int = params.get('page', None)
    page_size: int = params.get('page_size', None)
    check_args(limit, page, page_size)

    response = client.get_open_branch_list_request(repo, params)
    results = check_pagination(client, response, limit, params)

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
            repository=repository)

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
        # elif demisto.command() == 'bitbucket-branch-get':
         #   result = branch_get_command(client, demisto.args())
          #  return_results(result)
        else:
            raise NotImplementedError('This command is not implemented yet.')
        # TODO: ADD command cases for the commands you will implement

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
