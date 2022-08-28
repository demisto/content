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

import demistomock as demisto
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


    def test_module(self) -> str:
        self._http_request(method='GET',
                           url_suffix='core.help',
                           params={},
                           timeout=self.timeout,
                           resp_type='text')
        return "ok"
    # TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API

    def get_list(self, full_url, params=None) -> dict:
        return self._http_request(method='GET', full_url=full_url, params=params)

    # HELPER FUNCTIONS
    def get_paged_results(self, response, results, limit=None, params=None) -> list:
        arr = response.get('values')
        i = len(arr)
        isNext = response.get('next', None)
        if not params:
            page = None
        else:
            page = params.get('page', None)
        if limit:
            while limit > 0 and i > 0:
                for value in arr:
                    results.append(value)
                    limit = limit - 1
                    i = i - 1
            if limit > 0 and isNext and (not page or page == 1):
                response = self.get_list(isNext)
                self.get_paged_results(response, results, limit)
        else:
            for value in arr:
                results.append(value)
            if isNext and (not page or page == 1):
                response = self.get_list(isNext)
                self.get_paged_results(response, results)
        return results



''' COMMAND FUNCTIONS '''


#def test_module(client: Client) -> str:
 #   return client.test_module()


# TODO: REMOVE the following dummy command function
def baseintegration_dummy_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    dummy = args.get('dummy', None)
    if not dummy:
        raise ValueError('dummy not specified')

    # Call the Client function and get the raw response
    result = client.baseintegration_dummy(dummy)

    return CommandResults(
        outputs_prefix='BaseIntegration',
        outputs_key_field='',
        outputs=result,
    )
# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


def project_list_command(client: Client, args) -> CommandResults:
    params = {'page': args.get('page', 1),
              'pagelen': args.get('page_size')}
    project_key = args.get('project_key')
    limit = args.get('limit', None)
    if not project_key:
        full_url = f'{client.serverUrl}/workspaces/{client.workspace}/projects/'
        readable_name = f'List of the projects in {client.workspace}'
    else:
        project_key = project_key.upper()
        full_url = f'{client.serverUrl}/workspaces/{client.workspace}/projects/{project_key}'
        readable_name = f'The information about project {project_key}'

    response = client.get_list(full_url, params)
    if full_url[-1] == '/':
        results = client.get_paged_results(response, [], limit, params)

    human_readable = []

    for value in results:
        d = {'Key': value.get('key'),
             'Name': value.get('name'),
             'Description': value.get('description'),
             'IsPrivate': value.get('is_private')}
        human_readable.append(d)

    readable_output = tableToMarkdown(
        name=readable_name,
        t=human_readable,
        removeNull=True,
        headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Bitbucket.Project',
        outputs=results,
        raw_response=results
    )


# def open_branch_list_command(client: Client, args):


''' MAIN FUNCTION '''


def main() -> None:
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
            result = '' #test_module(client)
            return_results(result)
        elif demisto.command() == 'bitbucket-project-list':
            result = project_list_command(client, demisto.args())
            return_results(result)
        # elif demisto.command() == 'bitbucket-open-branch-list':
         #   result = open_branch_list_command(client, demisto.args())
          #  return_results(result)
        # TODO: ADD command cases for the commands you will implement

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
