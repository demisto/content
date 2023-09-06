from typing import Dict, Tuple, Callable

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

import urllib3
# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''
DEFAULT_VCS_TYPE = 'github'
DEFAULT_LIMIT_VALUE = 20
''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool, vc_type: str, organization: str,
                 project: str):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers={'authorization': f'Basic {api_key}'})
        self.vc_type = vc_type
        self.organization = organization
        self.project = project
        self.api_key = api_key

    def get_job_artifacts(self, vc_type: str, organization: str, project: str, job_name: str):
        return self._http_request(
            method='GET',
            url_suffix=f'/project/{vc_type}/{organization}/{project}/{job_name}/artifacts'
        )

    def get_workflows_list(self, vc_type: str, organization: str, project: str, page_token: Optional[str] = None):
        url_suffix = f'insights/{vc_type}/{organization}/{project}/workflows'
        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params={'page-token': page_token} if page_token else None
        )

    def get_last_workflow_runs(self, vc_type: str, organization: str, project: str, workflow_name: str,
                               branch: str, page_token: Optional[str] = None):

        url_suffix = f'insights/{vc_type}/{organization}/{project}/workflows/{workflow_name}'
        params = {}
        if page_token:
            params['page-token'] = page_token
        if branch:
            params['branch'] = branch

        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=params,
        )

    def get_workflow_jobs(self, workflow_id: str, page_token: Optional[str] = None):
        url_suffix = f'/workflow/{workflow_id}/job'
        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params={'page-token': page_token} if page_token else None
        )

    def trigger_workflow(self, vc_type: str, organization: str, project: str, parameters: str):
        url_suffix = f'project/{vc_type}/{organization}/{project}/pipeline'

        return self._http_request(
            method='POST',
            url_suffix=url_suffix,
            json_data=parameters,
            resp_type='text',
            headers={'Circle-Token': self.api_key},
        )


''' HELPER FUNCTIONS '''


def get_response_with_pagination(client_command: Callable, client_command_args: List, limit: int) -> List[Dict]:
    """
    Preforms API calls to CircleCI, using pagination mechanism given by CircleCI.
    CircleCI gives a page token for retrieving next page if more results exists.
    Args:
        client_command (Callable): Client function command which performs the API call.
        client_command_args (Dict): Args for client command.
        limit (int): Maximum number of results to retrieve.

    Returns:
        (List[Dict]): List of the results.
    """
    results: List[Dict] = []
    response = client_command(*client_command_args)
    results.extend(response.get('items', []))
    while len(results) < limit:
        next_page_token: Optional[str] = response.get('next_page_token')
        if not next_page_token:
            break
        response = client_command(*(client_command_args + [next_page_token]))
        data = response.get('items', [])
        results.extend(data)
    return results[:limit]


def get_common_arguments(client: Client, args: Dict[str, Any]) -> Tuple[str, str, str, int]:
    """
    Performs same logic for getting arguments.
    Args:
        client (Client): Client to retrieve instance parameter configurations in case argument was not given.
        args (Dict[str, Any]): XSOAR arguments.

    Returns:
        (Tuple[str, str, str]): (vcs_type, organization, project, limit).
    """
    vc_type: str = args.get('vcs_type') or client.vc_type
    organization: str = args.get('organization') or client.organization
    project: str = args.get('project') or client.project
    limit: int = arg_to_number(args.get('limit')) or DEFAULT_LIMIT_VALUE

    return vc_type, organization, project, limit


''' COMMAND FUNCTIONS '''


def test_module_command(client: Client) -> str:
    """
    Tests connectivity to CircleCI services.
    Args:
        client (Client): Client to perform API request to test connection.

    Returns:
        (str): 'ok' upon success,
        (str): 'Error connecting to CircleCI. Make sure your URL and API token are configured correctly.' upon failure.
    """

    message: str = 'ok'
    try:
        vc_type, organization, project, _ = get_common_arguments(client, dict())
        client.get_workflows_list(vc_type, organization, project)
    except DemistoException as e:
        if 'not found' in str(e).lower():
            message = 'Error connecting to CircleCI. Check if your organization and repository names are correct.' \
                      ' If it is a private repository, make sure your API token is valid.'
        else:
            raise e
    return message


def circleci_workflows_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves workflows list details from CircleCI.
    Args:
        client (Client): Client to perform the API calls
        args (Dict[str, Any]): XSOAR arguments.
        - 'vc_type' (str): VC type. One of 'github', 'bitbucket'.
        - 'organization' (str): Organization to retrieve workflows from.
                                Defaults to organization parameter is none is given.
        - 'project' (str): Project to retrieve workflows from. Defaults to project parameter is none is given.

    Returns:
        (CommandResults).
    """
    vc_type, organization, project, limit = get_common_arguments(client, args)

    response = get_response_with_pagination(client.get_workflows_list, [vc_type, organization, project], limit)

    return CommandResults(
        outputs_prefix='CircleCI.Workflow',
        outputs_key_field='id',
        readable_output=tableToMarkdown('CircleCI Workflows', response, removeNull=True,
                                        headerTransform=camelize_string),
        outputs=response
    )


def circleci_artifacts_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves artifacts list from CircleCI job.
    Args:
        client (Client): Client to perform the API calls
        args (Dict[str, Any]): XSOAR arguments.
        - 'job_number' (str): Number of the job to retrieve its artifacts.
        - 'artifact_suffix' (Optional[str]): Will return only artifact whom suffix corresponds to suffix given.
        - 'vc_type' (str): VC type. One of 'github', 'bitbucket'.
        - 'organization' (str): Organization to retrieve artifacts from.
                                Defaults to artifacts parameter is none is given.
        - 'project' (str): Project to retrieve artifacts from. Defaults to project parameter is none is given.
        - 'limit' (int): Maximum number of results to return.

    Returns:
        (CommandResults).
    """
    vc_type, organization, project, limit = get_common_arguments(client, args)
    job_number: str = args.get('job_number', '')
    artifact_suffix: Optional[str] = args.get('artifact_suffix')

    response = get_response_with_pagination(client.get_job_artifacts, [vc_type, organization, project, job_number],
                                            limit)

    if artifact_suffix:
        response = [artifact for artifact in response if artifact.get('path', '').endswith(artifact_suffix)]
    else:
        response = response[:limit]

    return CommandResults(
        outputs_prefix='CircleCI.Artifact',
        outputs_key_field='url',
        readable_output=tableToMarkdown('CircleCI Artifacts', response, removeNull=True,
                                        headerTransform=camelize_string),
        outputs=response
    )


def circleci_workflow_jobs_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve jobs list from CircleCI workflow.
    Args:
        client (Client): Client to perform the API calls
        args (Dict[str, Any]): XSOAR arguments.
        - 'workflow_id' (str): Workflow ID to retrieve its jobs.
        - 'limit' (int): Maximum number of results to return.

    Returns:
        (CommandResults).
    """
    workflow_id: str = args.get('workflow_id', '')
    limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT_VALUE
    response = get_response_with_pagination(client.get_workflow_jobs, [workflow_id], limit)

    return CommandResults(
        outputs_prefix='CircleCI.WorkflowJob',
        outputs_key_field='id',
        readable_output=tableToMarkdown(f'CircleCI Workflow {workflow_id} Jobs', response, removeNull=True,
                                        headerTransform=camelize_string),
        outputs=response
    )


def circleci_workflow_last_runs_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve jobs list from CircleCI workflow.
    Args:
        client (Client): Client to perform the API calls
        args (Dict[str, Any]): XSOAR arguments.
        - 'workflow_name' (str): Name of workflow to retrieve its last runs details.
        - 'vc_type' (str): VC type. One of 'github', 'bitbucket'.
        - 'organization' (str): Organization to retrieve workflow last runs from.
                                Defaults to artifacts parameter is none is given.
        - 'project' (str): Project to retrieve workflow last runs from. Defaults to project parameter is none is given.
        - 'limit' (int): Maximum number of results to return.
    Returns:
        (CommandResults).
    """
    vc_type, organization, project, limit = get_common_arguments(client, args)
    workflow_name: str = args.get('workflow_name', '')
    branch: str = args.get('branch', '')

    response = get_response_with_pagination(client.get_last_workflow_runs,
                                            [vc_type, organization, project, workflow_name, branch], limit)

    return CommandResults(
        outputs_prefix='CircleCI.WorkflowRun',
        outputs_key_field='id',
        readable_output=tableToMarkdown(f'CircleCI Workflow {workflow_name} Last Runs', response, removeNull=True,
                                        headerTransform=camelize_string),
        outputs=response
    )


def circleci_trigger_workflow_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    vc_type, organization, project, _ = get_common_arguments(client, args)
    parameters_json: str = args.get('parameters', '')

    try:
        parameters = json.loads(parameters_json)
    except ValueError:
        raise DemistoException("Failed to parse the 'parameters' argument.")

    response_json = client.trigger_workflow(vc_type, organization, project, parameters)
    response = json.loads(response_json)

    return CommandResults(
        outputs_prefix='CircleCI.WorkflowTrigger',
        outputs_key_field='id',
        readable_output=f"CircleCI Workflow created successfully, ID={response.get('number')}",
        outputs=response,
    )


''' MAIN FUNCTION '''


def main() -> None:
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    base_url: str = urljoin(params.get('url', ''), '/api/v2')
    verify_certificate: bool = not params.get('insecure', False)
    proxy: bool = params.get('proxy', False)

    api_key: str = params.get('api_key_creds', {}).get('password') or params.get('api_key', '')
    vc_type: str = params.get('vcs_type', '')
    organization: str = params.get('organization', '')
    project: str = params.get('project', '')

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify_certificate,
            proxy=proxy,
            vc_type=vc_type,
            organization=organization,
            project=project)

        if command == 'test-module':
            return_results(test_module_command(client))

        elif command == 'circleci-workflows-list':
            return_results(circleci_workflows_list_command(client, args))

        elif command == 'circleci-artifacts-list':
            return_results(circleci_artifacts_list_command(client, args))

        elif command == 'circleci-workflow-jobs-list':
            return_results(circleci_workflow_jobs_list_command(client, args))

        elif command == 'circleci-workflow-last-runs':
            return_results(circleci_workflow_last_runs_command(client, args))

        elif command == 'circleci-trigger-workflow':
            return_results(circleci_trigger_workflow_command(client, args))

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
