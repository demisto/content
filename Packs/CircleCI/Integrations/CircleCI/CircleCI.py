from typing import Dict, Tuple

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''
DEFAULT_VCS_TYPE = 'github'

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool, vc_type: str, organization: str,
                 project: str):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers={'authorization': f'Basic {api_key}'})
        self.vc_type = vc_type
        self.organization = organization
        self.project = project

    def get_job_artifacts(self, vc_type: str, organization: str, project: str, job_name: str):
        return self._http_request(
            method='GET',
            url_suffix=f'/project/{vc_type}/{organization}/{project}/{job_name}/artifacts'
        )

    def get_workflows_list(self, vc_type: str, organization: str, project: str, workflow_name: Optional[str] = None):
        url_suffix = f'insights/{vc_type}/{organization}/{project}/workflows/'
        if workflow_name:
            url_suffix = f'{url_suffix}/{workflow_name}'
        return self._http_request(
            method='GET',
            url_suffix=url_suffix
        )

    def get_workflow_jobs(self, vc_type: str, organization: str, project: str, workflow_id: Optional[str] = None):
        if workflow_id:
            url_suffix = f'/workflow/{workflow_id}/job'
        else:
            url_suffix = f'insights/{vc_type}/{organization}/{project}/workflows'
        return self._http_request(
            method='GET',
            url_suffix=url_suffix
        )


''' HELPER FUNCTIONS '''


def get_args_with_default_as_instance_parameters(client: Client, args: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Performs same logic for getting arguments whom default value is set to the instance parameter configuration.
    Args:
        client (Client): Client to retrieve instance parameter configurations in case argument was not given.
        args (Dict[str, Any]): XSOAR arguments.

    Returns:
        (Tuple[str, str, str]): (vcs_type, organization, project).
    """
    vc_type: str = args.get('vcs_type') or client.vc_type
    organization: str = args.get('organization') or client.organization
    project: str = args.get('project') or client.project

    return vc_type, organization, project


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
        vc_type, organization, project = get_args_with_default_as_instance_parameters(client, dict())
        client.get_workflow_jobs(vc_type, organization, project)
    except DemistoException as e:
        if 'not found' in str(e).lower():
            message = 'Error connecting to CircleCI. Make sure your URL and API token are configured correctly.'
        else:
            raise e
    return message


def circleci_workflows_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves workflows list details from CircleCI.
    Args:
        client (Client): Client to perform the API calls
        args (Dict[str, Any]): XSOAR arguments,
        - 'workflow' (Optional[str]): Name of specific workflow to retrieve its last runs.
        - 'vc_type' (str): VC type. One of 'github', 'bitbucket'.
        - 'organization' (str): Organization to retrieve workflows from.
                                Defaults to organization parameter is none is given.
        - 'project' (str): Project to retrieve workflows from. Defaults to project parameter is none is given.

    Returns:
        (CommandResults).
    """
    vc_type, organization, project = get_args_with_default_as_instance_parameters(client, args)
    workflow_name: Optional[str] = args.get('workflow')

    response = client.get_workflows_list(vc_type, organization, project, workflow_name)

    return CommandResults(
        outputs_prefix='CircleCI.Pipeline',
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
        args (Dict[str, Any]): XSOAR arguments,
        - 'job_number' (str): Number of the job to retrieve its artifacts.
        - 'vc_type' (str): VC type. One of 'github', 'bitbucket'.
        - 'organization' (str): Organization to retrieve artifacts from.
                                Defaults to artifacts parameter is none is given.
        - 'project' (str): Project to retrieve artifacts from. Defaults to project parameter is none is given.

    Returns:
        (CommandResults).
    """
    vc_type, organization, project = get_args_with_default_as_instance_parameters(client, args)
    job_number = args.get('job', '')

    response = client.get_job_artifacts(vc_type, organization, project, job_number)

    return CommandResults(
        outputs_prefix='CircleCI.Job',
        outputs_key_field='id',
        readable_output=tableToMarkdown('CircleCI Jobs', response, removeNull=True,
                                        headerTransform=camelize_string),
        outputs=response
    )


def circleci_workflow_jobs_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieves jobs list from CircleCI workflow.
    Args:
        client (Client): Client to perform the API calls
        args (Dict[str, Any]): XSOAR arguments,
        - 'workflow_id' (str): Workflow ID to retrieve its jobs.
        - 'vc_type' (str): VC type. One of 'github', 'bitbucket'.
        - 'organization' (str): Organization to retrieve workflows from.
                                Defaults to organization parameter is none is given.
        - 'project' (str): Project to retrieve workflows from. Defaults to project parameter is none is given.

    Returns:
        (CommandResults).
    """
    vc_type, organization, project = get_args_with_default_as_instance_parameters(client, args)
    workflow_id: Optional[str] = args.get('workflow_id')

    response = client.get_workflow_jobs(vc_type, organization, project, workflow_id)

    return CommandResults(
        outputs_prefix='CircleCI.Job',
        outputs_key_field='id',
        readable_output=tableToMarkdown('CircleCI Jobs', response, removeNull=True,
                                        headerTransform=camelize_string),
        outputs=response
    )


''' MAIN FUNCTION '''


def main() -> None:
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    base_url: str = params.get('url', '')
    verify_certificate: bool = not params.get('insecure', False)
    proxy: bool = params.get('proxy', False)

    api_key: str = params.get('api_key', '')
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
        # x = client.get_workflows_list()
        # for z in x['items']:
        #     id_ = z['id']
        #     jobs = client.get_workflow_jobs(id_)
        #     for job in jobs['items']:
        #         if job['name'] == 'Run Unit Testing And Lint':
        #             artifacts = client.a(job['job_number'])
        #             for artifact in artifacts['items']:
        #                 if 'failed_lint_report' in artifact['path']:
        #                     bb = client._http_request(method='GET', full_url=artifact['url'], resp_type='text')
        #                     bbb = bb.split('\n')
        #                     if len(bbb) > 1:
        #                         bbbb = 3

        if command == 'test-module':
            test_module_command(client)

        if command == 'circleci-workflows-list':
            return_results(circleci_workflows_list_command(client, args))

        if command == 'circleci-artifacts-list':
            return_results(circleci_artifacts_list_command(client, args))

        if command == 'cirleci-workflow-jobs-list':
            return_results(circleci_workflow_jobs_list_command(client, args))

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
