import demistomock as demisto
import urllib3
from CommonServerPython import *

JOB_FIELDS_TO_EXTRACT = {'created_at', 'started_at', 'finished_at', 'duration', 'id', 'name', 'pipeline', 'ref',
                         'stage', 'web_url'}
PIPELINE_SCHEDULE_FIELDS_TO_EXTRACT = {'id', 'description', 'ref', 'next_run_at', 'active', 'created_at', 'updated_at',
                                       'last_pipeline'}
PIPELINE_FIELDS_TO_EXTRACT = {'id', 'project_id', 'status', 'ref', 'sha', 'created_at', 'updated_at', 'started_at',
                              'finished_at', 'duration', 'web_url', 'user'}


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers)

    def get_projects_request(self, repository_storage, last_activity_before, min_access_level, simple, sort,
                             membership, search_namespaces, archived, search, id_before, last_activity_after, starred,
                             id_after, owned, order_by, statistics, visibility, with_custom_attributes,
                             with_issues_enabled, with_merge_requests_enabled, with_programming_language):
        params = assign_params(repository_storage=repository_storage, last_activity_before=last_activity_before,
                               min_access_level=min_access_level, simple=simple, sort=sort, membership=membership,
                               search_namespaces=search_namespaces, archived=archived, search=search,
                               id_before=id_before, last_activity_after=last_activity_after,
                               starred=starred, id_after=id_after, owned=owned, order_by=order_by,
                               statistics=statistics, visibility=visibility,
                               with_custom_attributes=with_custom_attributes, with_issues_enabled=with_issues_enabled,
                               with_merge_requests_enabled=with_merge_requests_enabled,
                               with_programming_language=with_programming_language)
        headers = self._headers
        response = self._http_request('get', 'projects', params=params, headers=headers)
        return response

    def projects_get_access_requests_request(self, id_):
        headers = self._headers
        response = self._http_request('get', f'projects/{id_}/access_requests', headers=headers)
        return response

    def projects_request_access_request(self, id_):
        headers = self._headers
        response = self._http_request('post', f'projects/{id_}/access_requests', headers=headers)
        return response

    def projects_approve_access_request(self, id_, user_id, access_level):
        params = assign_params(access_level=access_level)
        headers = self._headers
        response = self._http_request('put', f'projects/{id_}/access_requests/{user_id}/approve', params=params,
                                      headers=headers)
        return response

    def projects_deny_access_request(self, id_, user_id):
        headers = self._headers
        self._http_request('delete', f'projects/{id_}/access_requests/{user_id}', headers=headers, resp_type='text')
        response = {
            'id': user_id,
            'state': 'denied'
        }
        return response

    def projects_get_repository_branches_request(self, id_, search):
        params = assign_params(search=search)
        headers = self._headers
        response = self._http_request('get', f'projects/{id_}/repository/branches', params=params, headers=headers)
        return response

    def projects_create_repository_branch_request(self, id_, branch, ref):
        params = assign_params(branch=branch, ref=ref)
        headers = self._headers
        response = self._http_request('post', f'projects/{id_}/repository/branches', params=params, headers=headers)
        return response

    def projects_delete_repository_branch_request(self, id_, branch):
        headers = self._headers
        self._http_request('delete', f'projects/{id_}/repository/branches/{branch}', headers=headers, resp_type='text')
        response = {
            'message': f'Branch \'{branch}\' is deleted.',
        }
        return response

    def projects_delete_repository_merged_branches_request(self, id_):
        headers = self._headers
        response = self._http_request('delete', f'projects/{id_}/repository/merged_branches', headers=headers)
        return response

    def get_version_request(self):
        headers = self._headers
        response = self._http_request('get', 'version', headers=headers)
        return response

    def get_pipeline_schedules_request(self, project_id: str, pipeline_schedule_id: Optional[str]):
        headers = self._headers
        base_suffix = f'projects/{project_id}/pipeline_schedules'
        final_suffix = f'{base_suffix}/{pipeline_schedule_id}' if pipeline_schedule_id else base_suffix
        response = self._http_request('get', final_suffix, headers=headers)
        return response

    def get_pipeline_request(self, project_id: str, pipeline_id: Optional[str], ref: Optional[str],
                             status: Optional[str]):
        headers = self._headers
        base_suffix = f'projects/{project_id}/pipelines'
        final_suffix = f'{base_suffix}/{pipeline_id}' if pipeline_id else base_suffix
        response = self._http_request('get', final_suffix, headers=headers,
                                      params=assign_params(ref=ref, status=status))
        return response

    def get_pipeline_job_request(self, project_id: str, pipeline_id: str):
        headers = self._headers
        suffix = f'projects/{project_id}/pipelines/{pipeline_id}/jobs'
        response = self._http_request('get', suffix, headers=headers)
        return response

    def get_job_artifact_request(self, project_id: str, job_id: str, artifact_path_suffix: str):
        headers = self._headers
        suffix = f'projects/{project_id}/jobs/{job_id}/artifacts/{artifact_path_suffix}'
        response = self._http_request('get', suffix, headers=headers, resp_type='text')
        return response


def get_projects_command(client, args):
    repository_storage = str(args.get('repository_storage', ''))
    last_activity_before = str(args.get('last_activity_before', ''))
    min_access_level = str(args.get('min_access_level', ''))
    simple = argToBoolean(args.get('simple', False))
    sort = str(args.get('sort', ''))
    membership = argToBoolean(args.get('membership', False))
    search_namespaces = argToBoolean(args.get('search_namespaces', False))
    archived = argToBoolean(args.get('archived', False))
    search = str(args.get('search', ''))
    id_before = str(args.get('id_before', ''))
    last_activity_after = str(args.get('last_activity_after', ''))
    starred = argToBoolean(args.get('starred', False))
    id_after = str(args.get('id_after', ''))
    owned = argToBoolean(args.get('owned', False))
    order_by = str(args.get('order_by', ''))
    statistics = argToBoolean(args.get('statistics', False))
    visibility = str(args.get('visibility', ''))
    with_custom_attributes = argToBoolean(args.get('with_custom_attributes', False))
    with_issues_enabled = argToBoolean(args.get('with_issues_enabled', False))
    with_merge_requests_enabled = argToBoolean(args.get('with_merge_requests_enabled', False))
    with_programming_language = str(args.get('with_programming_language', ''))

    response = client.get_projects_request(repository_storage, last_activity_before, min_access_level, simple, sort,
                                           membership, search_namespaces, archived, search, id_before,
                                           last_activity_after, starred, id_after, owned, order_by, statistics,
                                           visibility, with_custom_attributes, with_issues_enabled,
                                           with_merge_requests_enabled, with_programming_language)
    command_results = CommandResults(
        outputs_prefix='GitLab.Projects',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def projects_get_access_requests_command(client, args):
    id_ = args.get('id', None)
    response = client.projects_get_access_requests_request(id_)
    command_results = CommandResults(
        outputs_prefix='GitLab.AccessRequests',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )
    return command_results


def projects_request_access_command(client, args):
    id_ = args.get('id', None)
    response = client.projects_request_access_request(id_)
    command_results = CommandResults(
        outputs_prefix='GitLab.AccessRequests',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )
    return command_results


def projects_approve_access_command(client, args):
    id_ = args.get('id', None)
    user_id = args.get('user_id', None)
    access_level = args.get('access_level', None)
    response = client.projects_approve_access_request(id_, user_id, access_level)
    command_results = CommandResults(
        outputs_prefix='GitLab.AccessRequests',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )
    return command_results


def projects_deny_access_command(client, args):
    id_ = args.get('id', None)
    user_id = args.get('user_id', None)
    response = client.projects_deny_access_request(id_, user_id)
    command_results = CommandResults(
        outputs_prefix='GitLab.AccessRequests',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )
    return command_results


def projects_get_repository_branches_command(client, args):
    id_ = args.get('id', None)
    search = str(args.get('search', ''))

    response = client.projects_get_repository_branches_request(id_, search)
    command_results = CommandResults(
        outputs_prefix='GitLab.Branches',
        outputs_key_field='web_url',
        outputs=response,
        raw_response=response
    )

    return command_results


def projects_create_repository_branch_command(client, args):
    id_ = args.get('id', None)
    branch = str(args.get('branch', ''))
    ref = str(args.get('ref', ''))

    response = client.projects_create_repository_branch_request(id_, branch, ref)
    command_results = CommandResults(
        outputs_prefix='GitLab.Branches',
        outputs_key_field='web_url',
        outputs=response,
        raw_response=response
    )

    return command_results


def projects_delete_repository_branch_command(client, args):
    id_ = args.get('id', None)
    branch = str(args.get('branch', ''))

    response = client.projects_delete_repository_branch_request(id_, branch)
    command_results = CommandResults(
        outputs_prefix='GitLab.Branches',
        outputs_key_field='web_url',
        outputs=response,
        raw_response=response
    )

    return command_results


def projects_delete_repository_merged_branches_command(client, args):
    id_ = args.get('id', None)

    response = client.projects_delete_repository_merged_branches_request(id_)
    command_results = CommandResults(
        outputs_prefix='GitLab',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_version_command(client, args):
    response = client.get_version_request()
    command_results = CommandResults(
        outputs_prefix='GitLab',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gitlab_pipelines_schedules_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    project_id = args.get('project_id', '')
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


def gitlab_pipelines_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    project_id = args.get('project_id', '')
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


def gitlab_jobs_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    project_id = args.get('project_id', '')
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


def gitlab_artifact_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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
    project_id = args.get('project_id', '')
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


def test_module(client):
    # Test functions here
    response = client.get_version_request()
    if response.get('version'):
        demisto.results('ok')
    else:
        demisto.results('Test Failed:' + response)


def main():
    params = demisto.params()
    args = demisto.args()
    url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    headers = {}
    headers['PRIVATE-TOKEN'] = f'{params["api_key"]}'

    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        urllib3.disable_warnings()
        client = Client(urljoin(url, ""), verify_certificate, proxy, headers=headers)
        commands = {
            'gitlab-get-projects': get_projects_command,
            'gitlab-projects-get-access-requests': projects_get_access_requests_command,
            'gitlab-projects-request-access': projects_request_access_command,
            'gitlab-projects-approve-access': projects_approve_access_command,
            'gitlab-projects-deny-access': projects_deny_access_command,
            'gitlab-projects-get-repository-branches': projects_get_repository_branches_command,
            'gitlab-projects-create-repository-branch': projects_create_repository_branch_command,
            'gitlab-projects-delete-repository-branch': projects_delete_repository_branch_command,
            'gitlab-projects-delete-repository-merged-branches': projects_delete_repository_merged_branches_command,
            'gitlab-get-version': get_version_command,
            'gitlab-pipelines-schedules-list': gitlab_pipelines_schedules_list_command,
            'gitlab-pipelines-list': gitlab_pipelines_list_command,
            'gitlab-jobs-list': gitlab_jobs_list_command,
            'gitlab-artifact-get': gitlab_artifact_get_command
        }

        if command == 'test-module':
            test_module(client)
        else:
            return_results(commands[command](client, args))

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
