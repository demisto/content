import demistomock as demisto
import urllib3
from CommonServerPython import *


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def abort_upload_request(self, session_id):
        response = self._http_request('delete', f'snapshots/uploads/{session_id}')

        return response

    def add_project_request(self, repository, language, mode, commit, date, worker_label):
        params = assign_params(repository=repository, language=language, mode=mode,
                               commit=commit, date=date, worker_label=worker_label)
        headers = self._headers
        headers['Content-Type'] = 'application/x-yaml'
        response = self._http_request('post', 'projects', params=params, headers=headers)

        return response

    def get_alerts_request(self, analysis_id, sarif_version, excluded_files):
        params = assign_params(sarif_version=sarif_version, excluded_files=excluded_files)
        response = self._http_request('get', f'analyses/{analysis_id}/alerts', params=params)

        return response

    def get_analysis_request(self, analysis_id):
        response = self._http_request('get', f'analyses/{analysis_id}')

        return response

    def get_analysis_for_commit_request(self, project_id, commit_id):
        response = self._http_request('get', f'analyses/{project_id}/commits/{commit_id}')

        return response

    def get_code_review_request(self, review_id):
        response = self._http_request('get', f'codereviews/{review_id}')

        return response

    def get_project_request(self, project_id):
        response = self._http_request('get', f'projects/{project_id}')

        return response

    def get_project_by_url_identifier_request(self, provider, org, name):
        response = self._http_request('get', f'projects/{provider}/{org}/{name}')

        return response

    def get_project_config_request(self, project_id, source):
        params = assign_params(source=source)
        response = self._http_request(
            'get', f'projects/{project_id}/settings/analysis-configuration', params=params, resp_type='text')

        return response

    def get_projects_request(self, limit, start):
        params = assign_params(limit=limit, start=start)
        response = self._http_request('get', 'projects', params=params)

        return response

    def get_version_request(self):
        response = self._http_request('get', '')

        return response

    def request_analysis_request(self, project_id, commit, language):
        params = assign_params(commit=commit, language=language)
        response = self._http_request('post', f'analyses/{project_id}', params=params)

        return response

    def request_review_request(self, project_id, base, external_id,
                               callback_url, callback_secret, patch_file):
        params = {
            "base": base,
            "external-id": external_id,
            "callback-url": callback_url,
            "callback-secret": callback_secret
        }
        headers = self._headers
        headers['Content-Type'] = 'application/octet-stream'
        response = self._http_request('post', f'codereviews/{project_id}', params=params,
                                      headers=headers, files=patch_file)

        return response

    def create_query_job_request(self, language, project_id, query):
        parameters = {
            'project-id': project_id,
            'language': language
        }
        response = self._http_request('post', 'queryjobs', params=parameters, data=query)

        return response

    def get_query_job_request(self, queryjob_id):
        response = self._http_request('get', f'queryjobs/{queryjob_id}')

        return response

    def get_query_job_results_for_project_request(self, queryjob_id, project_id, start, limit, nofilter):
        params = assign_params(start=start, limit=limit, nofilter=nofilter)
        response = self._http_request('get', f'queryjobs/{queryjob_id}/results/{project_id}', params=params)

        return response

    def get_query_job_results_overview_request(self, queryjob_id):
        response = self._http_request('get', f'queryjobs/{queryjob_id}/results')

        return response


def add_project_command(client, args):
    repository = str(args.get('repository', ''))
    language = argToList(args.get('language', []))
    mode = str(args.get('mode', ''))
    commit = str(args.get('commit', ''))
    date = str(args.get('date', ''))
    worker_label = argToList(args.get('worker-label', []))

    response = client.add_project_request(repository, language, mode, commit, date, worker_label)
    command_results = CommandResults(
        outputs_prefix='LGTM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_alerts_command(client, args):
    analysis_id = str(args.get('analysis-id', ''))
    sarif_version = str(args.get('sarif-version', ''))
    excluded_files = argToBoolean(args.get('excluded-files', False))

    response = client.get_alerts_request(analysis_id, sarif_version, excluded_files)
    command_results = CommandResults(
        outputs_prefix='LGTM.alerts',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_analysis_command(client, args):
    analysis_id = str(args.get('analysis-id', ''))

    response = client.get_analysis_request(analysis_id)
    command_results = CommandResults(
        outputs_prefix='LGTM.analysis_summary',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_analysis_for_commit_command(client, args):
    project_id = args.get('project-id', None)
    commit_id = str(args.get('commit-id', ''))

    response = client.get_analysis_for_commit_request(project_id, commit_id)
    command_results = CommandResults(
        outputs_prefix='LGTM.analysis_summary',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_code_review_command(client, args):
    review_id = str(args.get('review-id', ''))

    response = client.get_code_review_request(review_id)
    command_results = CommandResults(
        outputs_prefix='LGTM.code_review_result',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_project_command(client, args):
    project_id = args.get('project-id', None)

    response = client.get_project_request(project_id)
    command_results = CommandResults(
        outputs_prefix='LGTM.project_details',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_project_by_url_identifier_command(client, args):
    provider = str(args.get('provider', ''))
    org = str(args.get('org', ''))
    name = str(args.get('name', ''))

    response = client.get_project_by_url_identifier_request(provider, org, name)
    command_results = CommandResults(
        outputs_prefix='LGTM.project_details',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_project_config_command(client, args):
    project_id = args.get('project-id', None)
    source = str(args.get('source', ''))

    response = client.get_project_config_request(project_id, source)
    human_readable = tableToMarkdown(t=response, name='Project Config', headers='Config')

    command_results = CommandResults(
        outputs_prefix='LGTM.config',
        outputs_key_field='',
        outputs=response,
        readable_output=human_readable,
        raw_response=response
    )

    return command_results


def get_projects_command(client, args):
    limit = args.get('limit', None)
    start = str(args.get('start', ''))

    response = client.get_projects_request(limit, start)
    command_results = CommandResults(
        outputs_prefix='LGTM.project_list',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_version_command(client, args):

    response = client.get_version_request()
    command_results = CommandResults(
        outputs_prefix='LGTM.version',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def request_analysis_command(client, args):
    project_id = args.get('project-id', None)
    commit = str(args.get('commit', ''))
    language = argToList(args.get('language', []))

    response = client.request_analysis_request(project_id, commit, language)
    command_results = CommandResults(
        outputs_prefix='LGTM.analysis_request',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def request_review_command(client, args):
    project_id = args.get('project-id', None)
    base = str(args.get('base', ''))
    external_id = args.get('external-id', None)
    callback_url = str(args.get('callback-url', ''))
    callback_secret = str(args.get('callback-secret', ''))
    patch_file_entry_id = args.get('patch-entry-id', None)

    patch_file_info = demisto.getFilePath(patch_file_entry_id)
    uploaded_patch_file = open(patch_file_info['path'], 'rb')
    patch_file = {'file': (patch_file_info['name'], uploaded_patch_file)}

    response = client.request_review_request(project_id, base, external_id, callback_url, callback_secret, patch_file)
    command_results = CommandResults(
        outputs_prefix='LGTM.code_review_request',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_query_job_command(client, args):
    language = str(args.get('language', ''))
    project_id = argToList(args.get('project-id', []))
    query = str(args.get('query-list', ''))

    response = client.create_query_job_request(language, project_id, query)
    command_results = CommandResults(
        outputs_prefix='LGTM.queryjob',
        outputs_key_field='LGTM.queryjob.task-result.id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_query_job_command(client, args):
    queryjob_id = str(args.get('queryjob-id', ''))

    response = client.get_query_job_request(queryjob_id)
    command_results = CommandResults(
        outputs_prefix='LGTM.queryjob',
        outputs_key_field='LGTM.queryjob.id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_query_job_results_for_project_command(client, args):
    queryjob_id = str(args.get('queryjob-id', ''))
    project_id = str(args.get('project-id', ''))
    start = args.get('start', None)
    limit = args.get('limit', None)
    nofilter = argToBoolean(args.get('nofilter', False))

    response = client.get_query_job_results_for_project_request(queryjob_id, project_id, start, limit, nofilter)
    command_results = CommandResults(
        outputs_prefix='LGTM.queryjob_project_results',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_query_job_results_overview_command(client, args):
    queryjob_id = str(args.get('queryjob-id', ''))

    response = client.get_query_job_results_overview_request(queryjob_id)
    command_results = CommandResults(
        outputs_prefix='LGTM.queryjob_results_overview',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client):
    # Test functions here
    client.get_version_request()
    demisto.results('ok')


def main():

    params = demisto.params()
    args = demisto.args()
    url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    headers = {}
    headers['Authorization'] = 'Bearer ' + f'{params["api_key"]}'
    headers['Content-Type'] = 'text/plain'

    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        urllib3.disable_warnings()
        client = Client(urljoin(url, ""), verify_certificate, proxy, headers=headers, auth=None)
        commands = {
            'lgtm-add-project': add_project_command,
            'lgtm-create-query-job': create_query_job_command,
            'lgtm-get-alerts': get_alerts_command,
            'lgtm-get-analysis': get_analysis_command,
            'lgtm-get-analysis-for-commit': get_analysis_for_commit_command,
            'lgtm-get-code-review': get_code_review_command,
            'lgtm-get-project': get_project_command,
            'lgtm-get-project-by-url-identifier': get_project_by_url_identifier_command,
            'lgtm-get-project-config': get_project_config_command,
            'lgtm-get-projects': get_projects_command,
            'lgtm-get-query-job': get_query_job_command,
            'lgtm-get-query-job-results-for-project': get_query_job_results_for_project_command,
            'lgtm-get-query-job-results-overview': get_query_job_results_overview_command,
            'lgtm-get-version': get_version_command,
            'lgtm-request-analysis': request_analysis_command,
            'lgtm-request-review': request_review_command
        }

        if command == 'test-module':
            test_module(client)

        else:
            return_results(commands[command](client, args))

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
