import demistomock as demisto
import urllib3
from CommonServerPython import *


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def abort_upload_request(self, session_id):

        headers = self._headers

        response = self._http_request('delete', f'snapshots/uploads/{session_id}', headers=headers)

        return response

    def add_project_request(self, repository, language, mode, commit, date, worker_label):
        params = assign_params(repository=repository, language=language, mode=mode, commit=commit, date=date, worker_label=worker_label)

        headers = self._headers
        headers['Content-Type'] = 'application/x-yaml'

        response = self._http_request('post', 'projects', params=params, headers=headers)

        return response

    def complete_upload_request(self, session_id):

        headers = self._headers

        response = self._http_request('post', f'snapshots/uploads/{session_id}', headers=headers)

        return response

    def get_alerts_request(self, analysis_id, sarif_version, excluded_files):
        params = assign_params(sarif_version=sarif_version, excluded_files=excluded_files)

        headers = self._headers

        response = self._http_request('get', f'analyses/{analysis_id}/alerts', params=params, headers=headers)

        return response

    def get_analysis_request(self, analysis_id):

        headers = self._headers

        response = self._http_request('get', f'analyses/{analysis_id}', headers=headers)

        return response

    def get_analysis_for_commit_request(self, project_id, commit_id):

        headers = self._headers

        response = self._http_request('get', f'analyses/{project_id}/commits/{commit_id}', headers=headers)

        return response

    def get_code_review_request(self, review_id):

        headers = self._headers

        response = self._http_request('get', f'codereviews/{review_id}', headers=headers)

        return response

    def get_project_request(self, project_id):

        headers = self._headers

        response = self._http_request('get', f'projects/{project_id}', headers=headers)

        return response

    def get_project_by_url_identifier_request(self, provider, org, name):

        headers = self._headers

        response = self._http_request('get', f'projects/{provider}/{org}/{name}', headers=headers)

        return response

    def get_project_config_request(self, project_id, source):
        params = assign_params(source=source)

        headers = self._headers

        response = self._http_request('get', f'projects/{project_id}/settings/analysis-configuration', params=params, headers=headers)

        return response

    def get_projects_request(self, limit, start):
        params = assign_params(limit=limit, start=start)

        headers = self._headers

        response = self._http_request('get', 'projects', params=params, headers=headers)

        return response

    def get_snapshot_request(self, project_id, language):

        headers = self._headers

        response = self._http_request('get', f'snapshots/{project_id}/{language}', headers=headers)

        return response

    def get_spec_request(self):

        headers = self._headers

        response = self._http_request('get', 'openapi', headers=headers)

        return response

    def get_version_request(self):

        headers = self._headers

        response = self._http_request('get', '', headers=headers)

        return response

    def init_snapshot_upload_request(self, project_id, language, commit, date):
        params = assign_params(commit=commit, date=date)

        headers = self._headers

        response = self._http_request('post', f'snapshots/{project_id}/{language}', params=params, headers=headers)

        return response

    def request_analysis_request(self, project_id, commit, language):
        params = assign_params(commit=commit, language=language)

        headers = self._headers

        response = self._http_request('post', f'analyses/{project_id}', params=params, headers=headers)

        return response

    def request_review_request(self, project_id, base, external_id, review_url, callback_url, callback_secret):

        params = {
            "base": base,
            "external-id": external_id,
            "review-url": review_url,
            "callback-url": callback_url,
            "callback-secret": callback_secret
        }
        headers = self._headers
        headers['Content-Type'] = 'application/octet-stream'

        response = self._http_request('post', f'codereviews/{project_id}', params=params, headers=headers, data="<binary>")

        return response

    def upload_part_request(self, session_id):

        headers = self._headers

        response = self._http_request('put', f'snapshots/uploads/{session_id}', headers=headers)

        return response

    def create_query_job_request(self, language, project_id, query):

        headers = self._headers
        parameters = {
            'project-id': project_id,
            'language': language
        }
        response = self._http_request('post', 'queryjobs', params=parameters, headers=headers, data=query)

        return response

    def get_issue_request(self, project_id, alert_key):

        headers = self._headers

        response = self._http_request('get', f'issues/{project_id}/{alert_key}', headers=headers)

        return response

    def get_query_job_request(self, queryjob_id):

        headers = self._headers

        response = self._http_request('get', f'queryjobs/{queryjob_id}', headers=headers)

        return response

    def get_query_job_results_for_project_request(self, queryjob_id, project_id, start, limit, nofilter):
        params = assign_params(start=start, limit=limit, nofilter=nofilter)

        headers = self._headers

        response = self._http_request('get', f'queryjobs/{queryjob_id}/results/{project_id}', params=params, headers=headers)

        return response

    def get_query_job_results_overview_request(self, queryjob_id):

        headers = self._headers

        response = self._http_request('get', f'queryjobs/{queryjob_id}/results', headers=headers)

        return response

    def get_operation_request(self, operation_id):

        headers = self._headers

        response = self._http_request('get', f'operations/{operation_id}', headers=headers)

        return response

    def get_metric_request(self, metric_id):

        headers = self._headers

        response = self._http_request('get', f'system/metrics/{metric_id}', headers=headers)

        return response

    def get_metrics_request(self):

        headers = self._headers

        response = self._http_request('get', 'system/metrics', headers=headers)

        return response

    def get_health_request(self):

        headers = self._headers

        response = self._http_request('get', 'system/health', headers=headers)

        return response


def abort_upload_command(client, args):
    session_id = str(args.get('session-id', ''))

    response = client.abort_upload_request(session_id)
    command_results = CommandResults(
        outputs_prefix='LGTM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


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


def complete_upload_command(client, args):
    session_id = str(args.get('session-id', ''))

    response = client.complete_upload_request(session_id)
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
        outputs_prefix='LGTM.code_review',
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
    command_results = CommandResults(
        outputs_prefix='LGTM',
        outputs_key_field='',
        outputs=response,
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


def get_snapshot_command(client, args):
    project_id = args.get('project-id', None)
    language = str(args.get('language', ''))

    response = client.get_snapshot_request(project_id, language)
    command_results = CommandResults(
        outputs_prefix='LGTM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_spec_command(client, args):

    response = client.get_spec_request()
    command_results = CommandResults(
        outputs_prefix='LGTM',
        outputs_key_field='',
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


def init_snapshot_upload_command(client, args):
    project_id = args.get('project-id', None)
    language = str(args.get('language', ''))
    commit = str(args.get('commit', ''))
    date = str(args.get('date', ''))

    response = client.init_snapshot_upload_request(project_id, language, commit, date)
    command_results = CommandResults(
        outputs_prefix='LGTM.upload_session',
        outputs_key_field='id',
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
    review_url = str(args.get('review-url', ''))
    callback_url = str(args.get('callback-url', ''))
    callback_secret = str(args.get('callback-secret', ''))

    response = client.request_review_request(project_id, base, external_id, review_url, callback_url, callback_secret)
    command_results = CommandResults(
        outputs_prefix='LGTM.code_review_request',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def upload_part_command(client, args):
    session_id = str(args.get('session-id', ''))

    response = client.upload_part_request(session_id)
    command_results = CommandResults(
        outputs_prefix='LGTM',
        outputs_key_field='',
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


def get_issue_command(client, args):
    project_id = args.get('project-id', None)
    alert_key = str(args.get('alert-key', ''))

    response = client.get_issue_request(project_id, alert_key)
    command_results = CommandResults(
        outputs_prefix='LGTM',
        outputs_key_field='',
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


def get_operation_command(client, args):
    operation_id = args.get('operation-id', None)

    response = client.get_operation_request(operation_id)
    command_results = CommandResults(
        outputs_prefix='LGTM.operation',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_metric_command(client, args):
    metric_id = str(args.get('metric-id', ''))

    response = client.get_metric_request(metric_id)
    command_results = CommandResults(
        outputs_prefix='LGTM.metric',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_metrics_command(client, args):

    response = client.get_metrics_request()
    command_results = CommandResults(
        outputs_prefix='LGTM.metrics_list',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_health_command(client, args):

    response = client.get_health_request()
    command_results = CommandResults(
        outputs_prefix='LGTM.health',
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
            'lgtm-abort-upload': abort_upload_command,
            'lgtm-add-project': add_project_command,
            'lgtm-complete-upload': complete_upload_command,
            'lgtm-create-query-job': create_query_job_command,
            'lgtm-get-alerts': get_alerts_command,
            'lgtm-get-analysis': get_analysis_command,
            'lgtm-get-analysis-for-commit': get_analysis_for_commit_command,
            'lgtm-get-code-review': get_code_review_command,
            'lgtm-get-issue': get_issue_command,
            'lgtm-get-metric': get_metric_command,
            'lgtm-get-metrics': get_metrics_command,
            'lgtm-get-operation': get_operation_command,
            'lgtm-get-project': get_project_command,
            'lgtm-get-project-by-url-identifier': get_project_by_url_identifier_command,
            'lgtm-get-project-config': get_project_config_command,
            'lgtm-get-projects': get_projects_command,
            'lgtm-get-query-job': get_query_job_command,
            'lgtm-get-query-job-results-for-project': get_query_job_results_for_project_command,
            'lgtm-get-query-job-results-overview': get_query_job_results_overview_command,
            'lgtm-get-snapshot': get_snapshot_command,
            'lgtm-get-spec': get_spec_command,
            'lgtm-get-version': get_version_command,
            'lgtm-init-snapshot-upload': init_snapshot_upload_command,
            'lgtm-request-analysis': request_analysis_command,
            'lgtm-request-review': request_review_command,
            'lgtm-upload-part': upload_part_command
        }

        if command == 'test-module':
            test_module(client)
        else:
            return_results(commands[command](client, args))

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
