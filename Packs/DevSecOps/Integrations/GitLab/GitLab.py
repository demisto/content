import demistomock as demisto
import urllib3
from CommonServerPython import *


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers)

    def get_projects_request(self, repository_storage, last_activity_before, min_access_level, simple, sort, membership, search_namespaces, archived, search, id_before, last_activity_after, starred, id_after, owned, order_by, statistics, visibility, with_custom_attributes, with_issues_enabled, with_merge_requests_enabled, with_programming_language):
        params = assign_params(repository_storage=repository_storage, last_activity_before=last_activity_before, min_access_level=min_access_level, simple=simple, sort=sort, membership=membership, search_namespaces=search_namespaces, archived=archived, search=search, id_before=id_before, last_activity_after=last_activity_after,
                               starred=starred, id_after=id_after, owned=owned, order_by=order_by, statistics=statistics, visibility=visibility, with_custom_attributes=with_custom_attributes, with_issues_enabled=with_issues_enabled, with_merge_requests_enabled=with_merge_requests_enabled, with_programming_language=with_programming_language)
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
        response = self._http_request('put', f'projects/{id_}/access_requests/{user_id}/approve', params=params, headers=headers)
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

    response = client.get_projects_request(repository_storage, last_activity_before, min_access_level, simple, sort, membership, search_namespaces, archived, search, id_before,
                                           last_activity_after, starred, id_after, owned, order_by, statistics, visibility, with_custom_attributes, with_issues_enabled, with_merge_requests_enabled, with_programming_language)
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
        }

        if command == 'test-module':
            test_module(client)
        else:
            return_results(commands[command](client, args))

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
