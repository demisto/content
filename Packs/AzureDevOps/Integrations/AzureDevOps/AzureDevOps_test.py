import pytest

from CommonServerPython import *

ORGANIZATION = "XSOAR"
BASE_URL = F'https://dev.azure.com/{ORGANIZATION}'
CLIENT_ID = "XXXX"


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    with open(f'test_data/{file_name}', encoding='utf-8') as mock_file:
        return mock_file.read()


def get_azure_access_token_mock():
    return {
        'access_token': 'my-access-token',
        'expires_in': 3595,
        'refresh_token': 'my-refresh-token',
    }


def test_azure_devops_pipeline_run_command(requests_mock):
    """
    Scenario: run-pipeline.
    Given:
     - User has provided valid credentials.
    When:
     - azure-devops-pipeline-run called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureDevOps import Client, pipeline_run_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    project = 'test'
    pipeline_id = '1'
    url = f'{BASE_URL}/{project}/_apis/pipelines/{pipeline_id}/runs'

    mock_response = json.loads(load_mock_response('run_pipeline.json'))
    requests_mock.post(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = pipeline_run_command(client, {'project': project,
                                           'pipeline_id': pipeline_id,
                                           'branch_name': 'my-branch'})

    assert len(result.outputs) == 10
    assert result.outputs_prefix == 'AzureDevOps.PipelineRun'
    assert result.outputs.get('project') == project
    assert result.outputs.get('pipeline').get('name') == 'xsoar'
    assert result.outputs.get('pipeline').get('id') == "1"
    assert result.outputs.get('run_id') == "12"


def test_azure_devops_user_add_command(requests_mock):
    """
    Scenario: Add user to organization.
    Given:
     - User has provided valid credentials.
    When:
     - azure-devops-user-add called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
     - Validate API operation result error handling.
    """
    from AzureDevOps import Client, user_add_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    user_email = 'test@xsoar.com'
    account_license_type = 'express'
    group_type = 'projectReader'
    project_id = '123'

    url = f"https://vsaex.dev.azure.com/{ORGANIZATION}/_apis/UserEntitlements"

    mock_response = json.loads(load_mock_response('add_user.json'))
    requests_mock.post(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = user_add_command(client, {'user_email': user_email,
                                       'account_license_type': account_license_type,
                                       'group_type': group_type,
                                       'project_id': project_id})

    assert len(result.outputs) == 8
    assert result.outputs_prefix == 'AzureDevOps.User'
    assert result.outputs.get('id') == 'XXX'
    assert dict_safe_get(result.outputs, ['accessLevel', 'accountLicenseType']) == 'express'
    assert result.outputs.get('lastAccessedDate') == '0001-01-01T00:00:00Z'

    # Error case
    mock_response = json.loads(load_mock_response('add_user_error.json'))
    requests_mock.post(url, json=mock_response)

    with pytest.raises(Exception):
        user_add_command(client, {'user_email': user_email,
                                  'account_license_type': account_license_type,
                                  'group_type': group_type,
                                  'project_id': project_id})


def test_azure_devops_user_remove_command(requests_mock):
    """
    Scenario: Remove the user from all project memberships.
    Given:
     - User has provided valid credentials.
    When:
     - azure-devops-user-remove called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
     """
    from AzureDevOps import Client, user_remove_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    user_id = '1'

    url = f'https://vsaex.dev.azure.com/{ORGANIZATION}/_apis/userentitlements/{user_id}'

    requests_mock.delete(url)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = user_remove_command(client, {'user_id': user_id})

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == f'User {user_id} was successfully removed from the organization.'


def test_azure_devops_pull_request_create_command(requests_mock):
    """
    Scenario: Create a new pull-request..
    Given:
     - User has provided valid credentials.
    When:
     - azure-devops-pull-request-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureDevOps import Client, pull_request_create_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    project = 'test'
    repository_id = '1'
    url = f'{BASE_URL}/{project}/_apis/git/repositories/{repository_id}/pullrequests'

    mock_response = json.loads(load_mock_response('pull_request.json'))
    requests_mock.post(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = pull_request_create_command(client, {'project': project,
                                                  'repository_id': repository_id,
                                                  'source_branch': 'my-branch',
                                                  'target_branch': 'main',
                                                  'title': 'test-title',
                                                  'description': 'test-description',
                                                  'reviewers_ids': '2'},
                                         project=project, repository=repository_id)

    assert len(result.outputs) == 21
    assert result.outputs_prefix == 'AzureDevOps.PullRequest'
    assert result.outputs.get('repository').get('name') == 'xsoar'


def test_azure_devops_pull_request_get_command(requests_mock):
    """
    Scenario: Retrieve pull-request information.
    Given:
     - User has provided valid credentials.
    When:
     - azure-devops-pull-request-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureDevOps import Client, pull_request_get_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    project = 'test'
    repository_id = '1'
    pull_request_id = '2'
    url = f'{BASE_URL}/{project}/_apis/git/repositories/{repository_id}/pullrequests/{pull_request_id}'

    mock_response = json.loads(load_mock_response('pull_request.json'))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = pull_request_get_command(client, {'project': project,
                                               'repository_id': repository_id,
                                               'pull_request_id': pull_request_id
                                               })

    assert len(result.outputs) == 21
    assert result.outputs_prefix == 'AzureDevOps.PullRequest'
    assert result.outputs.get('repository').get('name') == 'xsoar'


def test_azure_devops_pull_request_update_command(requests_mock):
    """
    Scenario: Update a pull request.
    Given:
     - User has provided valid credentials.
    When:
     - azure-devops-pull-request-update called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
     - Ensure command validates that is at least one update parameter exists.
    """
    from AzureDevOps import Client, pull_request_update_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    project = 'test'
    repository_id = '1'
    pull_request_id = '2'
    url = f'{BASE_URL}/{project}/_apis/git/repositories/{repository_id}/pullrequests/{pull_request_id}'

    mock_response = json.loads(load_mock_response('pull_request.json'))
    requests_mock.patch(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = pull_request_update_command(client, {'project': project,
                                                  'repository_id': repository_id,
                                                  'pull_request_id': pull_request_id,
                                                  'title': 'new-title'
                                                  },
                                         project=project, repository=repository_id)

    assert len(result.outputs) == 21
    assert result.outputs_prefix == 'AzureDevOps.PullRequest'
    assert result.outputs.get('repository').get('name') == 'xsoar'

    with pytest.raises(Exception):
        pull_request_update_command(client, {'project': project,
                                             'repository_id': repository_id,
                                             'pull_request_id': pull_request_id
                                             })


def test_azure_devops_pull_request_list_command(requests_mock):
    """
    Scenario: Retrieve pull requests in repository.
    Given:
     - User has provided valid credentials.
    When:
     - azure-devops-pull-request-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
     - Ensure the command validates the 'limit' parameter value. The parameter value should be equals or greater than 1.
    """
    from AzureDevOps import Client, pull_requests_list_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    project = 'test'
    repository = 'xsoar'

    url = f'{BASE_URL}/{project}/_apis/git/repositories/{repository}/pullrequests/'

    mock_response = json.loads(load_mock_response('list_pull_request.json'))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = pull_requests_list_command(client, {'project': project,
                                                 'repository': repository
                                                 },
                                        project=project, repository=repository)

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureDevOps.PullRequest'
    assert dict_safe_get(result.outputs[0], ['repository', 'name']) == 'xsoar'

    with pytest.raises(Exception):
        pull_requests_list_command(client, {'project': project,
                                            'repository': repository,
                                            'limit': '-1'
                                            })


def test_azure_devops_project_list_command(requests_mock):
    """
    Scenario: Retrieve all projects in the organization that the authenticated user has access to.
    Given:
     - User has provided valid credentials.
    When:
     - azure-devops-project-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
     - Ensure the command validates the 'limit' parameter value. The parameter value should be equals or greater than 1.
    """
    from AzureDevOps import Client, project_list_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    url = f'{BASE_URL}/_apis/projects'

    mock_response = json.loads(load_mock_response('list_project.json'))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = project_list_command(client, {})

    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'AzureDevOps.Project'
    assert result.outputs[0].get('name') == 'xsoar'
    assert result.outputs[0].get('visibility') == 'private'
    with pytest.raises(Exception):
        project_list_command(client, {'limit': '-1'})


def test_azure_devops_repository_list_command(requests_mock):
    """
    Scenario: Retrieve git repositories in the organization project.
    Given:
     - User has provided valid credentials.
    When:
     - azure-devops-repository-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
     - Ensure the command validates the 'limit' parameter value. The parameter value should be equals or greater than 1.
    """
    from AzureDevOps import Client, repository_list_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    project = 'xsoar'
    url = f'{BASE_URL}/{project}/_apis/git/repositories'

    mock_response = json.loads(load_mock_response('list_repositories.json'))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = repository_list_command(client, {"project": project})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureDevOps.Repository'
    assert result.outputs[0].get('name') == 'xsoar'
    with pytest.raises(Exception):
        repository_list_command(client, {"project": project, 'limit': '-1'})


def test_azure_devops_users_query_command(requests_mock):
    """
    Scenario: Query users in the organization.
    Given:
     - User has provided valid credentials.
    When:
     - azure-devops-user-query called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
     - Ensure the command validates the 'limit' parameter value. The parameter value should be equals or greater than 1.
    """
    from AzureDevOps import Client, users_query_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    query = 'xsoar'
    url = f'{BASE_URL}/_apis/IdentityPicker/Identities'

    mock_response = json.loads(load_mock_response('query_user.json'))
    requests_mock.post(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = users_query_command(client, {"query": query})

    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'AzureDevOps.User'
    assert result.outputs[0].get('signInAddress') == 'xsoar@xsoar.com'
    with pytest.raises(Exception):
        users_query_command(client, {"query": query, 'limit': '-1'})


def test_azure_devops_pipeline_run_get_command(requests_mock):
    """
    Scenario: Retrieve pipeline run information.
    Given:
     - User has provided valid credentials.
    When:
     - azure-devops-pipeline-run-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from AzureDevOps import Client, pipeline_run_get_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    project = 'xsoar'
    pipeline_id = '1'
    run_id = '2'
    url = f'{BASE_URL}/{project}/_apis/pipelines/{pipeline_id}/runs/{run_id}'

    mock_response = json.loads(load_mock_response('get_pipeline_run.json'))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = pipeline_run_get_command(client, {"project": project,
                                               'pipeline_id': pipeline_id,
                                               'run_id': run_id})

    assert len(result.outputs) == 11
    assert result.outputs_prefix == 'AzureDevOps.PipelineRun'
    assert result.outputs.get('project') == project
    assert result.outputs.get('pipeline').get('name') == 'xsoar'
    assert result.outputs.get('pipeline').get('id') == "1"
    assert result.outputs.get('run_id') == "3"


def test_azure_devops_pipeline_run_list_command(requests_mock):
    """
    Scenario: Retrieve project pipeline runs list.
    Given:
     - User has provided valid credentials.
    When:
     - azure-devops-pipeline-run-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
     - Ensure the command validates the 'limit' parameter value. The parameter value should be equals or greater than 1.
    """
    from AzureDevOps import Client, pipeline_run_list_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    project = 'xsoar'
    pipeline_id = '1'

    url = f'{BASE_URL}/{project}/_apis/pipelines/{pipeline_id}/runs'

    mock_response = json.loads(load_mock_response('pipeline_run_list.json'))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = pipeline_run_list_command(client, {"project": project,
                                                'pipeline_id': pipeline_id})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureDevOps.PipelineRun'
    assert result.outputs[0].get('project') == project
    assert result.outputs[0].get('pipeline').get('name') == 'xsoar'
    assert result.outputs[0].get('pipeline').get('id') == "1"
    assert result.outputs[0].get('run_id') == "42"
    assert result.outputs[0].get('state') == 'completed'
    with pytest.raises(Exception):
        pipeline_run_list_command(client, {"project": project,
                                           'pipeline_id': pipeline_id,
                                           'limit': '-1'})


def test_azure_devops_pipeline_list_command(requests_mock):
    """
    Scenario: Retrieve project pipelines list.
    Given:
     - User has provided valid credentials.
    When:
     - azure-devops-pipeline-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
     - Ensure the command validates the 'limit' parameter value. The parameter value should be equals or greater than 1.
    """
    from AzureDevOps import Client, pipeline_list_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    project = 'xsoar'

    url = f'{BASE_URL}/{project}/_apis/pipelines'

    mock_response = json.loads(load_mock_response('pipeline_list.json'))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = pipeline_list_command(client, {"project": project})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureDevOps.Pipeline'
    assert result.outputs[0].get('name') == 'xsoar (1)'
    assert result.outputs[0].get('project') == project
    with pytest.raises(Exception):
        pipeline_list_command(client, {"project": project,
                                       'limit': '-1'})


def test_azure_devops_branch_list_command(requests_mock):
    """
    Scenario: Retrieve repository branches list.
    Given:
     - User has provided valid credentials.
    When:
     - azure-devops-branch-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
     - Ensure the command validates the 'limit' parameter value. The parameter value should be equals or greater than 1.
    """
    from AzureDevOps import Client, branch_list_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    project = 'xsoar'
    repository = 'test'

    url = f'{BASE_URL}/{project}/_apis/git/repositories/{repository}/refs'

    mock_response = json.loads(load_mock_response('branch_list.json'))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = branch_list_command(client, {"project": project, "repository": repository}, None, None)

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureDevOps.Branch'
    assert result.outputs[0].get('repository') == repository
    assert result.outputs[0].get('name') == 'refs/heads/main'
    with pytest.raises(Exception):
        branch_list_command(client, {"project": project,
                                     "repository": repository,
                                     'limit': '-1'})


@pytest.mark.parametrize('test_object', [
    ({'id': 24, 'result': 0}),
    ({'id': 22, 'result': 1}),
    ({'id': 25, 'result': -1}),
    ({'id': 21, 'result': -1}),
])
def test_get_last_fetch_incident_index(requests_mock, test_object):
    """
    Scenario: Retrieve the index of the last fetched pull-request.
    Given:
     - User has provided valid credentials.
     - Case A: No new pull-requests - The last pull-request is already fetched and active.
     - Case B: One new pull-requests.
     - Case C: No new pull-requests - The last pull request is already fetched and no longer active.
     - Case D: There is new pull-requests - The last pull request is not yet fetched,
       and the last-fetched pull-request is no longer active.
    When:
     - fetch-incidents called.
    Then:
     - Ensure the return value is correct.
    """
    from AzureDevOps import Client, get_last_fetch_incident_index

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    project = 'test'
    repository = 'xsoar'

    url = f'{BASE_URL}/{project}/_apis/git/repositories/{repository}/pullrequests/'

    mock_response = json.loads(load_mock_response('list_pull_request.json'))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    assert get_last_fetch_incident_index(project, repository, client, test_object['id']) == test_object['result']


def test_get_closest_index(requests_mock):
    """
    Scenario: Retrieve the closest index to the last fetched pull-request ID.
    Given:
     - User has provided valid credentials.
    When:
     - fetch-incidents called.
    Then:
     - Ensure the return value is correct.
    """
    from AzureDevOps import Client, get_closest_index

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    project = 'test'
    repository = 'xsoar'

    url = f'{BASE_URL}/{project}/_apis/git/repositories/{repository}/pullrequests/'

    mock_response = json.loads(load_mock_response('list_pull_request.json'))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    assert get_closest_index(project, repository, client, 23) == 0


def test_is_new_pr(requests_mock):
    """
    Validate if there is new pull-request in the repository.
    Given:
     - User has provided valid credentials.
    When:
     - fetch-incidents called.
    Then:
     - Ensure the return value is correct.
    """
    from AzureDevOps import Client, is_new_pr

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    project = 'test'
    repository = 'xsoar'

    url = f'{BASE_URL}/{project}/_apis/git/repositories/{repository}/pullrequests/'

    mock_response = json.loads(load_mock_response('list_pull_request.json'))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    assert is_new_pr(project, repository, client, 23)
    assert is_new_pr(project, repository, client, 22)
    assert not is_new_pr(project, repository, client, 24)
    assert not is_new_pr(project, repository, client, 25)


def test_get_mapping_fields_command():
    """
    Given:
     - User has provided valid credentials.
    When
        - running get_mapping_fields_command
    Then
        - the result fits the expected mapping.
    """
    from AzureDevOps import get_mapping_fields_command
    expected_mapping = {'Azure DevOps': {'status': 'The status of the pull request.',
                                         'title': 'The title of the pull request.',
                                         'description': 'The description of the pull request.',
                                         'project': 'The name of the project.',
                                         'repository_id': 'The repository ID of the pull request target branch.',
                                         'pull_request_id': 'the ID of the pull request'}}
    res = get_mapping_fields_command()

    assert expected_mapping == res.extract_mapping()


def test_generate_login_url(mocker):
    """
    Given:
        - Self-deployed are true and auth code are the auth flow
    When:
        - Calling function azure-devops-generate-login-url
    Then:
        - Ensure the generated url are as expected.
    """
    # prepare
    import demistomock as demisto
    from AzureDevOps import main
    import AzureDevOps

    redirect_uri = 'redirect_uri'
    tenant_id = 'tenant_id'
    client_id = 'client_id'
    mocked_params = {
        'redirect_uri': redirect_uri,
        'organization': 'test_organization',
        'self_deployed': 'True',
        'tenant_id': tenant_id,
        'client_id': client_id,
        'auth_type': 'Authorization Code',
        'credentials': {'identifier': client_id, 'password': 'client_secret'}
    }
    mocker.patch.object(demisto, 'params', return_value=mocked_params)
    mocker.patch.object(demisto, 'command', return_value='azure-devops-generate-login-url')
    mocker.patch.object(AzureDevOps, 'return_results')

    # call
    main()

    # assert
    expected_url = f'[login URL](https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?' \
                   'response_type=code' \
                   '&scope=offline_access%20499b84ac-1321-427f-aa17-267ca6975798/.default' \
                   f'&client_id={client_id}&redirect_uri={redirect_uri})'
    res = AzureDevOps.return_results.call_args[0][0].readable_output
    assert expected_url in res


@pytest.mark.parametrize('pull_request_id, mock_response_path', [('40', 'list_reviewers_pull_request.json')])
def test_azure_devops_pull_request_reviewer_list_command(requests_mock, pull_request_id: str, mock_response_path: str):
    """
    Given:
     - pull_request_id
    When:
     - executing azure-devops-pull-request-reviewer-list command
    Then:
     - Ensure outputs_prefix and readable_output are set up right
    """
    from AzureDevOps import Client, pull_request_reviewer_list_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    project = 'test'
    repository = 'xsoar'
    pull_request_id = pull_request_id

    url = f'https://dev.azure.com/{ORGANIZATION}/{project}/_apis/git/repositories/{repository}/' \
          f'pullRequests/{pull_request_id}/reviewers'

    mock_response = json.loads(load_mock_response(mock_response_path))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = pull_request_reviewer_list_command(client, {'pull_request_id': pull_request_id}, ORGANIZATION, repository, project)

    assert result.outputs_prefix == 'AzureDevOps.PullRequestReviewer'
    assert result.readable_output.startswith("### Reviewers List")
    assert result.outputs == mock_response["value"]


@pytest.mark.parametrize('pull_request_id, mock_response_path', [('42', 'pull_request_not_found.json')])
def test_azure_devops_pull_request_reviewer_list_command_pr_does_not_exist(requests_mock, pull_request_id: str,
                                                                           mock_response_path: str):
    """
    Given:
     - pull_request_id (pr does not exist)
    When:
     - executing azure-devops-pull-request-reviewer-list command
    Then:
     - Ensure outputs_prefix and readable_output are set up right
     - Ensure informative message when pull_request_id does not exist
    """
    from AzureDevOps import Client, pull_request_reviewer_list_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    project = 'test'
    repository = 'xsoar'
    pull_request_id = pull_request_id

    url = f'https://dev.azure.com/{ORGANIZATION}/{project}/_apis/git/repositories/{repository}/' \
          f'pullRequests/{pull_request_id}/reviewers'

    mock_response = json.loads(load_mock_response(mock_response_path))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = pull_request_reviewer_list_command(client, {'pull_request_id': pull_request_id}, ORGANIZATION, repository, project)

    assert 'The requested pull request was not found.' in result.raw_response.get("message")
    assert result.outputs == ""


@pytest.mark.parametrize('args, organization, expected_result',
                         [({'organization_name': 'OVERRIDE'}, 'TEST', 'OVERRIDE'),
                          ({}, 'TEST', 'TEST'),
                          ({'organization_name': 'OVERRIDE'}, '', 'OVERRIDE')])
def test_organization_repository_project_preprocess(args: dict, organization: str, expected_result: str):
    """
    Given:
     - organization as configuration parameter and as argument
    When:
     - executing organization_repository_project_preprocess function
    Then:
     - Ensure that the logic is correct
        1. The argument should override the parameter if both exist
        2. If there's only one, take it
    """

    from AzureDevOps import organization_repository_project_preprocess

    project = 'TEST'
    repository = 'TEST'

    organization, repository_id, project = organization_repository_project_preprocess(args, organization, repository, project,
                                                                                      is_organization_required=True,
                                                                                      is_repository_id_required=True)

    assert organization == expected_result


@pytest.mark.parametrize('args, organization, expected_result',
                         [({}, '', 'ERROR')])
def test_organization_repository_project_preprocess_when_no_organization(args: dict, organization: str, expected_result: str):
    """
    Given:
     - organization as configuration parameter and as argument
    When:
     - executing organization_repository_project_preprocess function
    Then:
     - Ensure raising an exception if organization does not exist and required
    """

    from AzureDevOps import organization_repository_project_preprocess

    project = 'TEST'
    repository = 'TEST'

    with pytest.raises(Exception):
        organization_repository_project_preprocess(args, organization, repository, project,
                                                   is_organization_required=True,
                                                   is_repository_id_required=True)


@pytest.mark.parametrize('pull_request_id, mock_response_path',
                         [('40', 'pull_request_reviewer_create.json')])
def test_azure_devops_pull_request_reviewer_add_command(requests_mock, pull_request_id: str, mock_response_path: str):
    """
    Given:
     - all arguments
    When:
     - executing azure-devops-pull-request-reviewer-create command
    Then:
     - Ensure outputs_prefix and readable_output are set up right
    """
    from AzureDevOps import Client, pull_request_reviewer_add_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    # setting parameters
    project = 'test'
    repository = 'xsoar'
    reviewer_user_id = 'testestest6565'

    url = f'https://dev.azure.com/{ORGANIZATION}/{project}/_apis/git/repositories/{repository}/' \
          f'pullRequests/{pull_request_id}/reviewers/{reviewer_user_id}'

    mock_response = json.loads(load_mock_response(mock_response_path))
    requests_mock.put(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = pull_request_reviewer_add_command(client, {'pull_request_id': pull_request_id, 'reviewer_user_id': reviewer_user_id},
                                               ORGANIZATION, repository, project)

    assert result.outputs_prefix == 'AzureDevOps.PullRequestReviewer'
    assert result.readable_output == 'TEST (TEST) was created successfully as a reviewer for Pull Request ID 40.'
    assert result.outputs == mock_response


@pytest.mark.parametrize('pull_request_id, mock_response_path', [('42', 'pull_request_not_found.json')])
def test_azure_devops_pull_request_reviewer_add_command_pr_does_not_exist(requests_mock, pull_request_id: str,
                                                                          mock_response_path: str):
    """
    Given:
     - all arguments
    When:
     - executing azure-devops-pull-request-reviewer-create command
    Then:
     - Ensure informative message when pull_request_id does not exist
    """
    from AzureDevOps import Client, pull_request_reviewer_add_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    # setting parameters
    project = 'test'
    repository = 'xsoar'
    reviewer_user_id = 'testestest6565'

    url = f'https://dev.azure.com/{ORGANIZATION}/{project}/_apis/git/repositories/{repository}/' \
          f'pullRequests/{pull_request_id}/reviewers/{reviewer_user_id}'

    mock_response = json.loads(load_mock_response(mock_response_path))
    requests_mock.put(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = pull_request_reviewer_add_command(client, {'pull_request_id': pull_request_id, 'reviewer_user_id': reviewer_user_id},
                                               ORGANIZATION, repository, project)

    # PR does not exist
    assert 'The requested pull request was not found.' in result.outputs.get("message")
    assert result.outputs == {'$id': '1', 'innerException': '', 'message': 'TF401180: The requested pull request was not found.',
                              'typeName': 'Microsoft.TeamFoundation.Git.Server.GitPullRequestNotFoundException,'
                                          ' Microsoft.TeamFoundation.Git.Server', 'typeKey': 'GitPullRequestNotFoundException',
                              'errorCode': 0, 'eventId': 3000, 'value': ''}


@pytest.mark.parametrize('pull_request_id, mock_response_path', [('40', 'pull_request_commit_list.json')])
def test_pull_request_commit_list_command(requests_mock, pull_request_id: str, mock_response_path: str):
    """
    Given:
     - all arguments
    When:
     - executing azure-devops-pull-request-commit-list command
    Then:
     - Ensure outputs_prefix and readable_output are set up right
    """
    from AzureDevOps import Client, pull_request_commit_list_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    # setting parameters
    project = 'test'
    repository = 'xsoar'

    url = f'https://dev.azure.com/{ORGANIZATION}/{project}/_apis/git/repositories/{repository}/' \
          f'pullRequests/{pull_request_id}/commits'

    mock_response = json.loads(load_mock_response(mock_response_path))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = pull_request_commit_list_command(client, {'pull_request_id': pull_request_id, 'limit': '1'},
                                              ORGANIZATION, repository, project)

    assert result.readable_output.startswith('### Commits')
    assert result.outputs_prefix == 'AzureDevOps.Commit'
    assert result.outputs == mock_response["value"]


@pytest.mark.parametrize('pull_request_id, mock_response_path', [('42', 'pull_request_not_found.json')])
def test_pull_request_commit_list_command_pr_does_not_exist(requests_mock, pull_request_id: str, mock_response_path: str):
    """
    Given:
     - all arguments
    When:
     - executing azure-devops-pull-request-commit-list command
    Then:
     - Ensure informative message when pull_request_id does not exist
    """
    from AzureDevOps import Client, pull_request_commit_list_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    # setting parameters
    project = 'test'
    repository = 'xsoar'

    url = f'https://dev.azure.com/{ORGANIZATION}/{project}/_apis/git/repositories/{repository}/' \
          f'pullRequests/{pull_request_id}/commits'

    mock_response = json.loads(load_mock_response(mock_response_path))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = pull_request_commit_list_command(client, {'pull_request_id': pull_request_id, 'limit': '1'},
                                              ORGANIZATION, repository, project)
    # PR does not exist
    assert 'The requested pull request was not found.' in result.raw_response.get("message")
    assert result.outputs == ""


@pytest.mark.parametrize('args, expected_limit, expected_offset',
                         [({}, 50, 0),
                          ({'limit': '2'}, 2, 0),
                          ({'page': '2'}, 50, 50),
                          ({'limit': '2', 'page': '2'}, 2, 2)])
def test_pagination_preprocess_and_validation(args: dict, expected_limit: int, expected_offset: int):
    from AzureDevOps import pagination_preprocess_and_validation

    limit, offset = pagination_preprocess_and_validation(args)

    assert limit == expected_limit
    assert offset == expected_offset


def test_commit_list_command(requests_mock):
    """
    Given:
     - all arguments, limit = 1
    When:
     - executing azure-devops-commit-list command
    Then:
     - Ensure outputs_prefix and readable_output are set up right
    """
    from AzureDevOps import Client, commit_list_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    # setting parameters
    project = 'test'
    repository = 'xsoar'

    url = f'https://dev.azure.com/{ORGANIZATION}/{project}/_apis/git/repositories/{repository}/commits'

    mock_response = json.loads(load_mock_response('commit_list.json'))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = commit_list_command(client, {'limit': '1'}, ORGANIZATION, repository, project)

    assert result.readable_output.startswith('### Commits')
    assert result.outputs_prefix == 'AzureDevOps.Commit'
    assert result.outputs == mock_response["value"]


def test_commit_get_command(requests_mock):
    """
    Given:
     - all arguments include commit_id (required)
    When:
     - executing azure-devops-commit-get command
    Then:
     - Ensure outputs_prefix and readable_output are set up right
    """
    from AzureDevOps import Client, commit_get_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    # setting parameters
    project = 'test'
    repository = 'xsoar'
    commit_id = 'xxxxxxxxxxxxx'

    url = f'https://dev.azure.com/{ORGANIZATION}/{project}/_apis/git/repositories/{repository}/commits/{commit_id}'

    mock_response = json.loads(load_mock_response('commit_list.json'))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = commit_get_command(client, {'commit_id': 'xxxxxxxxxxxxx'}, ORGANIZATION, repository, project)

    assert result.readable_output.startswith('### Commit Details')
    assert result.outputs_prefix == 'AzureDevOps.Commit'
    assert result.outputs == mock_response


def test_work_item_get_command(requests_mock):
    """
    Given:
     - all arguments include item_id (required)
    When:
     - executing azure-devops-work-item-get command
    Then:
     - Ensure outputs_prefix and readable_output are set up right
    """
    from AzureDevOps import Client, work_item_get_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    # setting parameters
    project = 'test'
    repository = 'xsoar'
    item_id = '12'

    url = f'https://dev.azure.com/{ORGANIZATION}/{project}/_apis/wit/workitems/{item_id}'

    mock_response = json.loads(load_mock_response('work_item_get.json'))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = work_item_get_command(client, {'item_id': '12'}, ORGANIZATION, repository, project)

    assert result.readable_output.startswith('### Work Item Details\n|Activity Date|Area Path|Assigned To|ID|State|Tags|Title|\n')
    assert result.outputs_prefix == 'AzureDevOps.WorkItem'
    assert result.outputs == mock_response


def test_work_item_create_command(requests_mock):
    """
    Given:
     - type and title arguments (required)
    When:
     - executing azure-devops-work-item-create command
    Then:
     - Ensure outputs_prefix and readable_output are set up right
    """
    from AzureDevOps import Client, work_item_create_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    # setting parameters
    project = 'test'
    repository = 'xsoar'
    work_item_type = "Epic"

    url = f'https://dev.azure.com/{ORGANIZATION}/{project}/_apis/wit/workitems/${work_item_type}'

    mock_response = json.loads(load_mock_response('work_item_create.json'))
    requests_mock.post(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = work_item_create_command(client, {"type": "Epic", "title": "Test"}, ORGANIZATION, repository, project)

    assert result.readable_output.startswith(f'Work Item {result.outputs.get("id")} was created successfully.')
    assert result.outputs_prefix == 'AzureDevOps.WorkItem'
    assert result.outputs == mock_response


def test_work_item_update_command(requests_mock):
    """
    Given:
     - item_id (required) and title
    When:
     - executing azure-devops-work-item-update command
    Then:
     - Ensure outputs_prefix and readable_output are set up right
    """
    from AzureDevOps import Client, work_item_update_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    # setting parameters
    project = 'test'
    repository = 'xsoar'
    item_id = "21"

    url = f'https://dev.azure.com/{ORGANIZATION}/{project}/_apis/wit/workitems/{item_id}'

    mock_response = json.loads(load_mock_response('work_item_update.json'))
    requests_mock.patch(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = work_item_update_command(client, {"item_id": "21", "title": "Test"}, ORGANIZATION, repository, project)

    assert result.readable_output.startswith('Work Item 21 was updated successfully.')
    assert result.outputs_prefix == 'AzureDevOps.WorkItem'
    assert result.outputs == mock_response


EXPECTED_RESULT = [{'op': 'add', 'path': '/fields/System.Title', 'from': None, 'value': 'zzz'},
                   {'op': 'add', 'path': '/fields/System.IterationPath', 'from': None, 'value': 'test'},
                   {'op': 'add', 'path': '/fields/System.Description', 'from': None, 'value': 'test'},
                   {'op': 'add', 'path': '/fields/Microsoft.VSTS.Common.Priority', 'from': None, 'value': '4'},
                   {'op': 'add', 'path': '/fields/System.Tags', 'from': None, 'value': 'test'}]
ARGUMENTS_LIST = ['title', 'iteration_path', 'description', 'priority', 'tag']
ARGS = {"title": "zzz", "iteration_path": "test", "description": "test", "priority": "4", "tag": "test"}


@pytest.mark.parametrize('args, arguments_list, expected_result',
                         [(ARGS, ARGUMENTS_LIST, EXPECTED_RESULT)])
def test_work_item_pre_process_data(args: dict, arguments_list: list[str], expected_result: dict):
    """
    Ensure work_item_pre_process_data function generates the data (body) for the request as expected.
    """
    from AzureDevOps import work_item_pre_process_data
    data = work_item_pre_process_data(args, arguments_list)
    assert data == expected_result


def test_file_create_command(requests_mock):
    """
    Given:
     - all required arguments
    When:
     - executing azure-devops-file-create command
    Then:
     - Ensure outputs_prefix and readable_output are set up right
    """
    from AzureDevOps import Client, file_create_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    # setting parameters
    project = 'test'
    repository = 'xsoar'

    url_1 = f'https://dev.azure.com/{ORGANIZATION}/{project}/_apis/git/repositories/{repository}/pushes'

    mock_response_1 = json.loads(load_mock_response('file.json'))
    requests_mock.post(url_1, json=mock_response_1)

    url_2 = f'{BASE_URL}/{project}/_apis/git/repositories/{repository}/refs'

    mock_response_2 = json.loads(load_mock_response('branch_list.json'))
    requests_mock.get(url_2, json=mock_response_2)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    args = {"branch_id": "111",
            "branch_name": "refs/heads/main",
            "commit_comment": "Test 5.",
            "file_content": "# Tasks\\n\\n* Item 1\\n* Item 2",
            "file_path": "/test_5.md"
            }
    result = file_create_command(client, args, ORGANIZATION, repository, project)

    assert result.readable_output.startswith(
        'Commit "Test 5." was created and pushed successfully by "" to branch "refs/heads/main".')
    assert result.outputs_prefix == 'AzureDevOps.File'
    assert result.outputs == mock_response_1


CREATE_FILE_CHANGE_TYPE = "add"
CREATE_FILE_ARGS = {"branch_id": "111",
                    "branch_name": "Test",
                    "commit_comment": "Test 6",
                    "file_content": "# Tasks\\n\\n* Item 1\\n* Item 2",
                    "file_path": "/test_5.md"
                    }
CREATE_FILE_EXPECTED_RESULT = {'refUpdates': [{'name': 'Test', 'oldObjectId': '111'}],
                               'commits': [{'comment': 'Test 6', 'changes': [{'changeType': 'add', 'item': {'path': '/test_5.md'},
                                                                              'newContent':
                                                                                  {'content': '# Tasks\\n\\n* Item 1\\n* Item 2',
                                                                                   'contentType': 'rawtext'}}]}]}
CREATE_FILE = (CREATE_FILE_CHANGE_TYPE, CREATE_FILE_ARGS, CREATE_FILE_EXPECTED_RESULT)

UPDATE_FILE_CHANGE_TYPE = "edit"
UPDATE_FILE_ARGS = {"branch_id": "111",
                    "branch_name": "Test",
                    "commit_comment": "Test 6",
                    "file_content": "UPDATE",
                    "file_path": "/test_5.md"
                    }
UPDATE_FILE_EXPECTED_RESULT = {'refUpdates': [{'name': 'Test', 'oldObjectId': '111'}],
                               'commits': [{'comment': 'Test 6', 'changes': [{'changeType': 'edit', 'item':
                                           {'path': '/test_5.md'},
                                   'newContent': {'content': 'UPDATE', 'contentType': 'rawtext'}}]}]}
UPDATE_FILE = (UPDATE_FILE_CHANGE_TYPE, UPDATE_FILE_ARGS, UPDATE_FILE_EXPECTED_RESULT)

DELETE_FILE_CHANGE_TYPE = "delete"
DELETE_FILE_ARGS = {"branch_id": "111",
                    "branch_name": "Test",
                    "commit_comment": "Test 6",
                    "file_path": "/test_5.md"
                    }
DELETE_FILE_EXPECTED_RESULT = {'refUpdates': [{'name': 'Test', 'oldObjectId': '111'}],
                               'commits': [{'comment': 'Test 6',
                                            'changes': [{'changeType': 'delete', 'item': {'path': '/test_5.md'}}]}]}
DELETE_FILE = (DELETE_FILE_CHANGE_TYPE, DELETE_FILE_ARGS, DELETE_FILE_EXPECTED_RESULT)


@pytest.mark.parametrize('change_type, args, expected_result',
                         [CREATE_FILE, UPDATE_FILE, DELETE_FILE])
def test_file_pre_process_body_request(requests_mock, change_type: str, args: dict, expected_result: dict):
    """
    Given:
     - all required arguments
    When:
     - executing file_pre_process_body_request static method
    Then:
     - Ensure that this static method works as expected by constructing the HTTP response data accordingly.
    """
    from AzureDevOps import Client, file_pre_process_body_request

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    data = file_pre_process_body_request(change_type, args)
    assert data == expected_result


def test_file_update_command(requests_mock):
    """
    Given:
     - all required arguments
    When:
     - executing azure-devops-file-update command
    Then:
     - Ensure outputs_prefix and readable_output are set up right
    """
    from AzureDevOps import Client, file_update_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    # setting parameters
    project = 'test'
    repository = 'xsoar'

    url_1 = f'https://dev.azure.com/{ORGANIZATION}/{project}/_apis/git/repositories/{repository}/pushes'

    mock_response_1 = json.loads(load_mock_response('file.json'))
    requests_mock.post(url_1, json=mock_response_1)

    url_2 = f'{BASE_URL}/{project}/_apis/git/repositories/{repository}/refs'

    mock_response_2 = json.loads(load_mock_response('branch_list.json'))
    requests_mock.get(url_2, json=mock_response_2)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    args = {"branch_id": "111",
            "branch_name": "refs/heads/main",
            "commit_comment": "Test 5.",
            "file_content": "UPTADE",
            "file_path": "/test_5.md"
            }
    result = file_update_command(client, args, ORGANIZATION, repository, project)

    assert result.readable_output.startswith('Commit "Test 5." was updated successfully by "" in branch "refs/heads/main".')
    assert result.outputs_prefix == 'AzureDevOps.File'
    assert result.outputs == mock_response_1


def test_file_delete_command(requests_mock):
    """
    Given:
     - all required arguments
    When:
     - executing azure-devops-file-delete command
    Then:
     - Ensure outputs_prefix and readable_output are set up right
    """
    from AzureDevOps import Client, file_delete_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    # setting parameters
    project = 'test'
    repository = 'xsoar'

    url_1 = f'https://dev.azure.com/{ORGANIZATION}/{project}/_apis/git/repositories/{repository}/pushes'

    mock_response_1 = json.loads(load_mock_response('file.json'))
    requests_mock.post(url_1, json=mock_response_1)

    url_2 = f'{BASE_URL}/{project}/_apis/git/repositories/{repository}/refs'

    mock_response_2 = json.loads(load_mock_response('branch_list.json'))
    requests_mock.get(url_2, json=mock_response_2)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    args = {"branch_id": "111",
            "branch_name": "refs/heads/main",
            "commit_comment": "Test 5.",
            "file_path": "/test_5.md"
            }
    result = file_delete_command(client, args, ORGANIZATION, repository, project)

    assert result.readable_output.startswith('Commit "Test 5." was deleted successfully by "" in branch "refs/heads/main".')
    assert result.outputs_prefix == 'AzureDevOps.File'
    assert result.outputs == mock_response_1


def test_file_list_command(requests_mock):
    """
    Given:
     - all required arguments
    When:
     - executing azure-devops-file-list command
    Then:
     - Ensure outputs_prefix and readable_output are set up right
    """
    from AzureDevOps import Client, file_list_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    # setting parameters
    project = 'test'
    repository = 'xsoar'

    url_1 = f'https://dev.azure.com/{ORGANIZATION}/{project}/_apis/git/repositories/{repository}/items'

    mock_response_1 = json.loads(load_mock_response('file_list.json'))
    requests_mock.get(url_1, json=mock_response_1)

    url_2 = f'{BASE_URL}/{project}/_apis/git/repositories/{repository}/refs'

    mock_response_2 = json.loads(load_mock_response('branch_list.json'))
    requests_mock.get(url_2, json=mock_response_2)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    args = {"branch_name": "refs/heads/main",
            "recursion_level": "OneLevel",
            }
    result = file_list_command(client, args, ORGANIZATION, repository, project)

    assert result.readable_output.startswith('### Files\n|File Name(s)|Object ID|Commit ID|Object Type|Is Folder|\n')
    assert result.outputs_prefix == 'AzureDevOps.File'
    assert result.outputs == mock_response_1["value"]


ZIP = ("zip", {"Content-Type": "application/zip"}, "response")
JSON = ("json", {"Content-Type": "application/json"}, "json")


@pytest.mark.parametrize('format_file, headers, resp_type', [ZIP, JSON])
def test_file_get_command(mocker, requests_mock, format_file: str, headers: dict, resp_type: str):
    """
    Given:
     - all required arguments
    When:
     - executing azure-devops-file-get command
    Then:
     - Ensure headers and resp_type were sent correctly based on input (json or zip).
    """
    from AzureDevOps import Client, file_get_command
    from requests import Response
    import AzureDevOps

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    response = Response()

    http_request = mocker.patch.object(client.ms_client, 'http_request',
                                       return_value=response if format_file == 'zip' else {"content": ""})

    args = {"file_name": "test_file", "branch_name": "Test", "format": format_file, "include_content": False}

    mocker.patch.object(AzureDevOps, 'fileResult')
    file_get_command(client, args, ORGANIZATION, "test", "test")

    assert http_request.call_args.kwargs["headers"] == headers
    assert http_request.call_args.kwargs["resp_type"] == resp_type


def test_branch_create_command(requests_mock):
    """
    Given:
     - all required arguments
    When:
     - executing azure-devops-branch-create command
    Then:
     - Ensure outputs_prefix and readable_output are set up right
    """
    from AzureDevOps import Client, branch_create_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    # setting parameters
    project = 'test'
    repository = 'xsoar'

    url_1 = f'https://dev.azure.com/{ORGANIZATION}/{project}/_apis/git/repositories/{repository}/pushes'

    mock_response_1 = json.loads(load_mock_response('branch_create.json'))
    requests_mock.post(url_1, json=mock_response_1)

    url_2 = f'{BASE_URL}/{project}/_apis/git/repositories/{repository}/refs'

    mock_response_2 = json.loads(load_mock_response('branch_list.json'))
    requests_mock.get(url_2, json=mock_response_2)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    args = {"branch_name": "refs/heads/main",
            "file_path": "Test",
            "commit_comment": "Initial commit",
            }
    result = branch_create_command(client, args, ORGANIZATION, repository, project)

    assert result.readable_output.startswith('Branch refs/heads/main was created successfully by XXXXXX.')
    assert result.outputs_prefix == 'AzureDevOps.Branch'
    assert result.outputs == mock_response_1


def test_pull_request_thread_create_command(requests_mock):
    """
    Given:
     - all required arguments
    When:
     - executing azure-devops-pull-request-thread-create command
    Then:
     - Ensure outputs_prefix and readable_output are set up right
    """
    from AzureDevOps import Client, pull_request_thread_create_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    # setting parameters
    project = 'test'
    repository = 'xsoar'
    pull_request_id = 43

    url = f'https://dev.azure.com/{ORGANIZATION}/{project}/_apis/git/repositories/{repository}/pullRequests/' \
          f'{pull_request_id}/threads'

    mock_response = json.loads(load_mock_response('pull_request_thread_create.json'))
    requests_mock.post(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    args = {"pull_request_id": 43, "comment_text": "Test"}
    result = pull_request_thread_create_command(client, args, ORGANIZATION, repository, project)

    assert result.readable_output.startswith('Thread 65 was created successfully by XXXXXX.')
    assert result.outputs_prefix == 'AzureDevOps.PullRequestThread'
    assert result.outputs == mock_response


def test_pull_request_thread_update_command(requests_mock):
    """
    Given:
     - all required arguments
    When:
     - executing azure-devops-pull-request-thread-update command
    Then:
     - Ensure outputs_prefix and readable_output are set up right
    """
    from AzureDevOps import Client, pull_request_thread_update_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    # setting parameters
    project = 'test'
    repository = 'xsoar'
    pull_request_id = 43
    thread_id = 66

    url = f'https://dev.azure.com/{ORGANIZATION}/{project}/_apis/git/repositories/{repository}/pullRequests/' \
          f'{pull_request_id}/threads/{thread_id}'

    mock_response = json.loads(load_mock_response('pull_request_thread_update.json'))
    requests_mock.patch(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    args = {"pull_request_id": 43, "thread_id": 66, "comment_text": "Test"}
    result = pull_request_thread_update_command(client, args, ORGANIZATION, repository, project)

    assert result.readable_output.startswith('Thread 66 was updated successfully by XXXXXXX.')
    assert result.outputs_prefix == 'AzureDevOps.PullRequestThread'
    assert result.outputs == mock_response


def test_pull_request_thread_list_command(requests_mock):
    """
    Given:
     - all required arguments
    When:
     - executing azure-devops-pull-request-thread-list command
    Then:
     - Ensure outputs_prefix and readable_output are set up right
     - Ensure nested threads are displayed as expected. (meaning updates should be displayed in the readable_output too)
    """
    from AzureDevOps import Client, pull_request_thread_list_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    # setting parameters
    project = 'test'
    repository = 'xsoar'
    pull_request_id = 43

    url = f'https://dev.azure.com/{ORGANIZATION}/{project}/_apis/git/repositories/{repository}/pullRequests/' \
          f'{pull_request_id}/threads'

    mock_response = json.loads(load_mock_response('pull_request_thread_list.json'))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    args = {"pull_request_id": 43}
    result = pull_request_thread_list_command(client, args, ORGANIZATION, repository, project)

    assert result.readable_output.startswith('### Threads\n|Thread ID|Content|Name|Date|\n|---|---|---|---|\n| 66 | 123 | XXX |'
                                             ' 2023-07-23T20:08:57.74Z |\n| 66 | 111 | XXX | 2023-07-23T20:11:30.633Z |')
    assert result.outputs_prefix == 'AzureDevOps.PullRequestThread'
    assert result.outputs == mock_response["value"]


def test_project_team_list_command(requests_mock):
    """
    Given:
     - all required arguments
    When:
     - executing azure-devops-project-team-list command
    Then:
     - Ensure outputs_prefix and readable_output are set up right
    """
    from AzureDevOps import Client, project_team_list_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    # setting parameters
    project = 'test'

    url = f'https://dev.azure.com/{ORGANIZATION}/_apis/projects/{project}/teams'

    mock_response = json.loads(load_mock_response('project_team_list.json'))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = project_team_list_command(client, {}, ORGANIZATION, project)

    assert result.readable_output.startswith('### Teams\n|Name|\n|---|\n| DevOpsDemo Team |\n')
    assert result.outputs_prefix == 'AzureDevOps.Team'
    assert result.outputs == mock_response["value"]


def test_team_member_list_command(requests_mock):
    """
    Given:
     - all required arguments
    When:
     - executing azure-devops-team-member-list command
    Then:
     - Ensure outputs_prefix and readable_output are set up right
    """
    from AzureDevOps import Client, team_member_list_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    # setting parameters
    project = 'test'
    team_id = "zzz"

    url = f'https://dev.azure.com/{ORGANIZATION}/_apis/projects/{project}/teams/{team_id}/members'

    mock_response = json.loads(load_mock_response('team_member_list.json'))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    result = team_member_list_command(client, {"team_id": "zzz"}, ORGANIZATION, project)

    assert result.readable_output.startswith(
        '### Team Members\n|Name|Unique Name|User ID|\n|---|---|---|\n| XXX |  |  |\n| YYY |  |  |')
    assert result.outputs_prefix == 'AzureDevOps.TeamMember'
    assert result.outputs == mock_response["value"]


def test_blob_zip_get_command(mocker, requests_mock):
    """
    Given:
        - all required arguments
    When:
        - executing azure-devops-blob-zip-get command
    Then:
        - Ensure the output's type is INFO_FILE
    """
    import AzureDevOps
    from AzureDevOps import Client, blob_zip_get_command
    from requests import Response

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False,
        auth_type='Device Code')

    with open('test_data/response_content') as content:
        response = Response()
        response._content = content

    mocker.patch.object(client.ms_client, 'http_request', return_value=response)

    args = {'file_object_id': 'zzz'}

    mocker.patch.object(AzureDevOps, 'fileResult', return_value={'Type': EntryType.ENTRY_INFO_FILE})
    res = blob_zip_get_command(client, args, ORGANIZATION, "test", "test")

    assert res['Type'] == EntryType.ENTRY_INFO_FILE
