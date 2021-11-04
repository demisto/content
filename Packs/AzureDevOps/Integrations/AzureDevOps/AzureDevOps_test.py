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
    with open(f'test_data/{file_name}', mode='r', encoding='utf-8') as mock_file:
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
        proxy=False)

    result = pipeline_run_command(client, {'project': project,
                                           'pipeline_id': pipeline_id,
                                           'branch_name': 'my-branch'})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureDevOps.Project'
    assert result.outputs.get('name') == 'test'
    assert result.outputs.get('Pipeline').get('name') == 'xsoar'
    assert result.outputs.get('Pipeline').get('id') == 1


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
        proxy=False)

    result = user_add_command(client, {'user_email': user_email,
                                       'account_license_type': account_license_type,
                                       'group_type': group_type,
                                       'project_id': project_id})

    assert len(result.outputs) == 3
    assert result.outputs_prefix == 'AzureDevOps.User'
    assert result.outputs.get('id') == 'XXX'
    assert result.outputs.get('accountLicenseType') == 'express'
    assert result.outputs.get('lastAccessedDate') == '0001-01-01T00:00:00Z'


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
        proxy=False)

    result = user_remove_command(client, {'user_id': user_id})

    assert result.outputs is None
    assert result.outputs_prefix is None
    assert result.readable_output == 'The User successfully removed from the organization.'


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
        proxy=False)

    result = pull_request_create_command(client, {'project': project,
                                                  'repository_id': repository_id,
                                                  'source_branch': 'my-branch',
                                                  'target_branch': 'main',
                                                  'title': 'test-title',
                                                  'description': 'test-description',
                                                  'reviewers_ids': '2'})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureDevOps.Project'
    assert result.outputs.get('name') == 'xsoar'
    assert result.outputs.get('Repository').get('name') == 'xsoar'


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
        proxy=False)

    result = pull_request_get_command(client, {'project': project,
                                               'repository_id': repository_id,
                                               'pull_request_id': pull_request_id
                                               })

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureDevOps.Project'
    assert result.outputs.get('name') == 'xsoar'
    assert result.outputs.get('Repository').get('name') == 'xsoar'


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
        proxy=False)

    result = pull_request_update_command(client, {'project': project,
                                                  'repository_id': repository_id,
                                                  'pull_request_id': pull_request_id,
                                                  'title': 'new-title'
                                                  })

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureDevOps.Project'
    assert result.outputs.get('name') == 'xsoar'
    assert result.outputs.get('Repository').get('name') == 'xsoar'


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
        proxy=False)

    result = pull_requests_list_command(client, {'project': project,
                                                 'repository': repository
                                                 })

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureDevOps.Project'
    assert result.outputs.get('name') == 'xsoar'
    assert result.outputs.get('Repository').get('name') == 'xsoar'


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
        proxy=False)

    result = project_list_command(client, {})

    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'AzureDevOps.Project'
    assert result.outputs[0].get('name') == 'xsoar'
    assert result.outputs[0].get('visibility') == 'private'


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
    """
    from AzureDevOps import Client, repository_list_command

    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())

    project = 'xsoar'
    url = f'{BASE_URL}/{project}/_apis/git/repositories'

    mock_response = json.loads(load_mock_response('list_project.json'))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False)

    result = repository_list_command(client, {"project": project})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureDevOps.Project'
    assert result.outputs.get('name') == 'xsoar'
    assert result.outputs.get('Repository')[0].get('name') == 'xsoar'


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
        proxy=False)

    result = users_query_command(client, {"query": query})

    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'AzureDevOps.User'
    assert result.outputs[0].get('email') == 'xsoar@xsoar.com'


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

    mock_response = json.loads(load_mock_response('get_pipeline.json'))
    requests_mock.get(url, json=mock_response)

    client = Client(
        client_id=CLIENT_ID,
        organization=ORGANIZATION,
        verify=False,
        proxy=False)

    result = pipeline_run_get_command(client, {"project": project,
                                               'pipeline_id': pipeline_id,
                                               'run_id': run_id})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureDevOps.Project'
    assert result.outputs.get('Pipeline').get('name') == 'xsoar'


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
        proxy=False)

    result = pipeline_run_list_command(client, {"project": project,
                                                'pipeline_id': pipeline_id})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureDevOps.Project'
    assert result.outputs.get('Pipeline')[0].get('name') == 'xsoar'
    assert result.outputs.get('Pipeline')[0].get('Run').get('state') == 'completed'


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
        proxy=False)

    result = pipeline_list_command(client, {"project": project})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureDevOps.Project'
    assert result.outputs.get('Pipeline')[0].get('name') == 'xsoar (1)'


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
        proxy=False)

    result = branch_list_command(client, {"project": project, "repository": repository})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'AzureDevOps.Project'
    assert result.outputs.get('Repository').get('name') == repository
    assert result.outputs.get('Repository').get('Branch')[0].get('name') == 'main'
