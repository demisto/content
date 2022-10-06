import io
import json
import requests
import pytest
from GitLab import Client


BASE_URL = ''
mock_client = Client(39823965, BASE_URL, verify=False, proxy=False, headers=dict())
PROJECT_ID = '39823965'

RESPONSE_DETAILS_GET_PUT = [
    (200, 'GitLab.', "The opretion was successfull"),
    (202, 'GitLab.', "The opretion was successfull"),
    (404, '{"message": "404"}', ' not found.'),
    (400, '{"message": "400"}', ' bad request.')
]

RESPONSE_DETAILS_POST = [
    (201, "The opretion was successfull"),
    (404, '{"message": "404"}', ' not found.'),
    (400, '{"message": "400"}', ' bad request.')
]

RESPONSE_DETAILS_DELETE = [
    (200, 'GitLab.', "The opretion was successfull"),
    (202, 'GitLab.', "The opretion was successfull"),
    (204, 'GitLab.', "The opretion was successfull"),
    (404, '{"message": "404"}', ' not found.'),
    (400, '{"message": "400"}', ' bad request.')
]


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


command_test_data = util_load_json('test_data/commands_test_data.json')

test_data = {'group_id': '55694272',
             'raw_file': '.gitlab-ci.yml'}


branch_create = {'branch_name': 'new_branch_name',
                 'ref': 'main'
                 }

branch_delete = {'branch_name': 'new_branch_name',
                 'ref': 'main'}

pagination_dict = {'page': '1', 'per_page': '1', 'limit': '2'}

ARGS_CASES = [
    (1, 0, 'The page value must be equal to 1 or bigger.'),
    (2, -1, 'The page_size value must be equal to 1 or bigger.'),
    (1, 1, 'valid values')

]


@pytest.mark.parametrize('response_code,response_content,mocked_return,expected_result', RESPONSE_DETAILS_POST)
def test_create_issue_command(mocker, requests_mock, response_code, response_content, mocked_return,
                              expected_result):
    """
    Given:
        'title': the new title for the issue.
        'description': description for the issue
    When:
        Running the add_issue_to_project_board_command function.
    Then:
        Assert the message returned is as expected.
    """
    from GitLab import Client, create_issue_command
    client = Client()
    args = {}
    requests_mock.get(f'/projects/{PROJECT_ID}/issues', json='response_version')
    mocker.patch.object('demisto', 'args', return_value={'column_id': 'column_id', 'issue_unique_id': '11111'})
    requests_mock.post(f'{BASE_URL}/projects/columns/column_id/cards', status_code=response_code,
                       content=response_content)
    mocker_results = mocker.patch(mocked_return)
    print(mocker_results.startswith('bbb'))
    result = create_issue_command(client, args)
    print(result)
    assert mocker_results.call_args[0][0] == expected_result


@pytest.mark.parametrize('page, page_size, limit, expected_results', ARGS_CASES)
def test_check_args(page, page_size, expected_results):
    """
        Given:
            - A command's arguments

        When:
            - running commands that has pagination

        Then:
            - checking that if the parameters < 1 , exception is thrown

        """
    from GitLab import validate_pagination_values

    with pytest.raises(Exception) as e:
        validate_pagination_values(page, page_size)
    assert e.value.args[0] == expected_results


def test_valid_error_is_raised_when_empty_api_response_is_returned(mocker):
    """
    Given
    - Empty api response and invalid status code returned from the api response.

    When
    - running 'test-module'.

    Then
    - ValueError is raised.
    """
    from GitLab import test_module
    client = mock_client()
    api_response = requests.Response()
    api_response.status_code = 403
    api_response._content = None

    mocker.patch.object(client._client, 'get_access_token')
    mocker.patch.object(client._client._session, 'request', return_value=api_response)

    with pytest.raises(ValueError, match='[Forbidden 403]'):
        test_module(client)


def test_group_project_list_command_limit(requests_mock):
    """
    Given:
        - A http response
    When:
        - running a group project command
    Then:
        - check if the results returns are valid according to differnt valid limit
    """
    from GitLab import Client, group_project_list_command
    client = Client(project_id='39823965',
                    base_url='https://gitlab.com/api/v4',
                    verify=False,
                    proxy=False)
    args_limit_2 = {
        'group_id': '39882308',
        'limit': '2'
    }
    args_limit_1 = {
        'group_id': '37904896',
        'limit': '1'
    }
    response_json = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('results')
    response_project1 = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('project1')
    requests_mock.get('https://gitlab.com/api/v4/groups/:id/projects?id=55694272', json=response_json)
    res = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('results')
    requests_mock.patch.object(Client, 'get_full_url', return_value=response_json)
    results = group_project_list_command(client, args_limit_2)
    assert len(results) == 2
    assert results == res
    requests_mock.get('https://gitlab.com/api/v4/groups/:id/projects?id=55694272', json=response_project1)
    res = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('results')
    requests_mock.patch.object(Client, 'get_full_url', return_value=response_project1)
    results = group_project_list_command(client, args_limit_1)
    assert len(results) == 2
    assert results == res


def test_group_project_list_command_page(requests_mock):
    """
    Given:
        - A http response
    When:
        - running a group project command
    Then:
        - check if the results returns are valid according to differnt valid page_number
    """
    from GitLab import Client, group_project_list_command
    client = Client()
    args_results_page2 = {
        'group_id': '58584155',
        'per_page': '1',
        'page': '2'
    }
    args_results_page1 = {
        'group_id': '58584155',
        'per_page': '1',
        'page': '1'
    }
    response_project1 = util_load_json('test_data/commands_test_data.json').get('get_group_projects').get('project1')
    response_project2 = util_load_json('test_data/commands_test_data.json').get('get_group_projects').get('project2')
    requests_mock.get('https://gitlab.com/api/v4/groups/:id/projects?id=55694272', json=response_project1)
    res = util_load_json('test_data/commands_test_data.json').get('get_group_projects').get('results')
    requests_mock.patch.object(Client, 'get_full_url', return_value=response_project1)
    results = group_project_list_command(client, args_results_page1)
    assert len(results) == 1
    assert results == res

    requests_mock.get('https://gitlab.com/api/v4/groups/:id/projects?id=55694272', json=response_project2)
    res = util_load_json('test_data/commands_test_data.json').get('get_group_projects').get('results')
    requests_mock.patch.object(Client, 'get_full_url', return_value=response_project2)
    results = group_project_list_command(client, args_results_page2)
    assert len(results) == 1
    assert results == res


def test_project_list_command_limit(requests_mock):
    """
    Given:
        - A http response
    When:
        - running a group project command
    Then:
        - check if the results returns are valid according to differnt valid limit
    """
    from GitLab import Client, group_project_list_command
    client = Client(project_id='39823965',
                    base_url='https://gitlab.com/api/v4',
                    verify=False,
                    proxy=False)
    args_limit_2 = {
        'group_id': '39882308',
        'limit': '2'
    }
    args_limit_1 = {
        'group_id': '37904896',
        'limit': '1'
    }
    response_json = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('results')
    response_project1 = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('project1')
    requests_mock.get('https://gitlab.com/api/v4/groups/:id/projects?id=55694272', json=response_json)
    res = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('results')
    requests_mock.patch.object(Client, 'get_full_url', return_value=response_json)
    results = group_project_list_command(client, args_limit_2)
    assert len(results) == 2
    assert results == res
    requests_mock.get('https://gitlab.com/api/v4/groups/:id/projects?id=55694272', json=response_project1)
    res = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('results')
    requests_mock.patch.object(Client, 'get_full_url', return_value=response_project1)
    results = group_project_list_command(client, args_limit_1)
    assert len(results) == 2
    assert results == res


def test_project_list_command_page(requests_mock):
    """
    Given:
        - A http response
    When:
        - running a group project command
    Then:
        - check if the results returns are valid according to differnt valid page_number
    """
    from GitLab import Client, group_project_list_command
    client = Client()
    args_results_page2 = {
        'group_id': '58584155',
        'per_page': '1',
        'page': '2'
    }
    args_results_page1 = {
        'group_id': '58584155',
        'per_page': '1',
        'page': '1'
    }
    response_project1 = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('project1')
    response_project2 = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('project2')
    requests_mock.get('https://gitlab.com/api/v4/groups/:id/projects?id=55694272', json=response_project1)
    res = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('results')
    requests_mock.patch.object(Client, 'get_full_url', return_value=response_project1)
    results = group_project_list_command(client, args_results_page1)
    assert len(results) == 1
    assert results == res

    requests_mock.get('https://gitlab.com/api/v4/groups/:id/projects?id=55694272', json=response_project2)
    res = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('results')
    requests_mock.patch.object(Client, 'get_full_url', return_value=response_project2)
    results = group_project_list_command(client, args_results_page2)
    assert len(results) == 1
    assert results == res


def test_get_version_command(requests_mock):
    """
    Given:
        - A http response
    When:
        - running a get_version_command
    Then:
        - check if the results of version and reversion returns are valid.
    """
    from GitLab import Client, version_get_command
    client = Client()
    response_version = util_load_json('test_data/commands_test_data.json').get('get_version')
    requests_mock.get('https://gitlab.com/api/v4/version', json=response_version)
    results = version_get_command(client)
    assert len(results) == 2
    assert results['version'] == response_version['version']
    assert results['reversion'] == response_version['reversion']


def test_issue_update_command(request_mock):
    pass


def test_issue_list_command(request_mock):
    pass


def test_get_raw_file_command(request_mock):
    pass


def test_get_project_list_command(request_mock):
    pass


def test_list_project_users_command(request_mock):
    pass


def test_list_group_members_command(request_mock):
    pass


def test_list_merge_request_command(request_mock):
    pass


def list_commits_command(request_mock):
    pass


def list_branches_command(request_mock):
    pass
