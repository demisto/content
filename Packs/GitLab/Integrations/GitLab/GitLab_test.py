import io
import json
# import pytest

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


test_data = {'group_id': '55694272',
             'raw_file': '.gitlab-ci.yml'}


ARGS_CASES = [
    (1, 0, 'The page value must be equal to 1 or bigger.'),
    (2, -1, 'The page_size value must be equal to 1 or bigger.'),
    (1, 1, 'valid values')
]


def test_create_issue_command(mocker):
    """
    Given:
        'title': the new title for the issue.
        'description': description for the issue.
        'labels': labels for the issue.
    When:
        Running the add_issue_to_project_board_command function.
    Then:
        Assert the message returned is as expected.
    """
    from GitLab import Client, create_issue_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    params = {'title': 'title_test', 'description': 'desc_test', 'labels': 'label1'}
    expected_results = {'Iid': 114,
                        'Title': 'title_test',
                        'CreatedAt': '2022-10-06T14:45:38.004Z',
                        'UpdatedAt': '2022-10-06T14:45:38.004Z',
                        'CreatedBy': 'name',
                        'State': 'opened'}
    ret_value = util_load_json('test_data/commands_test_data.json').get('issue_create')
    mocker.patch.object(Client, 'create_issue_request', return_value=ret_value)
    result = create_issue_command(client, params)
    assert result == expected_results


'''
CREATE_ISSUE_NOTE_CASES = [
    ({'issue_iid': 15, 'body': 'issue_iid_not_exist_case'}, False,  # the issue_iid does note exist
     {"message": "404 Not found"}, {"message": "404 Not found"}),
    ({'issue_iid': 4, 'body': 'good'}, True,  # good case
     {"id": 14, "body": "good", "noteable_iid": 4}, {'Issue note created successfully'})
]


@pytest.mark.parametrize('params,is_good_case, client_return_result, expected_results', CREATE_ISSUE_NOTE_CASES)
def test_issue_note_create(mocker, params, is_good_case, client_return_result, expected_results):
    from GitLab import Client, issue_note_create_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    mocker.patch.object(Client, 'issue_note_create_request', return_value=client_return_result)
    result = issue_note_create_command(client, params)
    assert result == expected_results


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



@pytest.mark.parametrize('page, limit, expected_results', ARGS_CASES)
def test_check_args(page, limit, expected_results):
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
        validate_pagination_values(page, limit)
    assert e.value.args[0] == expected_results


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
'''
