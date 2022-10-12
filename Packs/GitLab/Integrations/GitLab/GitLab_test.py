import io
import json
import pytest


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


ARGS_CASES = [
    (2, -1, False,  # The page_size value must be equal to 1 or bigger.
     {'error': 'Pagination values must be positive'}  # expected
     ),
    (-5, 11, False,  # The page_size value must be equal to 1 or bigger.
     {'error': 'Pagination values must be positive'}  # expected
     ),
    (1, 1, True,  # Good Case
     {'limit': 1, 'per_page': 1, 'page_number': 1}),  # expected
    (120, 1, True,  # Good Case
     {'limit': 120, 'per_page': 100, 'page_number': 1})  # expected
]


@pytest.mark.parametrize('limit, page_number, isGoodCase, expected_results', ARGS_CASES)
def test_check_args(limit, page_number, isGoodCase, expected_results):
    """
        Given:
            - A command's arguments

        When:
            - running commands that has pagination

        Then:
            - checking that if the parameters < 1 , exception is thrown

        """
    from GitLab import validate_pagination_values
    from CommonServerPython import DemistoException

    if isGoodCase:
        res_limit, res_per_page, res_page_number = validate_pagination_values(limit, page_number)
        assert res_limit == expected_results['limit']
        assert res_per_page == expected_results['per_page']
        assert res_page_number == expected_results['page_number']

    else:
        with pytest.raises(DemistoException) as e:
            validate_pagination_values(limit, page_number)
        assert str(e.value) == expected_results['error']


ARGS_CHECK_LIMIT_GROUP_PROJECT = [
    ({'group_id': '39882308', 'limit': '2'},  # params
     'results',  # client result section from commands_test_data.jason
     2  # excpeted
     ),
    ({'group_id': '39882308', 'limit': '1'},  # params
     'project1',  # client result section from commands_test_data.jason
     1  # excpeted
     )
]


def test_create_issue_command(mocker):
    """
    Given:
        All relevant arguments for the command
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
    expected_result = {'iid': 114, 'title': 'title_test', 'description': 'desc_test',
                       'state': 'opened', 'created_at': "'2022-10-06T14:45:38.004Z'",
                       'updated_at': "'2022-10-06T14:45:38.004Z'", 'author': {'name': 'name'}}
    expected_hr = '### Created Issue\n' \
                  '|Iid|Title|CreatedAt|CreatedBy|UpdatedAt|State|\n' \
                  '|---|---|---|---|---|---|\n' \
                  '| 114 | title_test | \'2022-10-06T14:45:38.004Z\' | name | \'2022-10-06T14:45:38.004Z\' | opened |\n'

    ret_value = util_load_json('test_data/commands_test_data.json').get('issue_create')
    mocker.patch.object(Client, 'create_issue_request', return_value=ret_value)
    result = create_issue_command(client, params)
    assert result.raw_response == expected_result
    assert result.readable_output == expected_hr


def test_get_version_command(mocker):
    """
    Given:
        - All relevant arguments for the command
    When:
        - running a get_version_command
    Then:
        - check if the results of version and reversion returns are valid.
    """
    from GitLab import Client, version_get_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    response_version = util_load_json('test_data/commands_test_data.json').get('get_version')
    mocker.patch.object(Client, 'version_get_request', return_value=response_version)
    result = version_get_command(client, {})
    expected_raw_result = {'version': '15.5.0-pre', 'revision': '6146b2240b0'}
    expected_hr = 'GitLab version 15.5.0-pre\n reversion: 6146b2240b0 '
    assert result.raw_response == expected_raw_result
    assert result.readable_output == expected_hr


def test_group_project_list_command(mocker):
    """
    Given:
        - All relevant arguments for the command
    When:
        - running a group_project_list_command
    Then:
        - The http request is called with the right arguments, and returns the right command result
    """
    from GitLab import Client, group_project_list_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    args = {'group_id': 112, 'limit': 2}
    response_client = util_load_json('test_data/commands_test_data.json').get('get_group_project')
    mocker.patch.object(Client, 'group_projects_list_request', return_value=response_client)
    result = group_project_list_command(client, args)
    expected_hr = '### List Group Projects\n' \
                  '|Id|Name|Description|Path|\n' \
                  '|---|---|---|---|\n' \
                  '| 1 | ProjectTest1 | test1 | learn-gitlab1 |\n' \
                  '| 2 | ProjectTest2 | test2 | learn-gitlab2 |\n'
    assert result.readable_output == expected_hr
    assert result.raw_response == response_client


def test_get_project_list_command(mocker):
    """
    Given:
        - All relevant arguments for the command
    When:
        - running a get_project_list_command
    Then:
        - The http request is called with the right arguments, and returns the right command result
    """
    from GitLab import Client, get_project_list_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    args = {'limit': 2}
    response_client = util_load_json('test_data/commands_test_data.json').get('get_project_list')
    mocker.patch.object(Client, 'get_project_list_request', return_value=response_client)
    result = get_project_list_command(client, args)
    expected_hr = '### List Projects\n' \
                  '|Id|Name|Description|Path|\n' \
                  '|---|---|---|---|\n' \
                  '| 1 | LearnGitLab1 | description1 | /learn-gitlab1 |\n' \
                  '| 2 | LearnGitLab2 | description2 | /learn-gitlab2 |\n'
    assert result.readable_output == expected_hr
    assert result.raw_response == response_client


ARGS_BRANCHES = [
    ({'branch_name': '1-test', 'limit': '1'},  # args single branch
     'branch_single_request',
     'get_branches_single',  # result from json
     '### Branch details\n' \
     '|Title|CommitShortId|CommitTitle|CreatedAt|IsMerge|IsProtected|\n' \
     '|---|---|---|---|---|---|\n' \
     '| 1-test | f9d0bf17 | test1 | 2022-07-27T13:09:50.000+00:00 | false | false |\n'
     ),
    ({'limit': '2'},  # args list
     'branch_list_request',
     'get_branches',
     '### List Branches\n' \
     '|Title|CommitShortId|CommitTitle|CreatedAt|IsMerge|IsProtected|\n' \
     '|---|---|---|---|---|---|\n' \
     '| 1-test | f9d0bf17 | test1 | 2022-07-27T13:09:50.000+00:00 | false | false |\n' \
     '| 2-test | d9177263 | test2 | 2022-07-18T12:19:47.000+00:00 | false | false |\n'
     )
]


@pytest.mark.parametrize('args, client_function, result_key_json, expected_results', ARGS_BRANCHES)
def test_branch_list_command(mocker, args, client_function, result_key_json, expected_results):
    """
    Given:
        - All relevant arguments for the command
    When:
        - running a branch_list_command
    Then:
        - The http request is called with the right arguments, and returns the right command result
    """
    from GitLab import Client, branch_list_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    response_client = util_load_json('test_data/commands_test_data.json').get(result_key_json)
    mocker.patch.object(Client, client_function, return_value=response_client)
    result = branch_list_command(client, args)
    assert result.readable_output == expected_results


ARGS_COMMITS = [
    ({'commit_id': 'a1', 'limit': '1'},  # args single branch
     'commit_single_request',
     'get_commit_single',  # result from json
     '### Commit details\n' \
     '|Title|Message|ShortId|Author|CreatedAt|\n' \
     '|---|---|---|---|---|\n' \
     '| commit1 | message1 | a1 | demo1 | 2022-07-26T11:28:03.000+00:00 |\n' \
     ),
    ({'limit': '2'},  # args list
     'commit_list_request',
     'get_commits',
     '### List Commits\n' \
     '|Title|Message|ShortId|Author|CreatedAt|\n' \
     '|---|---|---|---|---|\n' \
     '| commit1 | message1 | a1 | demo1 | 2022-07-26T11:28:03.000+00:00 |\n' \
     '| commit2 | message2 | b2 | demo2 | 2022-07-26T11:28:03.000+00:00 |\n'
     '| commit3 | message3 | c3 | demo3 | 2022-07-26T11:28:03.000+00:00 |\n'
     )
]


@pytest.mark.parametrize('args, client_function, result_key_json, expected_results', ARGS_COMMITS)
def test_commit_list_command(mocker, args, client_function, result_key_json, expected_results):
    """
    Given:
        - All relevant arguments for the command
    When:
        - running a commit_list_command
    Then:
        - The http request is called with the right arguments, and returns the right command result
    """
    from GitLab import Client, commit_list_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    response_client = util_load_json('test_data/commands_test_data.json').get(result_key_json)
    mocker.patch.object(Client, client_function, return_value=response_client)
    result = commit_list_command(client, args)
    assert result.readable_output == expected_results


def test_merge_request_list_command(mocker):
    """
    Given:
        - All relevant arguments for the command
    When:
        - running a merge_request_list_command
    Then:
        - The http request is called with the right arguments, and returns the right command result
    """
    from GitLab import Client, merge_request_list_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    args = {'limit': 2}
    response_client = util_load_json('test_data/commands_test_data.json').get('list_merge_request')
    mocker.patch.object(Client, 'merge_request_list_request', return_value=response_client)
    result = merge_request_list_command(client, args)
    expected_hr = '### List Merge requests\n' \
                  '|Iid|CreatedAt|CreatedBy|Status|\n' \
                  '|---|---|---|---|\n' \
                  '| 5 | 2022-10-02T10:11:27.506Z | Test Account | opened |\n' \
                  '| 6 | 2022-10-02T10:11:27.506Z | Test Account | opened |\n'
    assert result.readable_output == expected_hr
    assert result.raw_response == response_client


'''
@pytest.mark.parametrize('args, client_result_jason_name,total_results ', ARGS_CHECK_LIMIT_GROUP_PROJECT)
def test_group_project_list_command_limit(requests_mock,args, client_result_jason_name, total_results):
    """
    Given:
        - A http response
    When:
        - running a group project command
    Then:
        - check if the results returns are valid according to differnt valid limit
    """
    from GitLab import Client, group_project_list_command
    client = Client(project_id=1234,
                    base_url="base_url",
                    verify=False,
                    proxy=False,
                    headers={'PRIVATE-TOKEN': 'api_key'})
    response_json = util_load_json('test_data/commands_test_data.json').get('get_group_projects').get(client_result_jason_name)
    print('ok')
    requests_mock.patch.object(Client, 'group_projects_list_request', return_value=response_json)
    results = group_project_list_command(client, args)
    assert len(results) == total_results




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



'''
