"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""
import io
import json
import requests
import pytest
from typing import Dict, Callable, Union, List, Any
from CommonServerPython import CommandResults
from GitLab import Client
'''
group_project_list_command
create_issue_command
branch_create_command
branch_delete_command
merged_branch_delete_command
get_raw_file_command
get_project_list_command
version_get_command

#~~~~~~~~~ not written yet ~~~~~~~
file_get_command,file_create_command, file_update_command,file_delete_command, \
issue_list_command, issue_update_command,commit_list_command, merge_request_list_command,merge_request_create_command, \
merge_request_update_command,issue_note_create_command,issue_note_delete_command,issue_note_update_command, \
issue_note_list_command, merge_request_note_list_command, merge_request_note_create_command, \
merge_request_note_update_command, merge_request_note_delete_command, branch_list, \
group_list, group_member_list
'''

BASE_URL = 'https://gitlab.com/api/v4'
mock_client = Client(37904895, BASE_URL, verify=False, proxy=False, headers=dict())


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


command_test_data = util_load_json('test_data/baseintegration_GitLab.json')

test_data = {'group_id': '55694272',
             'raw_file': '.gitlab-ci.yml'}


branch_create = {'branch_name': 'new_branch_name',
                 'ref': 'main'
                 }

branch_delete = {'branch_name': 'new_branch_name',
                 'ref': 'main'}

pagination_dict = {'page': '1', 'per_page': '1', 'limit': '2'}

ARGS_CASES = [
    (-1, None, None, 'The limit value must be equal to 1 or bigger.'),
    (1, 0, None, 'The page value must be equal to 1 or bigger.'),
    (None, 2, -1, 'The page_size value must be equal to 1 or bigger.')
]


@pytest.mark.parametrize('page, page_size, limit, expected_results', ARGS_CASES)
def test_check_args(limit, page, page_size, expected_results):
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
        validate_pagination_values(page, page_size, limit)
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
    client = Client(project_id='55694272',
                    base_url='https://gitlab.com/api/v4',
                    verify=False,
                    proxy=False)
    args_limit_2 = {
        'group_id': '37904896',
        'limit': '2'
    }
    args_limit_1 = {
        'group_id': '37904896',
        'limit': '1'
    }
    # limit is 2
    response_json = util_load_json('test_data/baseintegration_GitLab.json').get('get_paged_results').get('results')
    response_project1 = util_load_json('test_data/baseintegration_GitLab.json').get('get_paged_results').get('project1')
    # response_project2 = util_load_json('test_data/baseintegration_GitLab.json').get('get_paged_results').get('project2')
    requests_mock.get('https://gitlab.com/api/v4/groups/:id/projects?id=55694272', json=response_json)
    res = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('results')
    requests_mock.patch.object(Client, 'get_full_url', return_value=response_json)
    results = group_project_list_command(client, args_limit_2)
    assert len(results) == 2
    assert results == res

    # limit is 1
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
    client = Client(project_id='55694272',
                    base_url='https://gitlab.com/api/v4',
                    verify=False,
                    proxy=False)
    args_results_page2 = {
        'group_id': '37904896',
        'per_page': '1',
        'page': '2'
    }
    args_results_page1 = {
        'group_id': '37904896',
        'per_page': '1',
        'page': '1'
    }
    # checking that the result returning from the first page is the first project and only it
    response_project1 = util_load_json('test_data/baseintegration_GitLab.json').get('get_paged_results').get('project1')
    response_project2 = util_load_json('test_data/baseintegration_GitLab.json').get('get_paged_results').get('project2')
    requests_mock.get('https://gitlab.com/api/v4/groups/:id/projects?id=55694272', json=response_project1)
    res = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('results')
    requests_mock.patch.object(Client, 'get_full_url', return_value=response_project1)
    results = group_project_list_command(client, args_results_page1)
    assert len(results) == 1
    assert results == res

    # checking that the result returning from the second page is the second project and only it
    requests_mock.get('https://gitlab.com/api/v4/groups/:id/projects?id=55694272', json=response_project2)
    res = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('results')
    requests_mock.patch.object(Client, 'get_full_url', return_value=response_project2)
    results = group_project_list_command(client, args_results_page2)
    assert len(results) == 1
    assert results == res


#  REMOVE the following dummy unit test function

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
    client = Client(project_id='55694272',
                    base_url='https://gitlab.com/api/v4',
                    verify=False,
                    proxy=False)
    response_version = util_load_json('test_data/baseintegration_GitLab.json').get('get_version')
    requests_mock.get('https://gitlab.com/api/v4/version', json=response_version)
    results = version_get_command(client)
    assert len(results) == 2
    assert results['version'] == response_version['version']
    assert results['reversion'] == response_version['reversion']


def test_create_issue_command(requests_mock):
    pass


def test_branch_create_command(request_mock):
    pass   # need to complete


def test_branch_delete_command(request_mock):
    pass   # need to complete


def test_merged_branch_delete_command(request_mock):
    pass   # need to complete


def test_get_raw_file_command(request_mock):
    pass   # need to complete


def test_get_project_list_command(request_mock):
    pass   # need to complete


'''
 response = util_load_json('test_data/commands_test_data.json').get('check_pagination').get('response')
    res = util_load_json('test_data/commands_test_data.json').get('check_pagination').get('result')
    response2 = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('response1')
    results10 = check_pagination(client, response, 10, {})
    results1 = check_pagination(client, response, 1, {})
    results2 = check_pagination(client, response2, 1, {})
    assert results10 == res
    assert results1 == res
    assert results2 == res

'''
