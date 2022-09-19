"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io

import pytest


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


ARGS_CASES = [
    (-1, None, 'The limit value must be equal to 1 or bigger.'),
    (1, 0, 'The page value must be equal to 1 or bigger.')
]


@pytest.mark.parametrize('limit, page, expected_results', ARGS_CASES)
def test_check_args(limit, page, expected_results):
    """
        Given:
            - A command's arguments

        When:
            - running commands that has pagination

        Then:
            - checking that if the parameters < 1 , exception is thrown

        """
    from Bitbucket import check_args

    with pytest.raises(Exception) as e:
        check_args(limit, page)
    assert e.value.args[0] == expected_results


def test_get_paged_results(mocker):
    """
        Given:
            - A http response and a limit to the list

        When:
            - running a command with pagination needed

        Then:
            - return a list with all the results after pagination

        """
    from Bitbucket import get_paged_results, Client
    client = Client(workspace='workspace',
                    server_url='server_url',
                    auth=(),
                    proxy=False,
                    verify=False,
                    repository='repository')
    response1 = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('response1')
    response2 = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('response2')
    res = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('results')
    mocker.patch.object(Client, 'get_full_url', return_value=response2)
    results = get_paged_results(client, response1, 10)
    assert len(results) == 2
    assert results == res


def test_check_pagination():
    """
        Given:
            - A http response and a limit to the list

        When:
            - running a command with optional pagination, and checking if it is needed

        Then:
            - return a list with all the results after pagination
    """
    from Bitbucket import check_pagination, Client
    client = Client(workspace='workspace',
                    server_url='server_url',
                    auth=(),
                    proxy=False,
                    verify=False,
                    repository='repository')
    response = util_load_json('test_data/commands_test_data.json').get('check_pagination').get('response')
    res = util_load_json('test_data/commands_test_data.json').get('check_pagination').get('result')
    response_2 = util_load_json('test_data/commands_test_data.json').get('check_pagination').get('res_2')
    result_2 = util_load_json('test_data/commands_test_data.json').get('check_pagination').get('result_2')
    results10 = check_pagination(client, response, 10)
    results1 = check_pagination(client, response, 1)
    results_2 = check_pagination(client, response_2, 1)
    assert results10 == res
    assert results1 == res
    assert results_2 == result_2


create_pull_request_body_params = [('new_pr', 'test', 'master', '111111111', "hi this is a new pr", 'yes',
                                    {'title': 'new_pr',
                                     'source': {'branch': {'name': 'test'}},
                                     'destination': {'branch': {'name': 'master'}},
                                     'reviewers': [{'account_id': '111111111'}],
                                     'description': 'hi this is a new pr',
                                     'close_source_branch': True})]


@pytest.mark.parametrize('title, source_branch, destination_branch, reviewer_id, description, '
                         'close_source_branch, expected_body', create_pull_request_body_params)
def test_create_pull_request_body(title, source_branch, destination_branch, reviewer_id, description,
                                  close_source_branch, expected_body):
    """
        Given:
            - A body parameters to pull requests commands

        When:
            - running one of the following commands: pull_request_create or pull_request_update

        Then:
            - check that the function returns the correct body according to the parameters that it gets
    """
    from Bitbucket import create_pull_request_body
    body = create_pull_request_body(title, source_branch, destination_branch, reviewer_id, description, close_source_branch)
    assert body == expected_body


def test_project_list_command(mocker):
    """
    Given:
        - All relevant arguments for the command

    When:
        - bitcucket-project-list command is executed

    Then:
        - The http request is called with the right arguments.
    """
    from Bitbucket import project_list_command, Client
    client = Client(workspace='workspace',
                    server_url='server_url',
                    auth=(),
                    proxy=False,
                    verify=False,
                    repository='repository')
    args = {'limit': '10'}
    response = util_load_json('test_data/commands_test_data.json').get('check_pagination').get('response')
    expected_result = util_load_json('test_data/commands_test_data.json').get('check_pagination').get('result')
    mocker.patch.object(client, 'get_project_list_request', return_value=response)
    result = project_list_command(client, args)
    expected_readable_output = '### List of the projects in workspace\n|Key|Name|Description|IsPrivate|\n' \
                               '|---|---|---|---|\n| T1 | Test1 | description | true |\n'
    readable_output = result.readable_output
    assert readable_output == expected_readable_output
    assert result.raw_response == expected_result
