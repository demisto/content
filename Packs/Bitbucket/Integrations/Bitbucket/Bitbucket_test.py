"""
Pytest Unit Tests: all function names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS ""

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io

import pytest
from Bitbucket import Client


@pytest.fixture
def bitbucket_client():
    return Client(workspace='workspace',
                  server_url='server_url',
                  auth=(),
                  proxy=False,
                  verify=False,
                  repository='repository')


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_paged_results(mocker, bitbucket_client):
    """
        Given:
            - A http response and a limit to the list
        When:
            - running a command with pagination needed
        Then:
            - return a list with all the results after pagination
        """
    from Bitbucket import get_paged_results
    response1 = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('response1')
    response2 = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('response2')
    res = util_load_json('test_data/commands_test_data.json').get('get_paged_results').get('results')
    mocker.patch.object(bitbucket_client, 'get_full_url', return_value=response2)
    results = get_paged_results(bitbucket_client, response1, 10)
    assert len(results) == 2
    assert results == res


def test_check_pagination(bitbucket_client):
    """
        Given:
            - A http response and a limit to the list

        When:
            - running a command with optional pagination, and checking if it is needed

        Then:
            - return a list with all the results after pagination
    """
    from Bitbucket import check_pagination
    response = util_load_json('test_data/commands_test_data.json').get('check_pagination').get('response')
    res = util_load_json('test_data/commands_test_data.json').get('check_pagination').get('result')
    response_2 = util_load_json('test_data/commands_test_data.json').get('check_pagination').get('res_2')
    result_2 = util_load_json('test_data/commands_test_data.json').get('check_pagination').get('result_2')
    results10 = check_pagination(bitbucket_client, response, 10)
    results1 = check_pagination(bitbucket_client, response, 1)
    results_2 = check_pagination(bitbucket_client, response_2, 1)
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
    body = create_pull_request_body(title, source_branch, destination_branch, reviewer_id, description,
                                    close_source_branch)
    assert body == expected_body


def test_project_list_command(mocker, bitbucket_client):
    """
    Given:
        - All relevant arguments for the command

    When:
        - bitcucket-project-list command is executed

    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from Bitbucket import project_list_command
    args = {'limit': '10'}
    response = util_load_json('test_data/commands_test_data.json').get('check_pagination').get('res_2')
    expected_result = util_load_json('test_data/commands_test_data.json').get('check_pagination').get('result_2')
    mocker.patch.object(bitbucket_client, 'get_project_list_request', return_value=response)
    result = project_list_command(bitbucket_client, args)
    expected_readable_output = '### List of projects in workspace\n|Key|Name|Description|IsPrivate|\n' \
                               '|---|---|---|---|\n| T1 | Test1 | description | true |\n| T2 | Test1 | description | true |\n'
    readable_output = result.readable_output
    assert readable_output == expected_readable_output
    assert result.raw_response == expected_result


def test_project_list_command_with_project_key(mocker, bitbucket_client):
    """
    Given:
        - All relevant arguments for the command

    When:
        - bitcucket-project-list command is executed

    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from Bitbucket import project_list_command
    args = {'limit': '10', 'project_key': 'T1'}
    response = util_load_json('test_data/commands_test_data.json').get(
        'test_project_list_command_with_project_key').get('response')
    mocker.patch.object(bitbucket_client, 'get_project_list_request', return_value=response)
    result = project_list_command(bitbucket_client, args)
    expected_readable_output = '### The information about project T1\n|Key|Name|Description|IsPrivate|\n' \
                               '|---|---|---|---|\n| T1 | Test1 | description | true |\n'
    readable_output = result.readable_output
    assert readable_output == expected_readable_output
    assert result.raw_response == [response]


def test_open_branch_list_command(mocker, bitbucket_client):
    """
    Given:
        - All relevant arguments for the command
    When:
        - bitcucket-open-branch-list command is executed
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from Bitbucket import open_branch_list_command
    response = util_load_json('test_data/commands_test_data.json').get('test_open_branch_list_command')
    mocker.patch.object(bitbucket_client, 'get_open_branch_list_request', return_value=response)
    expected_result = response.get('values')
    expected_human_readable = '### Open Branches\n' \
                              '|Name|LastCommitCreatedBy|LastCommitCreatedAt|LastCommitHash|\n' \
                              '|---|---|---|---|\n' \
                              '| branch | Some User | 2022-09-08T00:00:00+00:00 | 1111111111111111111111111111111111111111 |\n' \
                              '| master | Some User | 2022-09-18T00:00:00+00:00 | 1111111111111111111111111111111111111111 |\n'
    result = open_branch_list_command(bitbucket_client, {})
    assert result.readable_output == expected_human_readable
    assert result.raw_response == expected_result


def test_branch_get_command(mocker, bitbucket_client):
    """
    Given:
        - All relevant arguments for the command
    When:
        - bitcucket-branch-get command is executed
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from Bitbucket import branch_get_command
    args = {'branch_name': 'master'}
    response = util_load_json('test_data/commands_test_data.json').get('test_branch_get_command')
    mocker.patch.object(bitbucket_client, 'get_branch_request', return_value=response)
    expected_human_readable = '### Information about the branch: master\n' \
                              '|Name|LastCommitCreatedBy|LastCommitCreatedAt|LastCommitHash|\n' \
                              '|---|---|---|---|\n' \
                              '| master | Some User | 2022-09-18T00:00:00+00:00 | 1111111111111111111111111111111111111111 |\n'
    result = branch_get_command(bitbucket_client, args)
    assert result.readable_output == expected_human_readable


def test_branch_create_command(mocker, bitbucket_client):
    """
    Given:
        - All relevant arguments for the command
    When:
        - bitcucket-branch-create command is executed
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from Bitbucket import branch_create_command
    http_request = mocker.patch.object(bitbucket_client, '_http_request')
    args = {'name': 'test', 'target_branch': 'master'}
    expected_body = {
        'target': {
            'hash': 'master'
        },
        'name': 'test'
    }
    branch_create_command(bitbucket_client, args)
    http_request.assert_called_with(method='POST',
                                    url_suffix='/repositories/workspace/repository/refs/branches',
                                    json_data=expected_body)


def test_branch_delete_command(mocker, bitbucket_client):
    """
    Given:
        - All relevant arguments for the command
    When:
        - bitcucket-branch-delete command is executed
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from Bitbucket import branch_delete_command
    http_request = mocker.patch.object(bitbucket_client, '_http_request')
    args = {'branch_name': 'test'}
    branch_delete_command(bitbucket_client, args)
    http_request.assert_called_with(method='DELETE',
                                    url_suffix='/repositories/workspace/repository/refs/branches/test',
                                    resp_type='response')


def test_commit_create_command(mocker, bitbucket_client):
    """
    Given:
        - All relevant arguments for the command
    When:
        - bitcucket-commit-create command is executed
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from Bitbucket import commit_create_command
    http_request = mocker.patch.object(bitbucket_client, '_http_request')
    args = {
        'message': 'message',
        'branch': 'branch',
        'file_name': 'hello.txt',
        'file_content': 'Hello world!'
    }
    expected_body = {
        "message": 'message',
        "branch": 'branch',
        'hello.txt': 'Hello world!'
    }
    commit_create_command(bitbucket_client, args)
    http_request.assert_called_with(method='POST',
                                    url_suffix='/repositories/workspace/repository/src',
                                    data=expected_body,
                                    resp_type='response')


def test_commit_list_command(mocker, bitbucket_client):
    """
    Given:
        - All relevant arguments for the command
    When:
        - bitcucket-commit-list command is executed
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from Bitbucket import commit_list_command
    args = {'included_branches': 'master', 'limit': '3'}
    response = util_load_json('test_data/commands_test_data.json').get('test_commit_list_command')
    mocker.patch.object(bitbucket_client, 'commit_list_request', return_value=response)
    expected_human_readable = '### The list of commits\n' \
                              '|Author|Commit|Message|CreatedAt|\n' \
                              '|---|---|---|---|\n' \
                              '| Some User <someuser@gmail.com> | 1111111111111111111111111111111111111111 ' \
                              '| delete the new file | 2022-09-18T00:00:00+00:00 |\n' \
                              '| Some User <someuser@gmail.com> | 1111111111111111111111111111111111111111 ' \
                              '| checking master | 2022-09-18T00:00:00+00:00 |\n' \
                              '| Some User <someuser@gmail.com> | 1111111111111111111111111111111111111111 ' \
                              '| delete the new file | 2022-09-18T00:00:00+00:00 |\n'
    result = commit_list_command(bitbucket_client, args)
    assert result.readable_output == expected_human_readable
    assert result.raw_response == response.get('values')


def test_issue_create_command(mocker, bitbucket_client):
    """
    Given:
        - All relevant arguments for the command
    When:
        - bitcucket-issue-create command is executed
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from Bitbucket import issue_create_command
    http_request = mocker.patch.object(bitbucket_client, '_http_request')
    args = {
        'title': 'NewIssue',
        'state': 'new',
        'type': 'enhancement',
        'priority': 'minor',
        'content': 'An enhancement to an integration'
    }
    expected_body = {
        'title': 'NewIssue',
        'state': 'new',
        'kind': 'enhancement',
        'priority': 'minor',
        'content': {
            'raw': 'An enhancement to an integration'
        }
    }
    issue_create_command(bitbucket_client, args)
    http_request.assert_called_with(method='POST',
                                    url_suffix='/repositories/workspace/repository/issues',
                                    json_data=expected_body)


def test_issue_list_command(mocker, bitbucket_client):
    """
    Given:
        - All relevant arguments for the command
    When:
        - bitcucket-issue-list command is executed
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from Bitbucket import issue_list_command
    args = {'limit': '3'}
    response = util_load_json('test_data/commands_test_data.json').get('test_issue_list_command')
    mocker.patch.object(bitbucket_client, 'issue_list_request', return_value=response)
    expected_human_readable = '### List of the issues\n' \
                              '|Id|Title|Type|Priority|Status|Votes|CreatedAt|UpdatedAt|\n' \
                              '|---|---|---|---|---|---|---|---|\n' \
                              '| 3 | hi | bug | minor | new | 0 | 2022-09-06T00:00:00.000000+00:00 ' \
                              '| 2022-09-28T00:00:00.000000+00:00 |\n' \
                              '| 93 | new bug | bug | major | new | 0 | 2022-09-28T00:00:00.000000+00:00 ' \
                              '| 2022-09-28T00:00:00.000000+00:00 |\n' \
                              '| 10 | title | bug | major | new | 0 | 2022-09-07T00:00:00.000000+00:00 ' \
                              '| 2022-09-22T00:00:00.000000+00:00 |\n'
    result = issue_list_command(bitbucket_client, args)
    assert result.readable_output == expected_human_readable
    assert result.raw_response == response.get('values')


def test_issue_update_command(mocker, bitbucket_client):
    """
    Given:
        - All relevant arguments for the command
    When:
        - bitcucket-issue-update command is executed
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from Bitbucket import issue_update_command
    http_request = mocker.patch.object(bitbucket_client, '_http_request')
    args = {
        'issue_id': '1',
        'title': 'No.1',
        'state': 'resolved',
        'type': 'enhancement',
        'priority': 'minor',
        'content': 'An enhancement to an integration'
    }
    expected_body = {
        'title': 'No.1',
        'state': 'resolved',
        'kind': 'enhancement',
        'priority': 'minor',
        'content': {
            'raw': 'An enhancement to an integration'
        }
    }
    issue_update_command(bitbucket_client, args)
    http_request.assert_called_with(method='PUT',
                                    url_suffix='/repositories/workspace/repository/issues/1/',
                                    json_data=expected_body)


def test_pull_request_create_command(mocker, bitbucket_client):
    """
    Given:
        - All relevant arguments for the command
    When:
        - bitcucket-pull-request-create command is executed
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from Bitbucket import pull_request_create_command
    http_request = mocker.patch.object(bitbucket_client, '_http_request')
    args = {
        'title': 'PR from test to master',
        'source_branch': 'test',
        'destination_branch': 'master',
        'description': 'A new pull request',
        'close_source_branch': 'yes'
    }
    expected_body = {
        'title': 'PR from test to master',
        'source': {
            'branch': {
                'name': 'test'
            }
        },
        'destination': {
            'branch': {
                'name': 'master'
            }
        },
        'description': 'A new pull request',
        'close_source_branch': True
    }
    pull_request_create_command(bitbucket_client, args)
    http_request.assert_called_with(method='POST',
                                    url_suffix='/repositories/workspace/repository/pullrequests',
                                    json_data=expected_body)
