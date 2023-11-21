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
    get_paged_results_object = util_load_json('test_data/commands_test_data.json').get('get_paged_results')
    response1 = get_paged_results_object.get('response1')
    response2 = get_paged_results_object.get('response2')
    res = get_paged_results_object.get('results')
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
    res = response.get('values', [])
    results10 = check_pagination(bitbucket_client, response, 10)
    results1 = check_pagination(bitbucket_client, response, 1)
    assert results10 == res
    assert results1 == res


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
        - A limit to te list, a partial_response option.

    When:
        - bitbucket-project-list command is executed

    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from Bitbucket import project_list_command
    args = {'limit': '10', 'partial_response': 'false'}
    check_pagination_object = util_load_json('test_data/commands_test_data.json').get('check_pagination')
    response = check_pagination_object.get('response2')
    expected_result = response.get('values')
    mocker.patch.object(bitbucket_client, 'get_project_list_request', return_value=response)
    result = project_list_command(bitbucket_client, args)
    expected_readable_output = '### List of projects in workspace\n|Key|Name|Description|IsPrivate|\n' \
                               '|---|---|---|---|\n| T1 | Test1 | description | true |\n' \
                               '| T2 | Test2 | description | true |\n'
    readable_output = result.readable_output
    assert readable_output == expected_readable_output
    assert result.raw_response == expected_result


def test_project_list_command_with_project_key(mocker, bitbucket_client):
    """
    Given:
        - A project key, a partial_response option.

    When:
        - bitbucket-project-list command is executed

    Then:
        - The http request is called with the right arguments,
            and returns a command result with the project information.
    """
    from Bitbucket import project_list_command
    args = {'project_key': 'T1', 'partial_response': 'true'}
    test_json = util_load_json('test_data/commands_test_data.json')
    response = test_json.get('test_project_list_command_with_project_key').get('response')
    expected_partial_result = [test_json.get('test_project_list_command_with_project_key_partial_result')]
    mocker.patch.object(bitbucket_client, 'get_project_list_request', return_value=response)
    result = project_list_command(bitbucket_client, args)
    expected_readable_output = '### The information about project T1\n|Key|Name|Description|IsPrivate|\n' \
                               '|---|---|---|---|\n| T1 | Test1 | description | true |\n'
    readable_output = result.readable_output
    assert readable_output == expected_readable_output
    assert result.outputs == expected_partial_result


def test_open_branch_list_command(mocker, bitbucket_client):
    """
    Given:
            - No arguments needed to this function, a partial_response option.
    When:
        - bitbucket-open-branch-list command is executed.
    Then:
        - The http request is called with the right arguments,
        and returns a command result with a list of the open branches.
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
    result = open_branch_list_command(bitbucket_client, {'partial_response': 'false'})
    assert result.readable_output == expected_human_readable
    assert result.outputs == expected_result


def test_branch_get_command(mocker, bitbucket_client):
    """
    Given:
        - A branch name, a partial_response option.
    When:
        - bitbucket-branch-get command is executed
    Then:
        - The http request is called with the right arguments, and returns a command result with the branch information.
    """
    from Bitbucket import branch_get_command
    args = {'branch_name': 'master', 'partial_response': 'true'}
    test_json = util_load_json('test_data/commands_test_data.json')
    response = test_json.get('test_branch_get_command')
    expected_partial_result = test_json.get('test_branch_partial_result')
    mocker.patch.object(bitbucket_client, 'get_branch_request', return_value=response)
    expected_human_readable = '### Information about the branch: master\n' \
                              '|Name|LastCommitCreatedBy|LastCommitCreatedAt|LastCommitHash|\n' \
                              '|---|---|---|---|\n' \
                              '| master | Some User | 2022-09-18T00:00:00+00:00 | 1111111111111111111111111111111111111111 |\n'
    result = branch_get_command(bitbucket_client, args)
    assert result.readable_output == expected_human_readable
    assert result.outputs == expected_partial_result


def test_branch_create_command(mocker, bitbucket_client):
    """
    Given:
        - A name (for the new branch), a target branch (a source branch)
    When:
        - bitbucket-branch-create command is executed
    Then:
        - The http request is called with the right arguments,
        returns a command result with a success message and info about the new branch.
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
        - A branch name.
    When:
        - bitbucket-branch-delete command is executed
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
        - A commit message, a branch, a file name, a file content
    When:
        - bitbucket-commit-create command is executed
    Then:
        - The http request is called with the right arguments, creates a new file, and returns a success message.
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
        - A branch (that its commits will be on the list), a limit to the list, and a partial_response option.
    When:
        - bitbucket-commit-list command is executed
    Then:
        - The http request is called with the right arguments,
            and returns a command result with the relevant commit list.
    """
    from Bitbucket import commit_list_command
    args = {'included_branches': 'master', 'limit': '3', 'partial_response': 'false'}
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
        - A title, a state, a type, a priority, a content, for the new issue, and a partial_response option.
    When:
        - bitbucket-issue-create command is executed
    Then:
        - The http request is called with the right arguments, and returns a command result with a success message.
    """
    from Bitbucket import issue_create_command
    http_request = mocker.patch.object(bitbucket_client, '_http_request')
    args = {
        'title': 'NewIssue',
        'state': 'new',
        'type': 'enhancement',
        'priority': 'minor',
        'content': 'An enhancement to an integration',
        'partial_response': 'false'
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
        - A limit to the list, a partial_response option.
    When:
        - bitbucket-issue-list command is executed
    Then:
        - The http request is called with the right arguments, and returns a command result with the issue list.
    """
    from Bitbucket import issue_list_command
    args = {'limit': '3', 'partial_response': 'true'}
    test_object = util_load_json('test_data/commands_test_data.json')
    response = test_object.get('test_issue_list_command')
    expected_partial_result = test_object.get('test_issue_partial_result')
    mocker.patch.object(bitbucket_client, 'issue_list_request', return_value=response)
    expected_human_readable = '### Issues List\n' \
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
    assert result.outputs == expected_partial_result


def test_issue_update_command(mocker, bitbucket_client):
    """
    Given:
        - An issue id (to update), a title, a state, a type, a priority, a content.
    When:
        - bitbucket-issue-update command is executed
    Then:
        - The http request is called with the right arguments,
        returns a command result with a success message and info about the updated issue.
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
        - A title, a source branch, a destination branch, a description, and if to close the branch after the merge.
    When:
        - bitbucket-pull-request-create command is executed
    Then:
        - The http request is called with the right arguments, and returns a command result with info about
            the new PR and a success message.
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


def test_pull_request_update_command(mocker, bitbucket_client):
    """
    Given:
        - A title, a partial_response option, a source branch, a destination branch, a description,
            if to close the branch after the merge, and a PR id.
    When:
        - bitbucket-pull-request-update command is executed
    Then:
        - The http request is called with the right arguments, and returns a command result with a success message
            and info about the updated PR.
    """
    from Bitbucket import pull_request_update_command
    args = {
        'title': 'PR from test to master',
        'source_branch': 'test',
        'destination_branch': 'master',
        'description': 'Wanted to update the description of the pr',
        'close_source_branch': 'yes',
        'pull_request_id': '8',
        'partial_response': 'true'
    }
    test_obj = util_load_json('test_data/commands_test_data.json')
    response = test_obj.get('test_pull_request_update_command')
    expected_partial_result = test_obj.get('test_pull_request_partial_result')
    mocker.patch.object(bitbucket_client, 'pull_request_update_request', return_value=response)
    expected_human_readable = 'The pull request 8 was updated successfully'
    result = pull_request_update_command(bitbucket_client, args)
    assert result.readable_output == expected_human_readable
    assert result.outputs == expected_partial_result


def test_issue_comment_create_command(mocker, bitbucket_client):
    """
    Given:
        - An issue id and a comment content.
    When:
        - bitbucket-issue-comment-create command is executed
    Then:
        - The http request is called with the right arguments, and returns a command result with info and a success message.
    """
    from Bitbucket import issue_comment_create_command
    http_request = mocker.patch.object(bitbucket_client, '_http_request')
    args = {
        'issue_id': '1',
        'content': 'A new bug in line 0'
    }
    expected_body = {
        'content': {
            'raw': 'A new bug in line 0'
        }
    }
    issue_comment_create_command(bitbucket_client, args)
    http_request.assert_called_with(method='POST',
                                    url_suffix='/repositories/workspace/repository/issues/1/comments',
                                    json_data=expected_body)


def test_issue_comment_update_command(mocker, bitbucket_client):
    """
    Given:
        - An issue id, a comment content and a comment id.
    When:
        - bitbucket-issue-comment-update command is executed
    Then:
        - The http request is called with the right arguments, and returns a command result with info and a success message.
    """
    from Bitbucket import issue_comment_update_command
    http_request = mocker.patch.object(bitbucket_client, '_http_request')
    args = {
        'issue_id': '2',
        'content': 'debug issue',
        'comment_id': '11111'
    }
    expected_body = {
        'content': {
            'raw': 'debug issue'
        }
    }
    issue_comment_update_command(bitbucket_client, args)
    http_request.assert_called_with(method='PUT',
                                    url_suffix='/repositories/workspace/repository/issues/2/comments/11111',
                                    json_data=expected_body)


def test_pull_request_list_command(mocker, bitbucket_client):
    """
    Given:
        - A limit to the list, a partial_response option.
    When:
        - bitbucket-pull-request-list command is executed
    Then:
        - The http request is called with the right arguments, and returns a command result with the PR list.
    """
    from Bitbucket import pull_request_list_command
    args = {'limit': '2', 'partial_response': 'false'}
    response = util_load_json('test_data/commands_test_data.json').get('test_pull_request_list_command')
    mocker.patch.object(bitbucket_client, 'pull_request_list_request', return_value=response)
    expected_human_readable = '### List of the pull requests\n' \
                              '|Id|Title|Description|SourceBranch|DestinationBranch|State|CreatedBy|CreatedAt' \
                              '|UpdatedAt|\n' \
                              '|---|---|---|---|---|---|---|---|---|\n' \
                              '| 8 | pull_request | updating description | test | master | OPEN | Some User |' \
                              ' 2022-09-12T00:00:00.000000+00:00 | 2022-09-29T00:00:00.000000+00:00 |\n' \
                              '| 6 | uuuupdate | updates description | branch | master | OPEN | Some User |' \
                              ' 2022-09-08T00:00:00.000000+00:00 | 2022-09-28T00:00:00.000000+00:00 |\n'
    result = pull_request_list_command(bitbucket_client, args)
    assert result.readable_output == expected_human_readable
    assert result.raw_response == response.get('values')


def test_issue_comment_list_command(mocker, bitbucket_client):
    """
    Given:
        - A limit to the list and an issue id, a partial_response option.
    When:
        - bitbucket-issue-comment-list command is executed
    Then:
        - The http request is called with the right arguments, and returns a command result a list of comments of the issue.
    """
    from Bitbucket import issue_comment_list_command
    args = {'limit': '2', 'issue_id': '8', 'partial_response': 'false'}
    response = util_load_json('test_data/commands_test_data.json').get('test_issue_comment_list_command')
    mocker.patch.object(bitbucket_client, 'issue_comment_list_request', return_value=response)
    expected_human_readable = '### List of the comments on issue "8"\n' \
                              '|Id|Content|CreatedBy|CreatedAt|UpdatedAt|IssueId|IssueTitle|\n' \
                              '|---|---|---|---|---|---|---|\n' \
                              '| 11111111 |  | Some User | 2022-09-14T00:00:00.000000+00:00 |  | 8 | hi resolved |\n' \
                              '| 22222222 | The new and updated comment | Some User | 2022-09-14T00:00:00.000000+00:00 ' \
                              '| 2022-09-14T00:00:00.000000+00:00 | 8 | hi resolved |\n'
    result = issue_comment_list_command(bitbucket_client, args)
    assert result.readable_output == expected_human_readable
    assert result.raw_response == response.get('values')


def test_pull_request_comment_list_command(mocker, bitbucket_client):
    """
    Given:
        - A limit to the list, a PR id, and a partial_response option.
    When:
        - bitbucket-pull-request-comment-list command is executed
    Then:
        - The http request is called with the right arguments, and returns a command result with a list of PR comments.
    """
    from Bitbucket import pull_request_comment_list_command
    args = {'limit': '3', 'pull_request_id': '6', 'partial_response': 'true'}
    test_json = util_load_json('test_data/commands_test_data.json')
    response = test_json.get('test_pull_request_comment_list_command')
    expected_partial_result = test_json.get('test_comment_partial_result')
    mocker.patch.object(bitbucket_client, 'pull_request_comment_list_request', return_value=response)
    expected_human_readable = '### List of the comments on pull request "6"\n' \
                              '|Id|Content|CreatedBy|CreatedAt|UpdatedAt|PullRequestId|PullRequestTitle|\n' \
                              '|---|---|---|---|---|---|---|\n' \
                              '| 111111111 | hi | Some User | 2022-09-12T00:00:00.000000+00:00 ' \
                              '| 2022-09-12T00:00:00.000000+00:00 | 6 | uuuupdate |\n' \
                              '| 222222222 | hello | Some User | 2022-09-12T00:00:00.000000+00:00 ' \
                              '| 2022-09-12T00:00:00.000000+00:00 | 6 | uuuupdate |\n'
    result = pull_request_comment_list_command(bitbucket_client, args)
    assert result.readable_output == expected_human_readable
    assert result.outputs == expected_partial_result


def test_workspace_member_list_command(mocker, bitbucket_client):
    """
    Given:
        - A limit to the list, a partial_response option.
    When:
        - bitbucket-workspace-member-list command is executed
    Then:
        - The http request is called with the right arguments, and returns a command result with a list of the members.
    """
    from Bitbucket import workspace_member_list_command
    args = {'limit': '2', 'partial_response': 'true'}
    test_json = util_load_json('test_data/commands_test_data.json')
    response = test_json.get('test_workspace_member_list_command')
    expected_partial_result = test_json.get('test_workspace_member_list_partial_result')
    mocker.patch.object(bitbucket_client, 'workspace_member_list_request', return_value=response)
    expected_human_readable = '### The list of all the workspace members\n' \
                              '|Name|AccountId|\n' \
                              '|---|---|\n' \
                              '| Some User | 111111111111111111111111 |\n' \
                              '| Another User | 222222222222222222222222 |\n'
    result = workspace_member_list_command(bitbucket_client, args)
    assert result.readable_output == expected_human_readable
    assert result.outputs == expected_partial_result


def test_pull_request_comment_update_command(mocker, bitbucket_client):
    """
        Given:
            - A limit to the list, a partial_response option.
        When:
            - bitbucket-pull-request-comment-update command is executed
        Then:
            - The http request is called with the right arguments, and returns a command result with partial information
                about the updated comment.
        """
    from Bitbucket import pull_request_comment_update_command
    args = {'partial_response': 'false'}
    test_json = util_load_json('test_data/commands_test_data.json')
    response = test_json.get('test_pull_request_comment_update_command')
    mocker.patch.object(bitbucket_client, 'pull_request_comment_update_request', return_value=response)
    expected_human_readable = 'The comment was updated successfully'
    result = pull_request_comment_update_command(bitbucket_client, args)
    assert result.readable_output == expected_human_readable
    assert result.outputs == response
