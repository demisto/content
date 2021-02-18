import demistomock as demisto
import pytest

integration_params = {
    'url': 'https://localhost',
    'APItoken': 'token',
    'username': 'test',
    'password': '1234!',
    'query': 'status=Open'
}

integration_args_missing_mandatory_project_key_and_name = {
    "summary": "test",
}

integration_args_missing_mandatory_name = {
    "summary": "test",
    "projectKey": "testKey",
}

integration_args_missing_mandatory_key = {
    "summary": "test",
    "projectName": "testName",
}

integration_args = {
    "summary": "test",
    "projectKey": "testKey",
    "projectName": "testName"
}


@pytest.fixture(autouse=True)
def set_params(mocker):
    mocker.patch.object(demisto, 'params', return_value=integration_params)


@pytest.mark.parametrize('args', [integration_args, integration_args_missing_mandatory_name,
                                  integration_args_missing_mandatory_key])
def test_create_issue_command_after_fix_mandatory_args_issue(mocker, args):
    from JiraV2 import create_issue_command
    mocker.patch.object(demisto, 'args', return_value=args)
    user_data = {
        "self": "https://demistodev.atlassian.net/rest/api/2/user?accountId=1234", "accountId": "1234",
        "emailAddress": "admin@demistodev.com", "displayName": "test", "active": True,
        "timeZone": "Asia/Jerusalem", "locale": "en_US", "groups": {"size": 1, "items": []},
        "applicationRoles": {"size": 1, "items": []}, "expand": "groups,applicationRoles",
        "projects": [{'id': '1234', 'key': 'testKey', 'name': 'testName'}]
    }
    mocker.patch('JiraV2.jira_req', return_value=user_data)
    mocker.patch.object(demisto, "results")
    create_issue_command()
    assert demisto.results.call_count == 1


@pytest.mark.parametrize('args', [integration_args_missing_mandatory_project_key_and_name])
def test_create_issue_command_before_fix_mandatory_args_summary_missing(mocker, args):
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, "results")
    from JiraV2 import create_issue_command
    with pytest.raises(SystemExit) as e:
        # when there are missing arguments, an Exception is raised to the user
        create_issue_command()
    assert e
    assert demisto.results.call_args[0][0]['Contents'] == \
           'You must provide at least one of the following: project_key or project_name'


def test_issue_query_command_no_issues(mocker):
    """
    Given
    - Jira issue query command

    When
    - Sending HTTP request and getting no issues from the query

    Then
    - Verify no error message is thrown to the user
    """
    from JiraV2 import issue_query_command
    mocker.patch('JiraV2.run_query', return_value={})
    human_readable, _, _ = issue_query_command('status=Open AND labels=lies')
    assert 'No issues matched the query' in human_readable


def test_issue_query_command_with_results(mocker):
    """
    Given
    - Jira issue query command

    When
    - Sending HTTP request and getting one issues from the query

    Then
    - Verify outputs
    """
    from JiraV2 import issue_query_command
    from test_data.raw_response import QUERY_ISSUE_RESPONSE
    from test_data.expected_results import QUERY_ISSUE_RESULT

    mocker.patch('JiraV2.run_query', return_value=QUERY_ISSUE_RESPONSE)
    _, outputs, _ = issue_query_command('status!=Open', max_results=1)
    assert outputs == QUERY_ISSUE_RESULT


def test_fetch_incidents_no_incidents(mocker):
    """
    Given
    - Jira fetch incidents command

    When
    - Sending HTTP request and getting no issues from the query

    Then
    - Verify no incidents are returned
    """
    from JiraV2 import fetch_incidents
    mocker.patch('JiraV2.run_query', return_value={})
    incidents = fetch_incidents('status=Open AND labels=lies', id_offset=1)
    assert incidents == []


def test_module(mocker):
    """
    Given
    - Jira test module

    When
    - Sending HTTP request and getting the user details

    Then
    - Verify test module returns ok
    """
    from JiraV2 import test_module as module
    user_data = {
        "self": "https://demistodev.atlassian.net/rest/api/2/user?accountId=1234", "accountId": "1234",
        "emailAddress": "admin@demistodev.com", "displayName": "test", "active": True,
        "timeZone": "Asia/Jerusalem", "locale": "en_US", "groups": {"size": 1, "items": []},
        "applicationRoles": {"size": 1, "items": []}, "expand": "groups,applicationRoles"
    }
    mocker.patch('JiraV2.jira_req', return_value=user_data)
    mocker.patch('JiraV2.run_query', return_value={})
    result = module()
    assert result == 'ok'


def test_get_modified_remote_data(mocker):
    """
    The get-modified-remote-data command is not (yet) supported by this integration.
    Make sure an exception is thrown so the server knows about it.
    """
    from JiraV2 import main
    mocker.patch.object(demisto, 'command', return_value='get-modified-remote-data')
    with pytest.raises(NotImplementedError):
        main()


def test_get_remote_data(mocker):
    """
    Given:
        - Jira v2 client
        - An update for the issue

    When:
        - Running get-remote-date

    Then:
        - Verify the `updated` field is set as expected
    """
    from JiraV2 import get_remote_data_command
    updated_date = '2020-11-25T16:29:37.277764067Z'
    mocker.patch(
        'JiraV2.get_issue',
        return_value=('', '', {'fields': {'updated': updated_date}})
    )
    res = get_remote_data_command('id', '0')
    assert res.mirrored_object['updated'] == updated_date
