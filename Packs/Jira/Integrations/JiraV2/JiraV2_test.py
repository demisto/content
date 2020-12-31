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
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    mocker.patch('JiraV2.run_query', return_value={})
    incidents = fetch_incidents('status=Open AND labels=lies', id_offset=1, should_get_attachments=False,
                                should_get_comments=False, should_mirror_in=False, should_mirror_out=False,
                                comment_tag='', attachment_tag='')
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
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    with pytest.raises(NotImplementedError):
        main()


def test_get_remote_data_when_needs_update(mocker):
    """
    Given:
        - Information regarding a changed incident in Demisto

    When:
        - Running get-remote-date and the incident needs to be updated

    Then:
        - Returns GetRemoteDataResponse object with the incident's details that needs to be updated
    """
    from JiraV2 import get_remote_data_command
    from test_data.expected_results import GET_JIRA_ISSUE_RES

    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    mocker.patch(
        'JiraV2.get_issue',
        return_value=('', '', GET_JIRA_ISSUE_RES)
    )
    mocker.patch(
        'JiraV2.get_comments_command',
        return_value=('No comments were found in the ticket', None, None)
    )
    mocker.patch(
        'JiraV2.get_attachments',
        return_value=''
    )
    res = get_remote_data_command({'id': '15', 'lastUpdate': '0'})
    assert len(res.mirrored_object) != 0
    assert res.entries == []


def test_get_remote_data_when_dont_need_update(mocker):
    """
    Given:
        - Information regarding a changed incident in Demisto

    When:
        - Running get-remote-date and the incident was already updated

    Then:
        - There aren't change to perform in Demisto
    """
    from JiraV2 import get_remote_data_command
    from test_data.expected_results import GET_JIRA_ISSUE_RES

    updated_date = '1996-11-25T16:29:37.277764067Z'
    GET_JIRA_ISSUE_RES['updated'] = updated_date
    mocker.patch(
        'JiraV2.get_issue',
        return_value=('', '', GET_JIRA_ISSUE_RES)
    )
    mocker.patch(
        'JiraV2.get_comments_command',
        return_value=('No comments were found in the ticket', None, None)
    )
    mocker.patch(
        'JiraV2.get_attachments',
        return_value=''
    )

    res = get_remote_data_command({'id': '15', 'lastUpdate': '2050-11-25T16:29:37.277764067Z'})
    assert res.mirrored_object == {}
    assert res.entries == []


def test_update_remote_system_delta(mocker):
    """
    Given:
        - Information regarding a changed incident in Demisto

    When:
        - An incident's summary was changed.

    Then:
        - The issue in Jira has the new summary.
    """
    from JiraV2 import update_remote_system_command
    mocker.patch(
        'JiraV2.edit_issue_command',
        return_value=''
    )
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    res = update_remote_system_command({'incidentChanged': '17757', 'remoteId': '17757', 'delta': {'summary': 'changes'}})
    assert res == '17757'


def test_get_mapping_fields():
    from JiraV2 import get_mapping_fields_command
    res = get_mapping_fields_command()
    assert list(res.scheme_types_mappings[0].fields.keys()) == ['issueId', 'summary', 'description', 'labels', 'priority', 'dueDate', 'assignee', 'status']


def test_get_new_attachment_return_result(mocker):
    """
    Given:
        - attachment related to an issue
        - The date the incident was last updated

    When:
        - An incident's attachment was modified\added

    Then:
        - The updated\new as fileResult
    """
    from JiraV2 import get_attachments
    from test_data.expected_results import JIRA_ATTACHMENT
    from dateparser import parse
    import pytz

    class file:
        def __init__(self):
            self.content = b'content'
    file_content = file()
    mocker.patch(
        'JiraV2.jira_req',
        return_value=file_content
    )
    res = get_attachments(JIRA_ATTACHMENT, parse('1996-11-25T16:29:37.277764067Z').replace(tzinfo=pytz.UTC))
    assert res[0]['File'] == 'download.png'


def test_get_new_attachment_without_return_new_attachment(mocker):
    """
    Given:
        - attachment related to an issue
        - The date the incident was last updated

    When:
        - An incident's attachment wasn't modified

    Then:
        - There is no attachment to update
    """
    from JiraV2 import get_attachments
    from test_data.expected_results import JIRA_ATTACHMENT
    from dateparser import parse
    import pytz

    class file:
        def __init__(self):
            self.content = b'content'
    file_content = file()
    mocker.patch(
        'JiraV2.jira_req',
        return_value=file_content
    )
    res = get_attachments(JIRA_ATTACHMENT, parse('2070-11-25T16:29:37.277764067Z').replace(tzinfo=pytz.UTC))
    assert res == []


def test_get_incident_entries(mocker):
    """
    Given:
        - Jira issue
        - The date the incident was last updated

    When:
        - An incident's attachment or comments are updated in Jira

    Then:
        - The new entries are returned
    """
    from JiraV2 import get_incident_entries
    from test_data.expected_results import GET_JIRA_ISSUE_RES
    from dateparser import parse
    import pytz

    updated_date = '1996-11-25T16:29:37.277764067Z'
    GET_JIRA_ISSUE_RES['updated'] = updated_date

    mocker.patch(
        'JiraV2.get_comments_command',
        return_value=('', '', {'comments': [{'updated': '2071-12-21 12:29:05.529000+00:00'}]})
    )
    mocker.patch(
        'JiraV2.get_attachments',
        return_value='here there is attachment'
    )
    res = get_incident_entries(GET_JIRA_ISSUE_RES, parse('2070-11-25T16:29:37.277764067Z').replace(tzinfo=pytz.UTC))
    assert len(res['comments']) > 0
    assert res['attachments'] == 'here there is attachment'


def test_create_update_incident_from_ticket():
    """
    Given:
        - incident
    When
        - need to update incident when an issue is modified in Jira
    Then
        - The updated incident
    """
    from JiraV2 import create_update_incident_from_ticket
    from test_data.expected_results import GET_JIRA_ISSUE_RES
    res = create_update_incident_from_ticket(GET_JIRA_ISSUE_RES)
    assert res['id'] == '17757'
    assert res['issue']
    assert list(res['fields'].keys()) == ['assignee', 'priority', 'status', 'project', 'reporter', 'summary', 'description', 'duedate', 'labels', 'updated', 'created', 'lastViewed']


def test_update_remote_system(mocker):
    """
    Given:
        - Information regarding a changed incident
    When
        - An incident was changed in Demisto
    Then
        - The remote system is updated and the incident id returns.
    """
    from JiraV2 import update_remote_system_command
    from test_data.expected_results import ARGS_FROM_UPDATE_REMOTE_SYS

    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(demisto, 'getFilePath', return_value={'name': 'file.png'})
    mocker.patch(
        'JiraV2.edit_issue_command',
        return_value=''
    )
    mocker.patch(
        'JiraV2.upload_file',
        return_value=''
    )
    res = update_remote_system_command(ARGS_FROM_UPDATE_REMOTE_SYS)
    assert res == '17757'


def test_fetch_incident_with_getting_attachments_and_comments(mocker):
    """
    Given:
        - Fetch parameters
    When
        - Incidents needs to include both attachments and comments.
    Then
        - Returned all fetched incidents with their attachments and comments.
    """
    from JiraV2 import fetch_incidents
    from test_data.raw_response import QUERY_ISSUE_RESPONSE
    from test_data.expected_results import GET_JIRA_ISSUE_RES
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    mocker.patch('JiraV2.run_query', return_value=QUERY_ISSUE_RESPONSE)
    mocker.patch.object(demisto, 'params', return_value={'fetch_attachments': True, 'fetch_comments': True, 'id_offset':'17803', 'query': 'status!=done'})
    mocker.patch(
        'JiraV2.get_comments_command',
        return_value=('', '', {'comments': [{'updated': '2071-12-21 12:29:05.529000+00:00'}]})
    )
    mocker.patch(
        'JiraV2.get_attachments',
        return_value=[{'FileID': 1, 'File': 'name', 'Type': 'file'}]
    )
    mocker.patch(
        'JiraV2.get_issue',
        return_value=('', '', GET_JIRA_ISSUE_RES)
    )
    res = fetch_incidents('status!=done', id_offset=1, should_get_attachments=True,
                                should_get_comments=True, should_mirror_in=False, should_mirror_out=False,
                                comment_tag='', attachment_tag='')
    assert list(res[0]['attachment'][0].keys()) == ['path', 'name']
    assert len(res[0]['labels'][12]['value']) > 0


def test_fetch_incident_with_getting_attachments(mocker):
    """
    Given:
        - Fetch parameters
    When
        - Incidents needs to include attachments.
    Then
        - Returned all fetched incidents with their attachments.
    """
    from JiraV2 import fetch_incidents
    from test_data.raw_response import QUERY_ISSUE_RESPONSE
    from test_data.expected_results import GET_JIRA_ISSUE_RES
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    mocker.patch('JiraV2.run_query', return_value=QUERY_ISSUE_RESPONSE)
    mocker.patch.object(demisto, 'params', return_value={'fetch_attachments': True, 'fetch_comments': True, 'id_offset':'17803', 'query': 'status!=done'})
    mocker.patch(
        'JiraV2.get_attachments',
        return_value=[{'FileID': 1, 'File': 'name', 'Type': 'file'}]
    )
    mocker.patch(
        'JiraV2.get_issue',
        return_value=('', '', GET_JIRA_ISSUE_RES)
    )
    res = fetch_incidents('status!=done', id_offset=1, should_get_attachments=True,
                                should_get_comments=False, should_mirror_in=False, should_mirror_out=False,
                                comment_tag='', attachment_tag='')
    assert list(res[0]['attachment'][0].keys()) == ['path', 'name']
    assert res[0]['labels'][12]['value'] == '[]'


def test_fetch_incident_with_getting_comments(mocker):
    """
    Given:
        - Fetch parameters
    When
        - Incidents needs to include comments.
    Then
        - Returned all fetched incidents with their comments.
    """
    from JiraV2 import fetch_incidents
    from test_data.raw_response import QUERY_ISSUE_RESPONSE
    from test_data.expected_results import GET_JIRA_ISSUE_RES
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    mocker.patch('JiraV2.run_query', return_value=QUERY_ISSUE_RESPONSE)
    mocker.patch.object(demisto, 'params', return_value={'fetch_attachments': True, 'fetch_comments': True, 'id_offset':'17803', 'query': 'status!=done'})
    mocker.patch(
        'JiraV2.get_comments_command',
        return_value=('', '', {'comments': [{'updated': '2071-12-21 12:29:05.529000+00:00'}]})
    )
    mocker.patch(
        'JiraV2.get_issue',
        return_value=('', '', GET_JIRA_ISSUE_RES)
    )
    res = fetch_incidents('status!=done', id_offset=1, should_get_attachments=False,
                                should_get_comments=True, should_mirror_in=False, should_mirror_out=False,
                                comment_tag='', attachment_tag='')
    assert res[0]['attachment'] == []
    assert len(res[0]['labels'][12]['value']) > 0


def test_fetch_incident_with_comments_when_exception_is_raised(mocker):
    """
    Given:
        - Fetch parameters
    When
        - Incidents needs to include comments and there is an exception raised.
    Then
        - Returned all fetched incidents without their comments.
    """
    from JiraV2 import fetch_incidents
    from test_data.raw_response import QUERY_ISSUE_RESPONSE
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    mocker.patch('JiraV2.run_query', return_value=QUERY_ISSUE_RESPONSE)
    mocker.patch.object(demisto, 'params', return_value={'fetch_attachments': True, 'fetch_comments': True, 'id_offset':'17803', 'query': 'status!=done'})
    mocker.patch(
        'JiraV2.get_comments_command',
        return_value=('', '', {'comments': [{'updated': '2071-12-21 12:29:05.529000+00:00'}]})
    )
    mocker.patch(
        'JiraV2.get_issue',
        return_value=TimeoutError,
    )
    res = fetch_incidents('status!=done', id_offset=1, should_get_attachments=False,
                                should_get_comments=True, should_mirror_in=False, should_mirror_out=False,
                                comment_tag='', attachment_tag='')
    assert res[0]['labels'][12]['value'] == '[]'


def test_fetch_incident_mirror_direction(mocker):
    """
    Given:
        - Fetch parameters
    When
        - Incidents needs to include Which direction to mirror its data- test 'Both' in this case.
    Then
        - Returned all fetched incidents without 'mirror_direction' set to 'Both'.
    """
    from JiraV2 import fetch_incidents
    from test_data.raw_response import QUERY_ISSUE_RESPONSE
    from test_data.expected_results import GET_JIRA_ISSUE_RES
    import json

    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')
    mocker.patch('JiraV2.run_query', return_value=QUERY_ISSUE_RESPONSE)
    mocker.patch.object(demisto, 'params', return_value={'fetch_attachments': True, 'fetch_comments': True, 'id_offset':'17803', 'query': 'status!=done'})
    mocker.patch(
        'JiraV2.get_comments_command',
        return_value=('', '', {'comments': [{'updated': '2071-12-21 12:29:05.529000+00:00'}]})
    )
    mocker.patch(
        'JiraV2.get_issue',
        return_value=('', '', GET_JIRA_ISSUE_RES)
    )
    res = fetch_incidents('status!=done', id_offset=1, should_get_attachments=False,
                                should_get_comments=True, should_mirror_in=True, should_mirror_out=True,
                                comment_tag='', attachment_tag='')
    assert json.loads(res[0]['rawJSON'])['mirror_direction'] == 'Both'


def test_handle_incoming_closing_incident(mocker):
    """
    Given:
        - Issue with status 'Done'
    When
        - Mirror in Data from Jira to Demisto
    Then
        - Returned an object for close its incident
    """
    from JiraV2 import handle_incoming_closing_incident, fetch_incidents
    from test_data.expected_results import GET_JIRA_ISSUE_RES
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')

    GET_JIRA_ISSUE_RES['fields']['status']['name'] = 'Done'
    res = handle_incoming_closing_incident(GET_JIRA_ISSUE_RES)
    assert res['Contents']['dbotIncidentClose'] is True
    assert res['Contents']['closeReason'] == 'Issue was marked as "Done"'


def test_get_mirror_type_both():
    """
    Given:
        - Mirror out is 'True' and mirror in 'True'
    When
        - Need to map mirror_in and mirror_out into 'Both'
    Then
        - Returned the correct mirror direction
    """
    from JiraV2 import get_mirror_type

    res = get_mirror_type(True, True)
    assert res == 'Both'


def test_get_mirror_type_out():
    """
    Given:
        - Mirror out is 'True' and mirror in 'False'
    When
        - Need to map mirror_in and mirror_out input to 'Out'
    Then
        - Returned the correct mirror direction
    """
    from JiraV2 import get_mirror_type

    res = get_mirror_type(False, True)
    assert res == 'Out'


def test_get_mirror_type_in():
    """
    Given:
        - Mirror out is 'False' and mirror in 'True'
    When
        - Need to map mirror_in and mirror_out input to 'In'
    Then
        - Returned the correct mirror direction
    """
    from JiraV2 import get_mirror_type

    res = get_mirror_type(True, False)
    assert res == 'In'


def test_get_mirror_type_none():
    """
    Given:
        - Mirror out is 'False' and mirror in 'False'
    When
        - Need to map mirror_in and mirror_out input to None
    Then
        - Returned the correct mirror direction
    """
    from JiraV2 import get_mirror_type

    res = get_mirror_type(False, False)
    assert res is None
