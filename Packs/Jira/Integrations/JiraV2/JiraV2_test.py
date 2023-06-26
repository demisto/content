from optparse import OptionParser
from unittest.mock import Mock
import demistomock as demisto
import pytest
from CommonServerPython import *

integration_params = {
    "url": "https://localhost",
    "APItoken": "token",
    "username": "test",
    "password": "1234!",
    "query": "status=Open",
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
    "projectName": "testName",
}


@pytest.fixture(autouse=True)
def set_params(mocker):
    mocker.patch.object(demisto, "params", return_value=integration_params)


@pytest.mark.parametrize(
    "args",
    [
        integration_args,
        integration_args_missing_mandatory_name,
        integration_args_missing_mandatory_key,
    ],
)
def test_create_issue_command_after_fix_mandatory_args_issue(mocker, args):
    from JiraV2 import create_issue_command

    mocker.patch.object(demisto, "args", return_value=args)
    user_data = {
        "self": "https://demistodev.atlassian.net/rest/api/2/user?accountId=1234",
        "accountId": "1234",
        "emailAddress": "admin@demistodev.com",
        "displayName": "test",
        "active": True,
        "timeZone": "Asia/Jerusalem",
        "locale": "en_US",
        "groups": {"size": 1, "items": []},
        "applicationRoles": {"size": 1, "items": []},
        "expand": "groups,applicationRoles",
        "projects": [{"id": "1234", "key": "testKey", "name": "testName"}],
    }
    mocker.patch("JiraV2.jira_req", return_value=user_data)
    mocker.patch.object(demisto, "results")
    create_issue_command()
    assert demisto.results.call_count == 1


@pytest.mark.parametrize(
    "args", [integration_args_missing_mandatory_project_key_and_name]
)
def test_create_issue_command_before_fix_mandatory_args_summary_missing(mocker, args):
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")
    from JiraV2 import create_issue_command

    with pytest.raises(SystemExit) as e:
        # when there are missing arguments, an Exception is raised to the user
        create_issue_command()
    assert e
    assert (demisto.results.call_args[0][0]["Contents"] == "You must provide at least one of the following: "
                                                           "project_key or project_name")


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

    mocker.patch("JiraV2.run_query", return_value={})
    human_readable, _, _ = issue_query_command("status=Open AND labels=lies")
    assert "No issues matched the query" in human_readable


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

    mocker.patch("JiraV2.run_query", return_value=QUERY_ISSUE_RESPONSE)
    _, outputs, _ = issue_query_command("status!=Open", max_results=1)
    assert outputs == QUERY_ISSUE_RESULT


def test_issue_query_command_with_custom_fields_with_results(mocker, requests_mock):
    """
    Given
    - Jira issue query command and extraFields parameters

    When
    - Sending HTTP request and getting one issues from the query

    Then
    - Verify outputs
    """
    from JiraV2 import issue_query_command
    from test_data.raw_response import QUERY_ISSUE_RESPONSE, EXPECTED_RESP
    from test_data.expected_results import QUERY_ISSUE_RESULT_WITH_CUSTOM_FIELDS
    requests_mock.get('https://localhost/rest/api/latest/search/', json=QUERY_ISSUE_RESPONSE)
    mocker.patch("JiraV2.get_custom_field_names", return_value=EXPECTED_RESP)
    _, outputs, _ = issue_query_command("status!=Open", extra_fields="Owner", max_results=1)
    assert outputs == QUERY_ISSUE_RESULT_WITH_CUSTOM_FIELDS


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

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch("JiraV2.run_query", return_value={})
    mocker.patch.object(demisto, 'setLastRun')
    incidents = fetch_incidents(
        "status=Open AND labels=lies",
        id_offset=1,
        should_get_attachments=False,
        should_get_comments=False,
        should_mirror_in=False,
        should_mirror_out=False,
        comment_tag="",
        attachment_tag="",
    )
    assert incidents == []
    assert demisto.setLastRun.call_count == 1
    lastRun = demisto.setLastRun.call_args[0][0]
    assert lastRun == {'idOffset': 0, 'lastCreatedTime': ''}


def test_fetch_incidents_no_incidents_with_id_offset_in_last_run(mocker):
    """
    Given
    - Jira fetch incidents command
    - Last run is populated with idOffset but no lastCreatedTime


    When
    - Sending HTTP request and getting no issues from the query

    Then
    - Verify no incidents are returned
    - Last run idOffset is not changed and an empty lastCreatedTime is added
    """

    from JiraV2 import fetch_incidents

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch("JiraV2.run_query", return_value={})
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'getLastRun', return_value={'idOffset': 30})
    incidents = fetch_incidents(
        "status=Open AND labels=lies",
        id_offset=1,
        should_get_attachments=False,
        should_get_comments=False,
        should_mirror_in=False,
        should_mirror_out=False,
        comment_tag="",
        attachment_tag="",
    )
    assert incidents == []
    assert demisto.setLastRun.call_count == 1
    last_run = demisto.setLastRun.call_args[0][0]
    assert last_run == {'idOffset': 30, 'lastCreatedTime': ''}


def test_fetch_incidents_with_incidents_and_id_offset_in_last_run(mocker):
    """
    Given
    - Jira fetch incidents command
    - Last run is populated with idOffset but no lastCreatedTime

    When
    - Sending HTTP request and getting new issue

    Then
    - Verify last run is updated with the ticket id offset and created time
    """

    from JiraV2 import fetch_incidents
    from test_data.raw_response import QUERY_ISSUE_RESPONSE

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch("JiraV2.run_query", return_value=QUERY_ISSUE_RESPONSE)
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'getLastRun', return_value={'idOffset': 30})
    incidents = fetch_incidents(
        "status=Open AND labels=lies",
        id_offset=1,
        should_get_attachments=False,
        should_get_comments=False,
        should_mirror_in=False,
        should_mirror_out=False,
        comment_tag="",
        attachment_tag="",
    )
    assert len(incidents) == 1
    assert demisto.setLastRun.call_count == 1
    last_run = demisto.setLastRun.call_args[0][0]
    assert last_run == {'idOffset': 12652, 'lastCreatedTime': '2019-05-04T00:44:31.743+0300'}


def test_fetch_incidents_with_incidents_and_full_last_run(mocker):
    """
    Given
    - Jira fetch incidents command
    - Last run is populated with idOffset and lastCreatedTime

    When
    - Sending HTTP request and getting new issue

    Then
    - Verify last run is updated with the ticket id offset and are updated
    """

    from JiraV2 import fetch_incidents
    from test_data.raw_response import QUERY_ISSUE_RESPONSE

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch("JiraV2.run_query", return_value=QUERY_ISSUE_RESPONSE)
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'getLastRun',
                        return_value={'idOffset': 1000, 'lastCreatedTime': '2019-04-04T00:55:22.743+0300'})
    incidents = fetch_incidents(
        "status=Open AND labels=lies",
        id_offset=1,
        should_get_attachments=False,
        should_get_comments=False,
        should_mirror_in=False,
        should_mirror_out=False,
        comment_tag="",
        attachment_tag="",
    )
    assert len(incidents) == 1
    assert demisto.setLastRun.call_count == 1
    last_run = demisto.setLastRun.call_args[0][0]
    assert last_run == {'idOffset': 12652, 'lastCreatedTime': '2019-05-04T00:44:31.743+0300'}


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
        "self": "https://demistodev.atlassian.net/rest/api/2/user?accountId=1234",
        "accountId": "1234",
        "emailAddress": "admin@demistodev.com",
        "displayName": "test",
        "active": True,
        "timeZone": "Asia/Jerusalem",
        "locale": "en_US",
        "groups": {"size": 1, "items": []},
        "applicationRoles": {"size": 1, "items": []},
        "expand": "groups,applicationRoles",
    }
    mocker.patch("JiraV2.jira_req", return_value=user_data)
    mocker.patch("JiraV2.run_query", return_value={})
    result = module()
    assert result == "ok"


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

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch("JiraV2.get_issue", return_value=("", "", GET_JIRA_ISSUE_RES))
    mocker.patch(
        "JiraV2.get_comments_command",
        return_value=("No comments were found in the ticket", None, None),
    )
    mocker.patch("JiraV2.get_attachments", return_value="")
    res = get_remote_data_command({"id": "15", "lastUpdate": "0"})
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

    updated_date = "1996-11-25T16:29:37.277764067Z"
    GET_JIRA_ISSUE_RES["updated"] = updated_date
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch("JiraV2.get_issue", return_value=("", "", GET_JIRA_ISSUE_RES))
    mocker.patch(
        "JiraV2.get_comments_command",
        return_value=("No comments were found in the ticket", None, None),
    )
    mocker.patch("JiraV2.get_attachments", return_value="")

    res = get_remote_data_command(
        {"id": "15", "lastUpdate": "2050-11-25T16:29:37.277764067Z"}
    )
    assert res.mirrored_object == {'in_mirror_error': ''}
    assert res.entries == []


def test_update_remote_system_delta(mocker):
    """
    Given:
        - Information regarding a changed incident in XSOAR

    When:
        - An incident's summary was changed.

    Then:
        - The issue in Jira has the new summary.
    """
    import JiraV2
    from JiraV2 import update_remote_system_command

    mocker.patch("JiraV2.edit_issue_command", return_value="")
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    res = update_remote_system_command(
        {
            "incidentChanged": "17757",
            "remoteId": "17757",
            "data": {"summary": "data", "not_changes_key": "not_changes_val"},
            "delta": {"summary": "changes", "dbotMirrorDirection": "test"},
        }
    )
    assert res == "17757"
    assert JiraV2.edit_issue_command.call_args[1]['summary'] == 'data'


def test_get_mapping_fields(mocker):
    from JiraV2 import get_mapping_fields_command
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch("JiraV2.get_custom_fields", return_value={})
    res = get_mapping_fields_command()
    assert list(res.scheme_types_mappings[0].fields.keys()) == [
        "issueId",
        "summary",
        "description",
        "labels",
        "priority",
        "dueDate",
        "assignee",
        "status",
        "assignee_id"
    ]


def test_get_new_attachment_return_result(requests_mock):
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

    requests_mock.get('https://localhost/rest/attachment/content/14848', json={})
    res = get_attachments(JIRA_ATTACHMENT, parse("1996-11-25T16:29:35.277764067Z"))
    assert res[0]["File"] == "download.png"


def test_get_all_attachment_return_result(requests_mock):
    """
    Given:
        - attachment related to an issue
        - The date the incident was last updated

    When:
        - An incident's attachment was modified\added

    Then:
        - Getting all attachments as fileResult
    """
    from JiraV2 import get_attachments
    from test_data.expected_results import JIRA_ATTACHMENT_ALL
    from dateparser import parse

    for attachment in JIRA_ATTACHMENT_ALL:
        requests_mock.get(attachment.get('content'), json={})
        requests_mock.get(attachment.get('self'), json={'filename': attachment.get('filename')})

    res = get_attachments(
        JIRA_ATTACHMENT_ALL, parse("1996-11-25T16:29:35.277764067Z"), only_new=False
    )
    assert res[0]["File"] == "filename1"
    assert res[1]["File"] == "filename2"
    assert res[2]["File"] == "filename3"


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
            self.content = b"content"

    file_content = file()
    mocker.patch("JiraV2.jira_req", return_value=file_content)
    res = get_attachments(
        JIRA_ATTACHMENT,
        parse("2070-11-25T16:29:37.277764067Z").replace(tzinfo=pytz.UTC),
    )
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

    updated_date = "1996-11-25T16:29:37.277764067Z"
    GET_JIRA_ISSUE_RES["updated"] = updated_date

    mocker.patch(
        "JiraV2.get_comments_command",
        return_value=(
            "",
            "",
            {"comments": [{"updated": "2071-12-21 12:29:05.529000+00:00"}]},
        ),
    )
    mocker.patch("JiraV2.get_attachments", return_value="here there is attachment")
    res = get_incident_entries(
        GET_JIRA_ISSUE_RES,
        parse("2070-11-25T16:29:37.277764067Z").replace(tzinfo=pytz.UTC),
    )
    assert len(res["comments"]) > 0
    assert res["attachments"] == "here there is attachment"


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

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "getFilePath", return_value={"name": "file.png"})
    mocker.patch("JiraV2.edit_issue_command", return_value="")
    mocker.patch("JiraV2.upload_file", return_value="")
    mocker.patch("JiraV2.add_comment", return_value="")
    res = update_remote_system_command(ARGS_FROM_UPDATE_REMOTE_SYS)
    assert res == "17757"


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

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch("JiraV2.run_query", return_value=QUERY_ISSUE_RESPONSE)
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "fetch_attachments": True,
            "fetch_comments": True,
            "id_offset": "17803",
            "query": "status!=done",
        },
    )
    mocker.patch(
        "JiraV2.get_comments_command",
        return_value=(
            "",
            "",
            {"comments": [{"updated": "2071-12-21 12:29:05.529000+00:00"}]},
        ),
    )
    mocker.patch(
        "JiraV2.get_attachments",
        return_value=[{"FileID": 1, "File": "name", "Type": "file"}],
    )
    mocker.patch("JiraV2.get_issue", return_value=("", "", GET_JIRA_ISSUE_RES))
    res = fetch_incidents(
        "status!=done",
        id_offset=1,
        should_get_attachments=True,
        should_get_comments=True,
        should_mirror_in=False,
        should_mirror_out=False,
        comment_tag="",
        attachment_tag="",
    )
    assert list(res[0]["attachment"][0].keys()) == ["path", "name"]
    assert len(res[0]["labels"][12]["value"]) > 0


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

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch("JiraV2.run_query", return_value=QUERY_ISSUE_RESPONSE)
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "fetch_attachments": True,
            "fetch_comments": True,
            "id_offset": "17803",
            "query": "status!=done",
        },
    )
    mocker.patch(
        "JiraV2.get_attachments",
        return_value=[{"FileID": 1, "File": "name", "Type": "file"}],
    )
    mocker.patch("JiraV2.get_issue", return_value=("", "", GET_JIRA_ISSUE_RES))
    res = fetch_incidents(
        "status!=done",
        id_offset=1,
        should_get_attachments=True,
        should_get_comments=False,
        should_mirror_in=False,
        should_mirror_out=False,
        comment_tag="",
        attachment_tag="",
    )
    assert list(res[0]["attachment"][0].keys()) == ["path", "name"]
    assert res[0]["labels"][12]["value"] == "[]"


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

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch("JiraV2.run_query", return_value=QUERY_ISSUE_RESPONSE)
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "fetch_attachments": True,
            "fetch_comments": True,
            "id_offset": "17803",
            "query": "status!=done",
        },
    )
    mocker.patch(
        "JiraV2.get_comments_command",
        return_value=(
            "",
            "",
            {"comments": [{"updated": "2071-12-21 12:29:05.529000+00:00"}]},
        ),
    )
    mocker.patch("JiraV2.get_issue", return_value=("", "", GET_JIRA_ISSUE_RES))
    res = fetch_incidents(
        "status!=done",
        id_offset=1,
        should_get_attachments=False,
        should_get_comments=True,
        should_mirror_in=False,
        should_mirror_out=False,
        comment_tag="",
        attachment_tag="",
    )
    assert res[0]["attachment"] == []
    assert len(res[0]["labels"][12]["value"]) > 0


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

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch("JiraV2.run_query", return_value=QUERY_ISSUE_RESPONSE)
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "fetch_attachments": True,
            "fetch_comments": True,
            "id_offset": "17803",
            "query": "status!=done",
        },
    )
    mocker.patch(
        "JiraV2.get_comments_command",
        return_value=(
            "",
            "",
            {"comments": [{"updated": "2071-12-21 12:29:05.529000+00:00"}]},
        ),
    )
    mocker.patch(
        "JiraV2.get_issue", return_value=TimeoutError,
    )
    res = fetch_incidents(
        "status!=done",
        id_offset=1,
        should_get_attachments=False,
        should_get_comments=True,
        should_mirror_in=False,
        should_mirror_out=False,
        comment_tag="",
        attachment_tag="",
    )
    assert res[0]["labels"][12]["value"] == "[]"


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

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch("JiraV2.run_query", return_value=QUERY_ISSUE_RESPONSE)
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "fetch_attachments": True,
            "fetch_comments": True,
            "id_offset": "17803",
            "query": "status!=done",
        },
    )
    mocker.patch(
        "JiraV2.get_comments_command",
        return_value=(
            "",
            "",
            {"comments": [{"updated": "2071-12-21 12:29:05.529000+00:00"}]},
        ),
    )
    mocker.patch("JiraV2.get_issue", return_value=("", "", GET_JIRA_ISSUE_RES))
    res = fetch_incidents(
        "status!=done",
        id_offset=1,
        should_get_attachments=False,
        should_get_comments=True,
        should_mirror_in=True,
        should_mirror_out=True,
        comment_tag="",
        attachment_tag="",
    )
    assert json.loads(res[0]["rawJSON"])["mirror_direction"] == "Both"


def test_handle_incoming_closing_incident(mocker):
    """
    Given:
        - Issue with status 'Done'
    When
        - Mirror in Data from Jira to Demisto
    Then
        - Returned an object for close its incident
    """
    from JiraV2 import handle_incoming_closing_incident
    from test_data.expected_results import GET_JIRA_ISSUE_RES

    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")

    GET_JIRA_ISSUE_RES["fields"]["status"]["name"] = "Done"
    res = handle_incoming_closing_incident(GET_JIRA_ISSUE_RES)
    assert res["Contents"]["dbotIncidentClose"] is True
    assert res["Contents"]["closeReason"] == 'Issue was marked as "Done"'


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
    assert res == "Both"


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
    assert res == "Out"


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
    assert res == "In"


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


def test_edit_issue_status(mocker):
    """
    Given:
        - New status for an issue
    When
        - Need to change a status of an issue
    Then
        - An issue has a new status
    """
    from JiraV2 import (
        edit_issue_command,
        edit_status
    )

    mocker.patch("JiraV2.jira_req", return_value=None)
    mocker.patch("JiraV2.get_issue_fields", return_value=None)
    mocker.patch("JiraV2.get_issue", return_value=True)
    mocker.patch(
        "JiraV2.list_transitions_data_for_issue",
        return_value={"transitions": [{"name": "To Do", "id": 1, "to": {
            "self": "https: //demistodev.atlassian.net/rest/api/2/status/10000",
            "description": "",
            "iconUrl": "https://demistodev.atlassian.net/images/icons/status_generic.gif",
            "name": "To Do",
            "id": "10000",
            "statusCategory": {
                "self": "https://demistodev.atlassian.net/rest/api/2/statuscategory/2",
                "id": 2,
                "key": "new",
                "colorName": "blue-gray",
                "name": "To Do"
            }
        }}]},
    )
    mocked_return_error = mocker.patch("JiraV2.return_error", return_value=None)
    mocked_edit_transition = mocker.patch("JiraV2.edit_transition", return_value=None)
    mocked_edit_status = mocker.patch("JiraV2.edit_status", side_effect=edit_status)
    res = edit_issue_command("1234", status="To Do")
    assert mocked_return_error.call_count == 0
    assert mocked_edit_status.call_count == 1
    assert mocked_edit_transition.call_count == 0
    assert res is True


def test_edit_issue_transition(mocker):
    """
    Given:
        - New transition for an issue
    When
        - Need to change transition type in order to change the issue's status
    Then
        - An issue has a new transition
    """
    from JiraV2 import (
        edit_issue_command,
        edit_transition,
    )

    mocker.patch("JiraV2.jira_req", return_value=None)
    mocker.patch("JiraV2.get_issue_fields", return_value=None)
    mocker.patch("JiraV2.get_issue", return_value=True)
    mocker.patch(
        "JiraV2.list_transitions_data_for_issue",
        return_value={"transitions": [{"name": "To Do", "id": 1}]},
    )
    mocked_return_error = mocker.patch("JiraV2.return_error", return_value=None)
    mocked_edit_transition = mocker.patch(
        "JiraV2.edit_transition", side_effect=edit_transition
    )
    mocked_edit_status = mocker.patch("JiraV2.edit_status", return_value=None)
    res = edit_issue_command("1234", transition="To Do")
    assert mocked_return_error.call_count == 0
    assert mocked_edit_status.call_count == 0
    assert mocked_edit_transition.call_count == 1
    assert res is True


def test_edit_issue_when_passing_both_transition_and_status(mocker):
    """
    Given:
        - Transition and status for an issue
    When
        - A user passes to edit_issue command both parameters
    Then
        - Error is being returned saying both parameters can't be passed
    """
    from JiraV2 import edit_issue_command

    mocker.patch("JiraV2.jira_req", return_value=None)
    mocker.patch("JiraV2.get_issue_fields", return_value=None)
    mocker.patch("JiraV2.get_issue", return_value=True)
    mocker.patch(
        "JiraV2.list_transitions_data_for_issue",
        return_value={"transitions": [{"name": "To Do", "id": 1}]},
    )
    mocked_return_error = mocker.patch("JiraV2.return_error", return_value=None)
    mocked_edit_transition = mocker.patch("JiraV2.edit_transition", return_value=None)
    mocked_edit_status = mocker.patch("JiraV2.edit_status", return_value=None)
    edit_issue_command("1234", transition="To Do", status="To Do")
    assert mocked_return_error.call_count == 1
    assert mocked_edit_status.call_count == 0
    assert mocked_edit_transition.call_count == 0


def test_list_transitions_command(mocker):
    """
    Given:
        - issueId
    When
        - Need to get a list of all possible transitions
    Then
        - Returns a list of transitions
    """
    from JiraV2 import list_transitions_command

    mocker.patch(
        "JiraV2.list_transitions_data_for_issue",
        return_value={"transitions": [{"name": "To Do", "id": 1}]},
    )
    res = list_transitions_command({"issueId": "123"})
    assert res.outputs_key_field == "ticketId"
    assert res.raw_response == ["To Do"]
    assert res.outputs == {"ticketId": "123", "transitions": ["To Do"]}


def test_get_modified_data_command(mocker):
    """
    Given:
        - Date string represents the last time we retrieved modified incidents for this integration.
    When
        - Before running get_remote_data_command
    Then
        - Returns a list of changed incidents
    """
    from JiraV2 import get_modified_remote_data_command
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")
    mocker.patch("JiraV2.json", return_value={"timeZone": "Asia/Jerusalem"})

    class Res:
        def __init__(self):
            self.status_code = 200

        def json(self):
            return {"timeZone": "Asia/Jerusalem"}

    response = Res()
    response.json()
    mocker.patch("JiraV2.get_user_info_data", return_value=response)
    mocker.patch(
        "JiraV2.issue_query_command",
        return_value=(None, None, {"issues": [{"id": "123"}]}),
    )

    modified_ids = get_modified_remote_data_command({"lastUpdate": "1"})
    assert modified_ids.modified_incident_ids == ["123"]


def test_get_modified_data_command_when_getting_exception_for_get_user_info_data(
        mocker,
):
    """
    Given:
        - Date string represents the last time we retrieved modified incidents for this integration.
    When
        - Having an error in get_user_info_data function.
    Then
        - An error is printed via demisto.error and returning an empty modified_incident_ids list
    """
    from JiraV2 import get_modified_remote_data_command

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")
    mocked_demisto_error = mocker.patch.object(demisto, "error")
    mocker.patch(
        "JiraV2.get_user_info_data", side_effect=Mock(side_effect=Exception("Test"))
    )
    modified_ids = get_modified_remote_data_command({"lastUpdate": "0"})
    assert mocked_demisto_error.call_count == 1
    assert modified_ids.modified_incident_ids == []


def test_get_modified_data_command_when_getting_not_ok_status_code_for_get_user_info_data(
        mocker,
):
    """
    Given:
        - Date string represents the last time we retrieved modified incidents for this integration.
    When
        - Getting '404' from get_user_info_data function.
    Then
        - An error is printed via demisto.error and returning an empty modified_incident_ids list
    """
    from JiraV2 import get_modified_remote_data_command

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")
    mocker.patch("JiraV2.json", return_value={"timeZone": "Asia/Jerusalem"})

    class res:
        def __init__(self):
            self.status_code = 404
            self.reason = "Not Found"

    response = res()
    mocker.patch("JiraV2.get_user_info_data", return_value=response)
    mocked_demisto_error = mocker.patch.object(demisto, "error")

    modified_ids = get_modified_remote_data_command({"lastUpdate": "0"})
    assert mocked_demisto_error.call_count == 1
    assert modified_ids.modified_incident_ids == []


def test_get_comments_command(mocker):
    """
    Given:
        - IssueId
    When
        - Running get_comments_command in order to get an issue's comments.
    Then
        - Returns a list of comments for the given issue.
    """
    from JiraV2 import get_comments_command

    comments = {
        "comments": [
            {
                "updated": "2071-12-21 12:29:05.529000+00:00",
                "body": "comment text",
                "updateAuthor": {"name": "Test"},
                "created": "10.12",
            }
        ]
    }
    mocker.patch("JiraV2.jira_req", return_value=comments)

    _, outputs, context = get_comments_command(123)
    assert list(outputs.keys())[0] == "Ticket(val.Id == obj.Id)"
    assert outputs["Ticket(val.Id == obj.Id)"]["Id"] == 123
    assert (outputs["Ticket(val.Id == obj.Id)"]["Comment"][0]["Comment"] == "comment text")
    assert outputs["Ticket(val.Id == obj.Id)"]["Comment"][0]["User"] == "Test"
    assert outputs["Ticket(val.Id == obj.Id)"]["Comment"][0]["Created"] == "10.12"
    assert context == comments


def test_get_issue_fields_issue_json_param():
    """
    Given:
        - issue_json param
    When
        - editing an issue using 'jira-edit-issue' command
    Then
        - json as dict
    """
    from JiraV2 import get_issue_fields
    res = get_issue_fields(issue_json='{"description": "test"}')
    assert {'description': 'test', 'fields': {}} == res


def test_get_issue_fields_issuejson_param():
    """
    Given:
        - issueJson param
    When
        - Creating a new issue using 'jira-create-issue' command
    Then
        - json as dict
    """
    from JiraV2 import get_issue_fields
    res = get_issue_fields(issueJson='{"description": "test"}')
    assert {'description': 'test', 'fields': {}} == res


def test_get_issue_fields():
    from JiraV2 import get_issue_fields
    issue_fields = get_issue_fields(False, False,
                                    **{"components": "Test, Test 1", "security": "Anyone", "environment": "Test"})
    assert issue_fields == {'fields': {'components': [{'name': 'Test'}, {'name': 'Test 1'}], 'environment': 'Test',
                                       'security': {'name': 'Anyone'}}}


@pytest.mark.parametrize('get_attachments_arg, should_get_attachments', [
    ('true', True), ('false', False)
])
def test_get_issue_and_attachments(mocker, get_attachments_arg, should_get_attachments):
    """
    Given:
        - Case A: That the user has set the get_attachments to 'true' as he wants to download attachments
        - Case B: That the user has set the get_attachments to 'false' as he does not want to download attachments
    When
        - Calling the get issue command
    Then
        - Ensure the demisto.results with file data is called
        - Ensure the demisto.results with file data is not called
    """
    from test_data.raw_response import GET_ISSUE_RESPONSE
    from JiraV2 import get_issue
    from requests import Response

    def jira_req_mock(method: str, resource_url: str, body: str = '', link: bool = False, resp_type: str = 'text',
                      headers: dict = None, files: dict = None):

        response = Response()
        response.status_code = 200
        response._content = b'{"filename": "filename"}'

        if resource_url == 'rest/attachment/15451':
            return response
        elif resp_type == 'json':
            return GET_ISSUE_RESPONSE
        else:
            return type("RequestObjectNock", (OptionParser, object), {"content": 'Some zip data'})

    mocker.patch("JiraV2.jira_req", side_effect=jira_req_mock)
    demisto_results_mocker = mocker.patch.object(demisto, 'results')
    get_issue('id', get_attachments=get_attachments_arg)
    if should_get_attachments:
        demisto_results_mocker.assert_called_once()
    else:
        demisto_results_mocker.assert_not_called()


OAUTH1 = {
    'url': 'example.com',
    'consumerKey': 'example_key',
    'accessToken': 'example_token',
    'privateKey': 'example_private_key',
    'username': ''
}

PAT = {'url': 'example.com', 'username': '', 'accessToken': 'example_token'}

BASIC = {'url': 'example.com', 'username': 'example_user', 'APItoken': 'example_token'}
AUTH_CASES = [
    (OAUTH1, {}, {'Content-Type': 'application/json', 'X-Atlassian-Token': 'nocheck'}),
    (OAUTH1, {'X-Atlassian-Token': 'nocheck'}, {'X-Atlassian-Token': 'nocheck'}),
    (PAT, {}, {'Content-Type': 'application/json', 'Authorization': 'Bearer example_token'}),
    (PAT, {'X-Atlassian-Token': 'nocheck'}, {'X-Atlassian-Token': 'nocheck', 'Authorization': 'Bearer example_token'}),
    (BASIC, {}, {'Content-Type': 'application/json'}),
    (BASIC, {'X-Atlassian-Token': 'nocheck'}, {'X-Atlassian-Token': 'nocheck'}),
]


def test_get_project_id_old_version(requests_mock):
    """
    Given:
        - Jira api version less than 9.0.0.
    When
        - Running the create issue command.
    Then
        - Ensure only the original api endpoint is being used.
    """
    from JiraV2 import get_project_id
    first_case_mock = requests_mock.get('https://localhost/rest/api/latest/issue/createmeta', status_code=200,
                                        json={"projects": [{"name": "Test_name", "key": "Test_key", "id": "Test_id"}]})
    second_case_mock = requests_mock.get('https://localhost/rest/api/latest/project', status_code=200)
    id = get_project_id(project_name='Test_name')
    assert id == 'Test_id'
    assert first_case_mock.called_once and not second_case_mock.called


def test_get_project_id(mocker):
    """
    Given:
        - Jira api version greater or equal to 9.0.0.
    When
        - Running the create issue command.
    Then
        - Ensure only the new api endpoint is being used.
    """
    from JiraV2 import get_project_id

    def mock_res(method, endpoint, resp_type):
        if endpoint == 'rest/api/latest/issue/createmeta':
            raise DemistoException("Status code: 404\nMessage: Issue Does Not Exist")
        elif endpoint == 'rest/api/latest/project':
            return [{"name": "Test_name", "key": "Test_key", "id": "Test_id"}]

    mocker.patch('JiraV2.jira_req', side_effect=mock_res)
    id = get_project_id(project_name='Test_name')
    assert id == 'Test_id'


def test_get_project_id_non_english(mocker):
    """
    Given:
        - Exception (404) contains non english content.
    When
        - Running the create issue command.
    Then
        - Ensure the new api endpoint is being used.
    """
    from JiraV2 import get_project_id

    def mock_res(method, endpoint, resp_type):
        if endpoint == 'rest/api/latest/issue/createmeta':
            raise DemistoException("Status code: 404\nMessage: La Incidencia no Existe")
        elif endpoint == 'rest/api/latest/project':
            return [{"name": "Test_name", "key": "Test_key", "id": "Test_id"}]

    mocker.patch('JiraV2.jira_req', side_effect=mock_res)
    id = get_project_id(project_name='Test_name')
    assert id == 'Test_id'


@pytest.mark.parametrize('params, custom_headers, expected_headers', AUTH_CASES)
def test_jira_req(mocker, requests_mock, params, custom_headers, expected_headers):
    """
       Given:
           - Case OAuth authentication: The user is using the default headers for a command
           - Case OAuth authentication: The user is using custom headers for a command
           - Case PAT authentication: The user is using the default headers for a command
           - Case PAT authentication: The user is using custom headers for a command
           - Case BASIC authentication: The user is using the default headers for a command
           - Case BASIC authentication: The user is using custom headers for a command

       When
           - Running any command, trying to make a request to Jira while using specific authentication.
       Then
           - Ensure the authentication headers are correct when using custom headers
           - Ensure the authentication headers are correct when using default headers
       """
    import JiraV2

    class ResponseDummy():
        def __init__(self):
            self.ok = 1

    req_mock = mocker.patch.object(JiraV2.SESSION, 'request', return_value=ResponseDummy())
    JiraV2.USERNAME = params.get('username')
    JiraV2.HEADERS = {'Content-Type': 'application/json'}
    mocker.patch.object(demisto, "params", return_value=params)
    JiraV2.jira_req(method='get',
                    resource_url=params.get('url'),
                    headers=custom_headers)
    assert expected_headers == req_mock.call_args[1]['headers']


def test_get_issue_outputs(mocker):
    """
    Given:
        - The issue ID.
    When
        - Running the get issue command.
    Then
        - Ensure the outputs as expected
    """
    from test_data.raw_response import GET_ISSUE_RESPONSE
    from test_data.expected_results import GET_ISSUE_OUTPUTS_RESULT
    from JiraV2 import get_issue

    mocker.patch('JiraV2.jira_req', return_value=GET_ISSUE_RESPONSE)

    _, outputs, _ = get_issue('id')

    assert outputs == GET_ISSUE_OUTPUTS_RESULT


def test_get_custom_field_names(mocker, requests_mock):
    from JiraV2 import get_custom_field_names
    from test_data.raw_response import FIELDS_RESPONSE, EXPECTED_RESP
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    requests_mock.get('https://localhost/rest/api/latest/field', json=FIELDS_RESPONSE)
    res = get_custom_field_names()
    assert res == EXPECTED_RESP


def test_get_attachment_data_request(mocker, requests_mock):
    """
    Given:
        - An attachment data.
    When
        - Running the get_attachment_data command.
    Then
        - Ensure the command does not fail due to a wrong url.
    """
    from JiraV2 import get_attachment_data
    from test_data.raw_response import ATTACHMENTS

    mocker.patch.object(demisto, "params", return_value=integration_params)
    requests_mock.get('https://localhost/rest/api/2/attachment/content/16188', json={})

    assert get_attachment_data(ATTACHMENTS['cloud_attachment']), 'There was a request to the wrong url'


@pytest.mark.parametrize('attachment_to_extract,expected_link', [
    ('cloud_attachment', '/rest/api/2/attachment/content/16188'),
    ('on_prem_attachment', '/secure/attachment/18447/filename')])
def test_get_attachment_data_url_processing(mocker, requests_mock, attachment_to_extract, expected_link):
    """
    Given:
        - Case a: An attachment data from jira cloud instance.
        - Case b: An attachment data from jira on prem instance.
    When
        - Running the get_attachment_data command.
    Then
        - Ensure the filename output is correct, and the req_path correspond to the right type of system.
    """
    from JiraV2 import get_attachment_data
    from test_data.raw_response import ATTACHMENTS
    attachment = ATTACHMENTS[attachment_to_extract]
    url_to_mock = attachment.get('content')
    request = requests_mock.get(url_to_mock, json={})
    mocker.patch.object(demisto, "params", return_value=integration_params)

    filename, _ = get_attachment_data(attachment)

    assert filename == 'filename'
    assert request.last_request.path == expected_link


attribute_mock_response_email_exists = [
    {'self': 'https://test.atlassian.net',
     'accountId': 'TEST-ID',
     'accountType': 'atlassian',
     'emailAddress': 'some_email@mail.com',
     'avatarUrls': {},
     'displayName': 'some user',
     'active': True,
     'timeZone': 'Asia',
     'locale': 'en_US'
     }]

attribute_mock_response_no_email = [
    {'self': 'https://test.atlassian.net',
     'accountId': 'TEST-ID',
     'accountType': 'atlassian',
     'emailAddress': '',
     'avatarUrls': {},
     'displayName': 'some user',
     'active': True,
     'timeZone': 'Asia',
     'locale': 'en_US'
     }]

attribute_mock_response_no_email_multiple = [
    {'self': 'https://test1.atlassian.net',
     'accountId': 'TEST-ID1',
     'accountType': 'atlassian',
     'emailAddress': '',
     'avatarUrls': {},
     'displayName': 'some user1',
     'active': True,
     'timeZone': 'Asia',
     'locale': 'en_US'
     },
    {'self': 'https://test2.atlassian.net',
     'accountId': 'TEST-ID2',
     'accountType': 'atlassian',
     'emailAddress': '',
     'avatarUrls': {},
     'displayName': 'some user2',
     'active': True,
     'timeZone': 'Asia',
     'locale': 'en_US'
     }
]


@pytest.mark.parametrize('mock_response, expected_output', [(attribute_mock_response_email_exists, 'TEST-ID'),
                                                            (attribute_mock_response_no_email, 'TEST-ID'),
                                                            (attribute_mock_response_no_email_multiple,
                                                             'Multiple account IDs found')])
def test_get_account_id_from_attribute_valid_attribute_match(mocker, mock_response, expected_output):
    """
    Given:
        - An email attribute.
    When
        - Running the get_account_id_from_attribute command when:
         1. email matches the email in the response.
         2. email in the response is hidden but there is only one option.
         3. email in the response is hidden and there are multiple options.
    Then
        - Ensure the attribute was found and the output is correct.
    """
    from JiraV2 import get_account_id_from_attribute

    mocker.patch('JiraV2.search_user', return_value=mock_response)
    mocker.patch.object(demisto, "params", return_value=integration_params)
    res = get_account_id_from_attribute(attribute='some_email@mail.com')
    if len(mock_response) == 2:  # case number three
        assert expected_output in res
    else:
        assert expected_output == res.outputs['AccountID']


def test_get_account_id_from_attribute_attribute_do_not_match(mocker):
    """
    Given:
        - An email attribute.
    When
        - Running the get_account_id_from_attribute command.
    Then
        - Ensure the attribute was found but no match for the email.
    """
    from JiraV2 import get_account_id_from_attribute
    mock_response = [
        {'self': 'https://test.atlassian.net',
         'accountId': 'TEST-ID',
         'accountType': 'atlassian',
         'emailAddress': '',
         'avatarUrls': {},
         'displayName': 'some user',
         'active': True,
         'timeZone': 'Asia',
         'locale': 'en_US'
         }]
    mocker.patch('JiraV2.search_user', return_value=mock_response)
    mocker.patch.object(demisto, "params", return_value=integration_params)
    res = get_account_id_from_attribute(attribute='some_email@mail.com')

    assert res.outputs['AccountID'] == 'TEST-ID'


def test_append_to_empty_field_command(mocker):
    """
    Given:
        - The issue ID, a json of field and new values
    When
        - Running the append_to_field_command
    Then
        - Ensure appending is working as excpected
    """
    from test_data.raw_response import GET_ISSUE_RESPONSE
    from JiraV2 import append_to_field_command

    mocker.patch('JiraV2.jira_req', return_value=GET_ISSUE_RESPONSE)
    mocker.patch('JiraV2.__get_field_type', return_value='string')
    mock_update = mocker.patch('JiraV2._update_fields')

    _, outputs, _ = append_to_field_command('id', field_json='{"labels":"New"}')

    mock_update.assert_called_with('id', {'labels': 'New'})


def test_append_to_existing_field_command(mocker):
    """
    Given:
        - The issue ID, a json of field and new values
    When
        - Running the append_to_field_command
    Then
        - Ensure appending is working as excpected
    """
    from test_data.raw_response import GET_ISSUE_RESPONSE_WITH_LABELS
    from JiraV2 import append_to_field_command

    mocker.patch('JiraV2.jira_req', return_value=GET_ISSUE_RESPONSE_WITH_LABELS)
    mocker.patch('JiraV2.__get_field_type', return_value='array')
    mock_update = mocker.patch('JiraV2._update_fields')

    _, outputs, _ = append_to_field_command('id', field_json='{"labels":"New"}')

    mock_update.assert_called_with('id', {'labels': ['test', 'New']})


@pytest.mark.parametrize(
    'assignee, assignee_id, excpected_body_request',
    [
        ("server_assignee", None, '{"name": "server_assignee"}'),
        (None, "cloud_assignee", '{"accountId": "cloud_assignee"}')
    ]
)
def test_update_issue_assignee_command(mocker, assignee, assignee_id, excpected_body_request):
    """
    Given:
        - issue id, and assignees for cloud/server jira
    When
        - Running the update_issue_assignee_command
    Then
        - Ensure the body request is ok for both cloud/server jira
    """
    from test_data.raw_response import GET_ISSUE_RESPONSE
    from JiraV2 import update_issue_assignee_command

    jira_req_mocker = mocker.patch('JiraV2.jira_req', side_effect=['', GET_ISSUE_RESPONSE])

    assert update_issue_assignee_command(issue_id='19141', assignee=assignee, assignee_id=assignee_id)
    assert jira_req_mocker.call_args_list[0].args[2] == excpected_body_request


def test_test_update_issue_assignee_command_no_assignees():
    """
    Given:
        - issue id, without assignee / assignee_id
    When
        - Running the update_issue_assignee_command
    Then
        - Ensure an exception is raised
    """
    from JiraV2 import update_issue_assignee_command

    with pytest.raises(DemistoException):
        update_issue_assignee_command(issue_id='19141', assignee=None, assignee_id=None)


def test_get_organizations(mocker):
    from test_data.raw_response import ORGANIZATIONS
    from JiraV2 import get_organizations_command
    mocker.patch.object(demisto, "results")
    organizations = [
        {
            "id": "23",
            "name": "TEST"
        },
        {
            "id": "4",
            "name": "XSOAR"
        }
    ]
    mocker.patch("JiraV2.jira_req", return_value=ORGANIZATIONS)
    result = get_organizations_command()
    assert result.raw_response == organizations


def test_get_project_role(mocker):
    from test_data.raw_response import PROJECT_ROLES, PROJECT_ROLE
    from JiraV2 import get_project_role_command
    mocker.patch("JiraV2.get_project_roles", return_value=PROJECT_ROLES)
    mocker.patch("JiraV2.jira_req", return_value=PROJECT_ROLE)

    role = get_project_role_command("demisto", "Agent")
    assert role.get('id') == 11823


def test_get_project_roles(mocker):
    from test_data.raw_response import PROJECT_ROLES
    from JiraV2 import get_project_roles
    mocker.patch("JiraV2.jira_req", return_value=PROJECT_ROLES)

    roles = get_project_roles("demisto")
    assert len(roles) == 2
