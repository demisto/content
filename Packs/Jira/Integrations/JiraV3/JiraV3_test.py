import io
import json
import pytest
import demistomock as demisto
from unittest.mock import patch
from JiraV3 import (JiraBaseClient, JiraCloudClient, JiraOnPremClient)
from CommonServerPython import *


def util_load_json(path: str):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def util_load_bytes_file(path: str):
    with io.open(path, mode='rb') as f:
        return f.read()
        # return json.loads(f.read())


@patch.object(JiraBaseClient, '__abstractmethods__', set())
def jira_base_client_mock() -> JiraBaseClient:
    """The way to mock an abstract class is using the trick @patch.object(Abstract_Class, __abstractmethods__, set()),
    since Python, behind the scenes, checks the __abstractmethods__ property, which contains a set of the names of all
    the abstract methods defined on the abstract class, if it is not empty, we won't be able to instantiate the abstract class,
    however, if this set is empty, the Python interpreter will happily instantiate our class without any problems.
    """
    return JiraBaseClient(base_url='dummy_url', proxy=False, verify=False, callback_url='dummy_callback')


def jira_cloud_client_mock() -> JiraCloudClient:
    return JiraCloudClient(proxy=False, verify=False, client_id='dummy_client_id',
                           client_secret='dummy_secret', callback_url='dummy_url', cloud_id='dummy_cloud_id',
                           server_url='dummy_server_url')


def jira_onprem_client_mock() -> JiraOnPremClient:
    return JiraOnPremClient(proxy=False, verify=False, client_id='dummy_client_id',
                            client_secret='dummy_secret', callback_url='dummy_url',
                            server_url='dummy_server_url')


# Helper functions unit tests
ADF_TEXT_CASES = [
    ('Hello there', {
        'type': 'doc',
        'version': 1,
        'content': [
            {
                'type': 'paragraph',
                'content': [
                    {
                        'text': 'Hello there',
                        'type': 'text'
                    }
                ]
            }
        ]
    }
    )
]


@pytest.mark.parametrize('text, expected_adf_text', ADF_TEXT_CASES)
def test_text_to_adf(text, expected_adf_text):
    from JiraV3 import text_to_adf
    adf_text = text_to_adf(text=text)
    assert expected_adf_text == adf_text


COMMENT_URL_CASES = [
    ('https://dummy-domain.atlassian.net/rest/api/3/issue/10010/comment/10000', '10010'),
    ('http://dummy-domain.com/some_path/latest/issue/123/comment/', '123')
]


@pytest.mark.parametrize('url, expected_issue_id', COMMENT_URL_CASES)
def test_extract_issue_id_from_comment_url(url, expected_issue_id):
    from JiraV3 import extract_issue_id_from_comment_url
    issue_id = extract_issue_id_from_comment_url(comment_url=url)
    assert expected_issue_id == issue_id


ISSUE_FIELDS_MAPPING_CASES = [
    ([
        {
            "id": "statuscategorychangedate",
            "key": "statuscategorychangedate",
            "name": "Status Category Changed",
            "custom": False,
            "orderable": False,
            "navigable": True,
            "searchable": True,
            "clauseNames": [
                "statusCategoryChangedDate"
            ],
            "schema": {
                "type": "datetime",
                "system": "statuscategorychangedate"
            }
        },
        {
            "id": "parent",
            "key": "parent",
            "name": "Parent",
            "custom": False,
            "orderable": False,
            "navigable": True,
            "searchable": False,
            "clauseNames": [
                "parent"
            ]
        }], {
        "statuscategorychangedate": "Status Category Changed",
        "parent": "Parent"})
]


@pytest.mark.parametrize('issue_fields, issue_fields_mapping', ISSUE_FIELDS_MAPPING_CASES)
def test_get_issue_fields_mapping(mocker, issue_fields, issue_fields_mapping):
    from JiraV3 import JiraBaseClient, get_issue_fields_id_to_name_mapping
    mocker.patch.object(JiraBaseClient, 'get_issue_fields', return_value=issue_fields)
    client = jira_base_client_mock()
    mapping_result = get_issue_fields_id_to_name_mapping(client=client)
    assert mapping_result == issue_fields_mapping


CREATE_ISSUE_QUERY_CASES = [
    (
        'some_jql_string', None, None,
        {'jql': 'some_jql_string', 'startAt': 0, 'maxResults': 50},
    ),
    (
        'some_jql_string', 12, None,
        {'jql': 'some_jql_string', 'startAt': 12, 'maxResults': 50},
    ),
    (
        'some_jql_string', 1, 80,
        {'jql': 'some_jql_string', 'startAt': 1, 'maxResults': 80},
    )
]


@pytest.mark.parametrize('jql, start_at, max_results, expected_query_params', CREATE_ISSUE_QUERY_CASES)
def test_create_query_params(jql, start_at, max_results, expected_query_params):
    from JiraV3 import create_query_params
    query_params = create_query_params(jql_query=jql, start_at=start_at, max_results=max_results)
    assert query_params == expected_query_params


PAGINATION_ARGS_CASES = [
    ({'page': 1, 'page_size': 3, 'limit': 5}, {'start_at': 3, 'max_results': 3}),
    ({'limit': 5}, {'start_at': 0, 'max_results': 5}),
    ({'page': 4, 'limit': 5}, {'start_at': 200, 'max_results': 50}),
    ({'page_size': 23, 'limit': 5}, {'start_at': 0, 'max_results': 23})
]


@pytest.mark.parametrize('pagination_args, expected_parsed_pagination_args', PAGINATION_ARGS_CASES)
def test_prepare_pagination_args(pagination_args, expected_parsed_pagination_args):
    from JiraV3 import prepare_pagination_args
    parsed_pagination_args = prepare_pagination_args(**pagination_args)
    assert expected_parsed_pagination_args == parsed_pagination_args


# Commands unit tests

# BOARD_EPICS_LIST_CASES = [
#     ('test_data/raw_responses/board_epics/board_epic_list.json', 'test_data/parsed_responses/board_epics/board_epic_list.json'),
#     ('test_data/raw_responses/board_epics/board_epic_list_empty.json',
#      'test_data/parsed_responses/board_epics/board_epic_list_empty.json')
# ]


# @pytest.mark.parametrize('raw_response_file, expected_parsed_response_file', BOARD_EPICS_LIST_CASES)
# def test_jira_board_epic_list(mocker, raw_response_file, expected_parsed_response_file):
#     """Check that the jira-board-epic-list parses the raw results correctly
#     """
#     from JiraV3 import board_epic_list_command
#     raw_response = util_load_json(raw_response_file)
#     expected_parsed_response = util_load_json(expected_parsed_response_file)
#     client = jira_base_client_mock()
#     mocker.patch.object(client, 'get_epics_from_board', return_value=raw_response)
#     parsed_response = board_epic_list_command(client=client, args={'board_id': '14'})
#     assert parsed_response.to_context() == expected_parsed_response


# SPRINT_ISSUES_LIST_CASES = [
#     ('test_data/raw_responses/sprint_issues/sprint_issues_list.json',
#      'test_data/parsed_responses/sprint_issues/sprint_issues_list.json'),
#     ('test_data/raw_responses/sprint_issues/sprint_issues_list_empty.json',
#      'test_data/parsed_responses/sprint_issues/sprint_issues_list_empty.json')
# ]


# @pytest.mark.parametrize('raw_response_file, expected_parsed_response_file', SPRINT_ISSUES_LIST_CASES)
# def test_jira_sprint_issue_list(mocker, raw_response_file, expected_parsed_response_file):
#     """Check that the jira-sprint-issue-list parses the raw results correctly
#     """
#     from JiraV3 import sprint_issues_list_command
#     raw_response = util_load_json(raw_response_file)
#     expected_parsed_response = util_load_json(expected_parsed_response_file)
#     client = jira_base_client_mock()
#     mocker.patch.object(client, 'get_issues_from_sprint', return_value=raw_response)
#     mocker.patch.object(client, 'get_sprint_issues_from_board', return_value=raw_response)
#     parsed_response = sprint_issues_list_command(client=client, args={'sprint_id': '4'})
#     assert parsed_response.to_context() == expected_parsed_response

class TestJiraGetIssueCommand:
    def test_create_file_info_from_attachment(self, mocker):
        """
        Given:
            - An attachment id
        When
            - Calling the get create_file_info_from_attachment function to create a file of type EntryType.ENTRY_INFO_FILE
        Then
            - Validate that the file has been created, is of the correct type, and has the correct file name.
        """
        import os
        from CommonServerPython import EntryType
        from JiraV3 import create_file_info_from_attachment
        client = jira_base_client_mock()
        raw_response_attachment_metadata = util_load_json('test_data/get_issue_test/raw_response_attachment_metadata.json')
        dummy_attachment_content = util_load_bytes_file('test_data/get_issue_test/dummy_attachment_content.txt')
        mocker.patch.object(client, 'get_attachment_metadata', return_value=raw_response_attachment_metadata)
        mocker.patch.object(client, 'get_attachment_content', return_value=dummy_attachment_content)
        file_name = 'dummy_file_name.pdf'
        file_info_res = create_file_info_from_attachment(client=client, attachment_id='dummy_attachment_id',
                                                         file_name=file_name)
        assert file_info_res.get('Type') == EntryType.ENTRY_INFO_FILE
        assert file_info_res.get('File', '') == file_name
        assert os.path.exists(f"{demisto.investigation()['id']}_{file_info_res.get('FileID', '')}")
        os.remove(f"{demisto.investigation()['id']}_{file_info_res.get('FileID', '')}")

    @pytest.mark.parametrize('get_attachments', [
        (True), (False)
    ])
    def test_download_issue_attachments_to_war_room(self, mocker, get_attachments):
        """
        Given:
            - A boolean on whether to download the attachments from Jira to the war room or not.
        When
            - Calling the function that is in charge of downloading the attachments to the war room.
        Then
            - Validate that a fileResult object was created
        """
        from JiraV3 import download_issue_attachments_to_war_room
        client = jira_base_client_mock()
        mocker.patch('JiraV3.create_file_info_from_attachment', return_value={'Contents': '', 'ContentsFormat': 'dummy_format',
                                                                              'Type': 'dummy_type', 'File': 'dummy_filename',
                                                                              'FileID': 'dummy_id'})
        demisto_results_mocker = mocker.patch.object(demisto, 'results')
        raw_issue_response = util_load_json('test_data/get_issue_test/raw_response.json')
        download_issue_attachments_to_war_room(client, issue=raw_issue_response, get_attachments=get_attachments)
        if get_attachments:
            demisto_results_mocker.assert_called_once()
        else:
            demisto_results_mocker.assert_not_called()

    def test_jira_get_issue(self, mocker):
        """
        Given:
            - An issue key or id, and the arguments: expand_links=true, fields=watches,rank
        When
            - Calling the get issue command
        Then
            - Validate that the context data and human readable are correct.
        """
        from JiraV3 import get_issue_command
        client = jira_base_client_mock()
        args = {'issue_key': 'dummy_key', 'get_attachments': 'true', 'expand_links': 'true',
                'fields': 'watches,rank'}
        raw_response = util_load_json('test_data/get_issue_test/raw_response.json')
        raw_response_extended_issues = util_load_json('test_data/get_issue_test/raw_response_extended_issues.json')
        expected_command_results_context = util_load_json('test_data/get_issue_test/parsed_result.json')
        mocker.patch.object(client, 'get_issue', return_value=raw_response)
        mocker.patch('JiraV3.get_expanded_issues', return_value=raw_response_extended_issues)
        mocker.patch('JiraV3.download_issue_attachments_to_war_room', return_value=None)
        command_results = get_issue_command(client, args)
        for expected_command_result_context, command_result in zip(expected_command_results_context, command_results):
            assert expected_command_result_context['EntryContext'] == command_result.to_context()['EntryContext']
            assert expected_command_result_context['HumanReadable'] == command_result.to_context()['HumanReadable']


class TestJiraGetCommentsCommand:
    def test_jira_get_comments(self, mocker):
        """
        Given:
            - An issue key or id.
        When
            - Calling the get comments command.
        Then
            - Validate that the context data and human readable are correct.
        """
        from JiraV3 import get_comments_command
        client = jira_base_client_mock()
        raw_response = util_load_json('test_data/get_comments_test/raw_response.json')
        expected_command_results_context = util_load_json('test_data/get_comments_test/parsed_result.json')
        mocker.patch.object(client, 'get_comments', return_value=raw_response)
        command_result = get_comments_command(client=client, args={'issue_key': 'dummy_issue_key'})
        assert expected_command_results_context['EntryContext'] == command_result.to_context()['EntryContext']
        assert expected_command_results_context['HumanReadable'] == command_result.to_context()['HumanReadable']

    def test_extract_comment_entry_from_raw_response(self):
        """
        Given:
            - A comment that has been returned from the Jira API.
        When
            - Extracting the comment entry from the raw response.
        Then
            - Validate that the comment entry includes the correct values.
        """
        from JiraV3 import extract_comment_entry_from_raw_response
        comment_raw_response = {
            "id": "18322",
            "author": {
                "displayName": "Tomer Malache",
            },
            "body": {
                "version": 1,
                "type": "doc",
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": "Hello there"
                            }
                        ]
                    }
                ]
            },
            "renderedBody": "<p>Hello there</p>",
            "updateAuthor": {
                "displayName": "Tomer Malache",
            },
            "created": "2023-03-23T07:45:29.056+0200",
            "updated": "2023-03-23T07:45:29.056+0200",
        }
        expected_comment_entry = {'Id': '18322', 'Comment': 'Hello there', 'User': 'Tomer Malache',
                                  'Created': '2023-03-23T07:45:29.056+0200', 'Updated': '2023-03-23T07:45:29.056+0200',
                                  'UpdateUser': 'Tomer Malache'}
        comment_entry = extract_comment_entry_from_raw_response(comment_response=comment_raw_response)
        assert comment_entry == expected_comment_entry


class TestJiraEditIssueCommand:
    def test_edit_issue_with_transition_and_status_error(self):
        """
        Given:
            - A Jira client, and arguments that hold the status and transition supplied by the user.
        When
            - Calling the edit issue command.
        Then
            - Validate that an error is returned since the user cannot supply both a status and transition.
        """
        from JiraV3 import edit_issue_command
        client = jira_base_client_mock()
        with pytest.raises(DemistoException) as e:
            edit_issue_command(client=client, args={'issue_id': '1',
                                                    'status': 'dummy_status', 'transition': 'dummy_transition'})
        assert 'Please provide only status or transition, but not both' in str(e)

    def test_edit_issue_command(self, mocker):
        """
        Given:
            - A Jira client, and arguments to edit a Jira issue (without status and transition arguments).
        When
            - Calling the edit issue command.
        Then
            - Validate that the edit_issue method was called, then get_issue was called to retrieve the newly
            updated issue, and that the updated issue's data was returned to context data.
        """
        from JiraV3 import (edit_issue_command, create_issue_md_and_outputs_dict)
        client = jira_base_client_mock()
        args = {'issue_key': 'dummy_key', 'due_date': '2024-05-07'}
        mocker.patch.object(client, 'edit_issue', return_value=requests.Response())
        dummy_issue_data = {'id': '1234',
                            'key': 'dummy_key',
                            'fields': {'duedate': '2024-05-07'}}
        mocker.patch.object(client, 'get_issue', return_value=dummy_issue_data)
        _, outputs = create_issue_md_and_outputs_dict(issue_data=dummy_issue_data)
        command_result = edit_issue_command(client=client, args=args)
        assert command_result.to_context().get('EntryContext') == {'Ticket(val.Id && val.Id == obj.Id)': outputs}

    @pytest.mark.parametrize('args', [
        ({'issue_key': 'dummy_key', 'status': 'Selected for development'}),
        ({'issue_key': 'dummy_key', 'transition': 'In Development'})
    ])
    def test_apply_issue_status_and_transition(self, mocker, args):
        """
        Given:
            - A Jira client, and the status, or transition argument to change the status of the issue.
        When
            - Calling the edit issue command.
        Then
            - Validate that get_transitions, and transition_issue method was called, which is in charge of changing the status
            of the issue.
        """
        from JiraV3 import edit_issue_command
        client = jira_base_client_mock()
        transitions_raw_response = util_load_json('test_data/get_transitions_test/raw_response.json')
        get_transitions_mocker = mocker.patch.object(client, 'get_transitions', return_value=transitions_raw_response)
        apply_transition_mocker = mocker.patch.object(client, 'transition_issue', return_value=requests.Response())
        mocker.patch.object(client, 'get_issue', return_value={})
        mocker.patch.object(client, 'edit_issue', return_value=requests.Response())
        edit_issue_command(client=client, args=args)
        get_transitions_mocker.assert_called_once()
        apply_transition_mocker.assert_called_once()

    def test_create_issue_fields_with_action_rewrite(self, mocker):
        """
        Given:
            - A Jira client, and issue fields to edit the Jira issue, with the rewrite action.
        When
            - Calling the edit issue command.
        Then
            - Validate that the edit_issue method (which is in charge of calling the endpoint with the relevant data
            to edit the issue) was called with the correct json data.
        """
        from JiraV3 import edit_issue_command
        client = jira_base_client_mock()
        args = {'issue_key': 'dummy_key', 'description': 'dummy description', 'project_key': 'dummy_project_key',
                'project_id': 'dummy_project_id',
                'labels': 'label1,label2', 'components': 'comp1,comp2',
                'customfield_1': 'dummy custom field'}
        expected_issue_fields = {'fields': {'description': 'dummy description', 'project':
                                            {'key': 'dummy_project_key', 'id':
                                             'dummy_project_id'}, 'labels': ['label1', 'label2'],
                                            'components': [{'name': 'comp1'}, {'name': 'comp2'}],
                                            'customfield_1': 'dummy custom field'}}
        mocker.patch.object(client, 'get_issue', return_value={})
        edit_issue_mocker = mocker.patch.object(client, 'edit_issue', return_value=requests.Response())
        edit_issue_command(client=client, args=args)
        assert expected_issue_fields == edit_issue_mocker.call_args[1].get('json_data')

    def test_create_issue_fields_for_update_with_action_append(self, mocker):
        """
        Given:
            - A Jira client, and issue fields to edit the Jira issue, with the append action.
        When
            - Calling the edit issue command.
        Then
            - Validate that the edit_issue method (which is in charge of calling the endpoint with the relevant data
            to edit the issue) was called with the correct json data.
        """
        from JiraV3 import edit_issue_command
        client = jira_base_client_mock()
        args = {'issue_key': 'dummy_key', 'description': 'dummy description', 'project_key': 'dummy_project_key',
                'project_id': 'dummy_project_id',
                'labels': 'label1,label2', 'components': 'comp1,comp2',
                'customfield_1': 'dummy custom field', 'action': 'append'}
        expected_issue_fields = {'update': {'labels': [{'add': 'label1'}, {'add': 'label2'}], 'components': [
            {'add': {'name': 'comp1'}}, {'add': {'name': 'comp2'}}]}}
        mocker.patch.object(client, 'get_issue', return_value={})
        edit_issue_mocker = mocker.patch.object(client, 'edit_issue', return_value=requests.Response())
        edit_issue_command(client=client, args=args)
        assert expected_issue_fields == edit_issue_mocker.call_args[1].get('json_data')


class TestJiraCreateIssueCommand:
    def test_create_issue_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the create issue command.
        Then
            - Validate that the issue id and key of the newly created issue is returned.
        """
        from JiraV3 import create_issue_command
        client = jira_base_client_mock()
        raw_response = {'id': "1234", 'key': 'dummy_key',
                        'self': 'dummy_link'}
        expected_outputs = {'Id': '1234', 'Key': 'dummy_key'}
        mocker.patch.object(client, 'create_issue', return_value=raw_response)
        command_result = create_issue_command(client=client, args={})
        assert command_result.to_context().get('EntryContext') == {'Ticket(val.Id && val.Id == obj.Id)': expected_outputs}


class TestJiraDeleteIssueCommand:
    def test_delete_issue_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the delete issue command.
        Then
            - Validate that the correct readable output is outputted to the user.
        """
        from JiraV3 import delete_issue_command
        client = jira_base_client_mock()
        mocker.patch.object(client, 'delete_issue', return_value=requests.Response())
        command_result = delete_issue_command(client=client, args={'issue_key': 'dummy_key'})
        assert 'Issue deleted successfully' in command_result.to_context().get('HumanReadable')


class TestJiraGetTransitionsCommand:
    def test_get_transitions_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the get_transitions_command
        Then
            - Validate that the correct CommandResult object is returned to the user.
        """
        from JiraV3 import get_transitions_command
        client = jira_base_client_mock()
        raw_response = util_load_json('test_data/get_transitions_test/raw_response.json')
        expected_command_results_context = util_load_json('test_data/get_transitions_test/parsed_result.json')
        mocker.patch.object(client, 'get_transitions', return_value=raw_response)
        command_result = get_transitions_command(client=client, args={'issue_key': 'dummy_key'})
        assert expected_command_results_context['EntryContext'] == command_result.to_context()['EntryContext']
        assert expected_command_results_context['HumanReadable'] == command_result.to_context()['HumanReadable']


class TestJiraAddCommentCommand:
    def test_add_comment_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the add_comment_command
        Then
            - Validate that the correct CommandResult object is returned to the user.
        """
        from JiraV3 import add_comment_command
        client = jira_base_client_mock()
        args = {'visibility': 'Administrators', 'issue_key': 'dummy_key', 'comment': 'dummy_comment'}
        raw_response = util_load_json('test_data/create_comment_test/raw_response.json')
        expected_command_results_context = util_load_json('test_data/create_comment_test/parsed_result.json')
        mocker.patch.object(client, 'add_comment', return_value=raw_response)
        command_result = add_comment_command(client=client, args=args)
        assert expected_command_results_context['EntryContext'] == command_result.to_context()['EntryContext']
        assert expected_command_results_context['HumanReadable'] == command_result.to_context()['HumanReadable']


class TestJiraGetIDOffsetCommand:
    def test_get_id_offset_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the get_id_offset_command, in order to retrieve the first issue id in the Jira instance.
        Then
            - Validate that the correct CommandResult object is returned to the user, and that the correct JQL
            was sent to in order to retrieve the ID.
        """
        from JiraV3 import get_id_offset_command
        client = jira_base_client_mock()
        raw_response = util_load_json('test_data/issue_query_test/raw_response.json')
        run_query_mocker = mocker.patch.object(client, 'run_query', return_value=raw_response)
        command_result = get_id_offset_command(client=client, args={})
        assert 'ORDER BY created ASC' == run_query_mocker.call_args[1].get('query_params', {}).get('jql')
        assert {'Ticket': {'idOffSet': '10161'}} == command_result.to_context()['EntryContext']


class TestJiraEditCommentCommand:
    def test_get_id_offset_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the edit_comment_command.
        Then
            - Validate that the get_comments method is called to retrieve the comments of the issue, that includes the
            newly edited comment, and that the correct outputs is returned to the context data.
        """
        from JiraV3 import edit_comment_command
        client = jira_base_client_mock()
        comments_raw_response = util_load_json('test_data/get_comments_test/raw_response.json')
        expected_command_results_context = util_load_json('test_data/get_comments_test/parsed_result.json')
        mocker.patch.object(client, 'edit_comment', return_value=requests.Response())
        get_comments_mocker = mocker.patch.object(client, 'get_comments', return_value=comments_raw_response)
        command_result = edit_comment_command(client=client, args={'issue_key': 'dummy_issue_key'})
        get_comments_mocker.assert_called_once()
        assert expected_command_results_context['EntryContext'] == command_result.to_context()['EntryContext']


class TestJiraListIssueFieldsCommand:
    @pytest.mark.parametrize('pagination_args', [
        ({'start_at': 0, 'max_results': 2}), ({'start_at': 1, 'max_results': 3})
    ])
    def test_get_id_offset_command(self, mocker, pagination_args):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-issue-list-fields command.
        Then
            - Validate that correct pagination has been applied, since the API endpoint does not support pagination,
            and we do it manually.
        """
        from JiraV3 import list_fields_command
        client = jira_base_client_mock()
        issue_fields_raw_response = util_load_json('test_data/get_issue_fields_test/raw_response.json')
        expected_context = util_load_json('test_data/get_issue_fields_test/parsed_result.json')
        start_at = pagination_args.get('start_at', 0)
        max_results = pagination_args.get('max_results', 50)
        mocker.patch.object(client, 'get_issue_fields', return_value=issue_fields_raw_response)
        mocker.patch('JiraV3.prepare_pagination_args', return_value=pagination_args)
        command_result = list_fields_command(client=client, args={'issue_key': 'dummy_issue_key'})
        # [start_at: start_at + max_results] is the way do the pagination manually, therefore we check it.
        expected_outputs = expected_context['EntryContext']['Jira.IssueField(val.id && val.id == obj.id)'][start_at: start_at
                                                                                                           + max_results]
        assert expected_outputs == command_result.to_context()['EntryContext']['Jira.IssueField(val.id && val.id == obj.id)']


class TestJiraIssueToBacklogCommand:
    @pytest.mark.parametrize('args', [
        ({'rank_before_issue': 'key1', 'issues': 'issue1,issue2'}), ({'rank_after_issue': 'key1', 'issues': 'issue1,issue2'})
    ])
    def test_using_rank_without_board_id_error(self, args):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-issue-to-backlog command, with the rank_before_issue, or rank_after_issue arguments, without
            the board_id argument.
        Then
            - Validate that an error is thrown.
        """
        from JiraV3 import issues_to_backlog_command
        client = jira_base_client_mock()
        with pytest.raises(DemistoException) as e:
            issues_to_backlog_command(client=client, args=args)
        assert 'Please supply the board_id argument' in str(e)

    def test_issues_to_backlog_is_called_when_using_board_id(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-issue-to-backlog command, with the board_id argument.
        Then
            - Validate that the correct API call is being called (issues_to_backlog, which is available only for Jira Cloud).
        """
        from JiraV3 import issues_to_backlog_command
        client = jira_cloud_client_mock()
        issues_to_backlog_mocker = mocker.patch.object(client, 'issues_to_backlog', return_value=requests.Response())
        issues_to_backlog_command(client=client, args={'board_id': 'dummy_board_id'})
        issues_to_backlog_mocker.assert_called_once()

    def test_using_board_id_with_onprem_error(self):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-issue-to-backlog command, with the board_id argument, on an OnPrem instance.
        Then
            - Validate that an error is thrown, since only Jira Cloud supports the board_id argument.
        """
        from JiraV3 import issues_to_backlog_command
        client = jira_onprem_client_mock()
        with pytest.raises(DemistoException) as e:
            issues_to_backlog_command(client=client, args={'board_id': 'dummy_board_id'})
        assert 'The argument board_id is not supported for a Jira OnPrem instance' in str(e)

    def test_issues_to_backlog_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-issue-to-backlog command.
        Then
            - Validate that the correct API call is being called.
        """
        from JiraV3 import issues_to_backlog_command
        client = jira_base_client_mock()
        issues_from_sprint_to_backlog_mocker = mocker.patch.object(
            client, 'issues_from_sprint_to_backlog', return_value=requests.Response())
        command_results = issues_to_backlog_command(client=client, args={})
        issues_from_sprint_to_backlog_mocker.assert_called_once()
        assert command_results.to_context()['HumanReadable'] == 'Issues were moved to Backlog successfully'


class TestJiraIssuesToBoardCommand:
    def test_issues_to_board_with_onprem_error(self):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-issue-to-board command, with an OnPrem instance.
        Then
            - Validate that an error is thrown, since this command is only supported by Jira Cloud.
        """
        from JiraV3 import issues_to_board_command
        client = jira_onprem_client_mock()
        with pytest.raises(DemistoException) as e:
            issues_to_board_command(client=client, args={})
        assert 'This command is not supported by a Jira OnPrem instance' in str(e)

    def test_issues_to_board_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-issue-to-board command, with a Cloud instance.
        Then
            - Validate that the correct CommandResults is returned to the user.
        """
        from JiraV3 import issues_to_board_command
        client = jira_cloud_client_mock()
        mocker.patch.object(client, 'issues_to_board', return_value=requests.Response())
        command_results = issues_to_board_command(client=client, args={})
        assert command_results.to_context()['HumanReadable'] == 'Issues were moved to Board successfully'


class TestJiraBoardListCommand:
    def test_get_board_using_board_id_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-board-list command, with the board_id argument.
        Then
            - Validate that the correct API call is called to retrieve the specific data corresponding to the board id.
        """
        from JiraV3 import board_list_command
        client = jira_base_client_mock()
        board_raw_response = util_load_json('test_data/get_board_test/raw_response.json')
        expected_command_results = util_load_json('test_data/get_board_test/parsed_result.json')
        get_board_mocker = mocker.patch.object(client, 'get_board', return_value=board_raw_response)
        get_boards_mocker = mocker.patch.object(client, 'get_boards', return_value={})
        command_results = board_list_command(client=client, args={'board_id': 'dummy_board_id'})
        get_board_mocker.assert_called_once()
        get_boards_mocker.assert_not_called()
        assert expected_command_results['EntryContext'] == command_results.to_context()['EntryContext']

    def test_get_boards_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-board-list command, without the board_id argument.
        Then
            - Validate that the correct API call is called to retrieve the specific data.
        """
        from JiraV3 import board_list_command
        client = jira_base_client_mock()
        board_raw_response = util_load_json('test_data/get_boards_test/raw_response.json')
        expected_command_results = util_load_json('test_data/get_boards_test/parsed_result.json')
        get_board_mocker = mocker.patch.object(client, 'get_board', return_value={})
        get_boards_mocker = mocker.patch.object(client, 'get_boards', return_value=board_raw_response)
        command_results = board_list_command(client=client, args={})
        get_board_mocker.assert_not_called()
        get_boards_mocker.assert_called_once()
        assert expected_command_results['EntryContext'] == command_results.to_context()['EntryContext']


class TestJiraIssuesFromBacklogOfBoardCommand:
    def test_get_issues_from_backlog_of_board_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-board-backlog-list command.
        Then
            - Validate that the correct context data is returned to the user.
        """
        from JiraV3 import board_backlog_list_command
        client = jira_base_client_mock()
        backlog_issues_raw_response = util_load_json('test_data/get_issues_from_backlog_test/raw_response.json')
        expected_command_results = util_load_json('test_data/get_issues_from_backlog_test/parsed_result.json')
        mocker.patch.object(client, 'get_issues_from_backlog', return_value=backlog_issues_raw_response)
        command_results = board_backlog_list_command(client=client, args={'board_id': '14'})
        assert expected_command_results['EntryContext'] == command_results.to_context()['EntryContext']


class TestJiraIssuesFromBoardCommand:
    def test_get_issues_from_board_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-board-issue-list command.
        Then
            - Validate that the correct context data is returned to the user.
        """
        from JiraV3 import board_issues_list_command
        client = jira_base_client_mock()
        board_issues_raw_response = util_load_json('test_data/get_issues_from_board_test/raw_response.json')
        expected_command_results = util_load_json('test_data/get_issues_from_board_test/parsed_result.json')
        mocker.patch.object(client, 'get_issues_from_board', return_value=board_issues_raw_response)
        command_results = board_issues_list_command(client=client, args={'board_id': '14'})
        assert expected_command_results['EntryContext'] == command_results.to_context()['EntryContext']


class TestJiraBoarSprintsCommand:
    def test_get_issues_from_board_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-board-sprint-list command.
        Then
            - Validate that the correct context data is returned to the user.
        """
        from JiraV3 import board_sprint_list_command
        client = jira_base_client_mock()
        board_sprints_raw_response = util_load_json('test_data/get_board_sprints_test/raw_response.json')
        expected_command_results = util_load_json('test_data/get_board_sprints_test/parsed_result.json')
        mocker.patch.object(client, 'get_sprints_from_board', return_value=board_sprints_raw_response)
        command_results = board_sprint_list_command(client=client, args={'board_id': '12'})
        assert expected_command_results['EntryContext'] == command_results.to_context()['EntryContext']


class TestJiraIssueLinkTypesCommand:
    def test_get_issue_link_types_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-issue-link-type-get command.
        Then
            - Validate that the correct context data is returned to the user.
        """
        from JiraV3 import get_issue_link_types_command
        client = jira_base_client_mock()
        link_types_raw_response = util_load_json('test_data/get_issue_link_types_test/raw_response.json')
        expected_command_results = util_load_json('test_data/get_issue_link_types_test/parsed_result.json')
        mocker.patch.object(client, 'get_issue_link_types', return_value=link_types_raw_response)
        command_results = get_issue_link_types_command(client=client, args={})
        assert expected_command_results['EntryContext'] == command_results.to_context()['EntryContext']


class TestJiraIssueToIssueCommand:
    def test_issue_to_issue_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-issue-to-issue-link command.
        Then
            - Validate that the correct message is returned to the user.
        """
        from JiraV3 import link_issue_to_issue_command
        client = jira_base_client_mock()
        mocker.patch.object(client, 'create_issue_link', return_value=requests.Response())
        command_results = link_issue_to_issue_command(client=client, args={})
        assert 'Issue link created successfully' == command_results.to_context()['HumanReadable']


class TestJiraSprintIssueMoveCommand:
    def test_jira_sprint_issue_move(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-sprint-issue-move command.
        Then
            - Validate that the correct message is returned to the user.
        """
        from JiraV3 import issues_to_sprint_command
        client = jira_base_client_mock()
        mocker.patch.object(client, 'issues_to_sprint', return_value=requests.Response())
        command_results = issues_to_sprint_command(client=client, args={})
        assert 'Issues were moved to the Sprint successfully' == command_results.to_context()['HumanReadable']


class TestJiraEpicIssuesCommand:
    def test_get_epic_issues_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-epic-issue-list command.
        Then
            - Validate that the correct context data is returned to the user.
        """
        from JiraV3 import epic_issues_list_command
        client = jira_base_client_mock()
        epic_issues_raw_response = util_load_json('test_data/get_epic_issues_test/raw_response.json')
        expected_command_results = util_load_json('test_data/get_epic_issues_test/parsed_result.json')
        mocker.patch.object(client, 'get_epic_issues', return_value=epic_issues_raw_response)
        command_results = epic_issues_list_command(client=client, args={'epic_key': 'TSTPRD-1'})
        assert expected_command_results['EntryContext'] == command_results.to_context()['EntryContext']

    def test_get_epic_issues_without_extracting_epic_id_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-epic-issue-list command, and not being able
            to extract the board_id from the response.
        Then
            - Validate that the context data is identified only using the epic id, without the board id.
        """
        from JiraV3 import epic_issues_list_command
        client = jira_base_client_mock()
        epic_issues_raw_response = util_load_json('test_data/get_epic_issues_test/raw_response.json')
        mocker.patch.object(client, 'get_epic_issues', return_value=epic_issues_raw_response)
        for issue in epic_issues_raw_response.get('issues', []):
            (issue.get('fields', {}).get('sprint', {}) or {})['originBoardId'] = ''
        command_results = epic_issues_list_command(client=client, args={'epic_key': 'COMPANYSA-1'})
        entry_context = command_results.to_context()['EntryContext']
        assert 'Jira.EpicIssues(val.epicId && val.epicId == obj.epicId)' in entry_context
        assert ('Jira.EpicIssues(val.epicId && val.epicId == obj.epicId && val.boardId && val.'
                'boardId == obj.boardId)') not in entry_context


class TestJiraBoardEpicsCommand:
    def test_get_board_epics_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-board-epic-list command.
        Then
            - Validate that the correct context data is returned to the user.
        """
        from JiraV3 import board_epic_list_command
        client = jira_base_client_mock()
        board_epics_raw_response = util_load_json('test_data/get_board_epics_test/raw_response.json')
        expected_command_results = util_load_json('test_data/get_board_epics_test/parsed_result.json')
        mocker.patch.object(client, 'get_epics_from_board', return_value=board_epics_raw_response)
        command_results = board_epic_list_command(client=client, args={'board_id': '14'})
        assert expected_command_results['EntryContext'] == command_results.to_context()['EntryContext']


class TestJiraSprintIssuesCommand:
    def test_get_sprint_issues_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-sprint-issue-list command, without the board_id argument.
        Then
            - Validate that the correct API call was called to retrieve the sprint issues, which is the API
            call that does not require a board_id, only a sprint_id argument, and that correct context data
            is returned to the user.
        """
        from JiraV3 import sprint_issues_list_command
        client = jira_base_client_mock()
        sprint_issues_raw_response = util_load_json('test_data/get_sprint_issues_test/raw_response.json')
        expected_command_results = util_load_json('test_data/get_sprint_issues_test/parsed_result.json')
        issues_from_sprint_mocker = mocker.patch.object(client, 'get_issues_from_sprint', return_value=sprint_issues_raw_response)
        sprint_issues_from_board_mocker = mocker.patch.object(client,
                                                              'get_sprint_issues_from_board',
                                                              return_value=sprint_issues_raw_response)
        command_results = sprint_issues_list_command(client=client, args={'sprint_id': '4'})
        issues_from_sprint_mocker.assert_called_once()
        sprint_issues_from_board_mocker.assert_not_called()
        assert expected_command_results['EntryContext'] == command_results.to_context()['EntryContext']

    def test_get_sprint_issues_from_board_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the jira-sprint-issue-list command, with the board_id argument.
        Then
            - Validate that the correct API call was called to retrieve the sprint issues, which is the API
            call that does require a board_id, in addition to a sprint_id argument, and that correct context data
            is returned to the user.
        """
        from JiraV3 import sprint_issues_list_command
        client = jira_base_client_mock()
        sprint_issues_raw_response = util_load_json('test_data/get_sprint_issues_test/raw_response.json')
        expected_command_results = util_load_json('test_data/get_sprint_issues_test/parsed_result.json')
        issues_from_sprint_mocker = mocker.patch.object(client, 'get_issues_from_sprint', return_value=sprint_issues_raw_response)
        sprint_issues_from_board_mocker = mocker.patch.object(client,
                                                              'get_sprint_issues_from_board',
                                                              return_value=sprint_issues_raw_response)
        command_results = sprint_issues_list_command(client=client, args={'board_id': '12', 'sprint_id': '4'})
        issues_from_sprint_mocker.assert_not_called()
        sprint_issues_from_board_mocker.assert_called_once()
        assert expected_command_results['EntryContext'] == command_results.to_context()['EntryContext']

    def test_get_sprint_issues_without_extracting_board_id(self, mocker):
        """
        Given:
            - A Jira client.
        When
            - Calling the jira-sprint-issue-list command, without the board_id argument, and not being able
            to extract the board_id from the response.
        Then
            - Validate that the context data is identified only using the sprint id, without the board id.
        """
        from JiraV3 import sprint_issues_list_command
        client = jira_base_client_mock()
        sprint_issues_raw_response: Dict[str, Any] = util_load_json('test_data/get_sprint_issues_test/raw_response.json')
        issues_from_sprint_mocker = mocker.patch.object(client, 'get_issues_from_sprint', return_value=sprint_issues_raw_response)
        sprint_issues_from_board_mocker = mocker.patch.object(client,
                                                              'get_sprint_issues_from_board',
                                                              return_value=sprint_issues_raw_response)
        for issue in sprint_issues_raw_response.get('issues', []):
            (issue.get('fields', {}).get('sprint', {}) or {})['originBoardId'] = ''
        command_results = sprint_issues_list_command(client=client, args={'sprint_id': '4'})
        issues_from_sprint_mocker.assert_called_once()
        sprint_issues_from_board_mocker.assert_not_called()
        entry_context = command_results.to_context()['EntryContext']
        assert 'Jira.SprintIssues(val.sprintId && val.sprintId == obj.sprintId)' in entry_context
        assert ('Jira.SprintIssues(val.boardId && val.boardId == obj.boardId && val.sprintId && val.'
                'sprintId == obj.sprintId)') not in entry_context


class TestJiraDeleteCommentCommand:
    """
    Given:
        - A Jira client.
    When
        - Calling the jira-issue-delete-comment.
    Then
        - Validate that the correct message is returned to the user.
    """

    def test_delete_comment_command(self, mocker):
        from JiraV3 import delete_comment_command
        client = jira_base_client_mock()
        mocker.patch.object(client, 'delete_comment', return_value=requests.Response())
        command_results = delete_comment_command(client=client, args={'issue_key': 'dummy_issue_key'})
        assert 'Comment deleted successfully' in command_results.to_context()['HumanReadable']
