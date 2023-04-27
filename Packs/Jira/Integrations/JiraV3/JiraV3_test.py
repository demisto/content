import io
import json
import pytest
import demistomock as demisto
from unittest.mock import patch
from JiraV3 import JiraBaseClient
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
        {'jql': 'some_jql_string', 'startAt': 0, 'maxResults': 50, 'expand': 'renderedFields,transitions,names'},
    ),
    (
        'some_jql_string', 12, None,
        {'jql': 'some_jql_string', 'startAt': 12, 'maxResults': 50, 'expand': 'renderedFields,transitions,names'},
    ),
    (
        'some_jql_string', 1, 80,
        {'jql': 'some_jql_string', 'startAt': 1, 'maxResults': 80, 'expand': 'renderedFields,transitions,names'},
    )
]


@pytest.mark.parametrize('jql, start_at, max_results, expected_query_params', CREATE_ISSUE_QUERY_CASES)
def test_create_query_params(jql, start_at, max_results, expected_query_params):
    from JiraV3 import create_query_params
    query_params = create_query_params(jql_query=jql, start_at=start_at, max_results=max_results)
    assert query_params == expected_query_params


FIELDS_MAPPER_CASES = [
    (
        {'summary': ['dummy_summary_1', 'dummy_summary_2'], 'first_nested_key': 'first', 'second_nested_key': 'second',
         'third_nested_key': {'value': 'third'}},
        {'summary': 'fields.summary', 'first_nested_key': 'parent_key.first_child_key.first_value',
         'second_nested_key': 'parent_key.second_child_key.second_value',
         'third_nested_key': 'parent_key.second_child_key.third_value'},

        {'fields': {'summary': ['dummy_summary_1', 'dummy_summary_2']},
         'parent_key': {'first_child_key': {'first_value': 'first'},
                        'second_child_key': {'second_value': 'second',
                                             'third_value': {'value': 'third'}
                                             }
                        }
         }
    )
]


@pytest.mark.parametrize('issue_args, issue_fields_mapper, expected_issue_fields_mapper', FIELDS_MAPPER_CASES)
def test_create_issue_fields(issue_args, issue_fields_mapper, expected_issue_fields_mapper):
    from JiraV3 import create_issue_fields
    issue_fields = create_issue_fields(issue_args=issue_args, issue_fields_mapper=issue_fields_mapper)
    assert issue_fields == expected_issue_fields_mapper


UPDATE_MAPPER_CASES = [
    (
        {'summary': ['dummy_summary_1', 'dummy_summary_2'], 'first_nested_key': 'first', 'second_nested_key': 'second',
         'third_nested_key': {'value': 'third'}, 'fourth_nested_key': {'value': 'fourth'}},
        {'summary': ('fields.summary', ''), 'first_nested_key': ('parent_key.first_child_key.first_value', ''),
         'second_nested_key': ('parent_key.second_child_key.second_value', ''),
         'third_nested_key': ('parent_key.second_child_key.third_value', 'name'),
         'fourth_nested_key': ('parent_key.second_child_key.third_value', 'id')},
        'rewrite',
        {'fields': {'summary': [{'set': ['dummy_summary_1', 'dummy_summary_2']}]},
         'parent_key': {'first_child_key': {'first_value': [{'set': 'first'}]},
                        'second_child_key': {'second_value': [{'set': 'second'}],
                                             'third_value': [{'set': {'id': {'value': 'fourth'}}},
                                                             {'set': {'name': {'value': 'third'}}}]
                                             }
                        }
         }
    )
]


@pytest.mark.parametrize('issue_args, issue_update_mapper, action, expected_issue_update_mapper', UPDATE_MAPPER_CASES)
def test_create_issue_update(issue_args, issue_update_mapper, action, expected_issue_update_mapper):
    from JiraV3 import get_issue_fields_for_update
    issue_update_mapper = get_issue_fields_for_update(
        issue_args=issue_args, issue_update_mapper=issue_update_mapper, action=action)
    assert expected_issue_update_mapper == issue_update_mapper


TO_MD_AND_OUTPUTS_CASES = [
    (
        {'id': 'dummy_id', 'key': 'dummy_key',
         'fields': {'summary': 'dummy_summary', 'status': {'name': 'dummy_status_name'}, 'project': {'name': 'dummy_project'}},
         'properties': {'name': 'admin'}
         },
        {'Id': ('id', ''), 'Key': ('key', ''), 'Summary': ('fields.summary', ''), 'Status': ('fields.status.name', ''),
         'Properties': ('properties.name', ''), 'PropertiesId': ('properties.id', None)},
        {'ProjectName': ('fields.project.name', '')},
        {'Labels': ('fields.labels', [])},
        (
            {'Id': 'dummy_id', 'Key': 'dummy_key', 'Summary': 'dummy_summary', 'Status': 'dummy_status_name',
             'Properties': 'admin', 'PropertiesId': None, 'ProjectName': 'dummy_project'},
            {'Id': 'dummy_id', 'Key': 'dummy_key', 'Summary': 'dummy_summary', 'Status': 'dummy_status_name',
                'Properties': 'admin', 'PropertiesId': None, 'Labels': []}
        )
    )
]


@pytest.mark.parametrize('data, shared_fields, hr_fields, outputs_fields, expected_md_outputs_dicts', TO_MD_AND_OUTPUTS_CASES)
def test_response_to_md_and_outputs(data, shared_fields, hr_fields, outputs_fields, expected_md_outputs_dicts):
    from JiraV3 import response_to_md_and_outputs
    markdown_dict, outputs = response_to_md_and_outputs(data=data, shared_fields=shared_fields,
                                                        hr_fields=hr_fields, outputs_fields=outputs_fields)
    expected_markdown_dict, expected_outputs = expected_md_outputs_dicts
    assert expected_markdown_dict == markdown_dict
    assert expected_outputs == outputs


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

BOARD_EPICS_LIST_CASES = [
    ('test_data/raw_responses/board_epics/board_epic_list.json', 'test_data/parsed_responses/board_epics/board_epic_list.json'),
    ('test_data/raw_responses/board_epics/board_epic_list_empty.json',
     'test_data/parsed_responses/board_epics/board_epic_list_empty.json')
]


@pytest.mark.parametrize('raw_response_file, expected_parsed_response_file', BOARD_EPICS_LIST_CASES)
def test_jira_board_epic_list(mocker, raw_response_file, expected_parsed_response_file):
    """Check that the jira-board-epic-list parses the raw results correctly
    """
    from JiraV3 import board_epic_list_command
    raw_response = util_load_json(raw_response_file)
    expected_parsed_response = util_load_json(expected_parsed_response_file)
    client = jira_base_client_mock()
    mocker.patch.object(client, 'get_epics_from_board', return_value=raw_response)
    parsed_response = board_epic_list_command(client=client, args={'board_id': '14'})
    assert parsed_response.to_context() == expected_parsed_response


SPRINT_ISSUES_LIST_CASES = [
    ('test_data/raw_responses/sprint_issues/sprint_issues_list.json',
     'test_data/parsed_responses/sprint_issues/sprint_issues_list.json'),
    ('test_data/raw_responses/sprint_issues/sprint_issues_list_empty.json',
     'test_data/parsed_responses/sprint_issues/sprint_issues_list_empty.json')
]


@pytest.mark.parametrize('raw_response_file, expected_parsed_response_file', SPRINT_ISSUES_LIST_CASES)
def test_jira_sprint_issue_list(mocker, raw_response_file, expected_parsed_response_file):
    """Check that the jira-sprint-issue-list parses the raw results correctly
    """
    from JiraV3 import sprint_issues_list_command
    raw_response = util_load_json(raw_response_file)
    expected_parsed_response = util_load_json(expected_parsed_response_file)
    client = jira_base_client_mock()
    mocker.patch.object(client, 'get_issues_from_sprint', return_value=raw_response)
    mocker.patch.object(client, 'get_sprint_issues_from_board', return_value=raw_response)
    parsed_response = sprint_issues_list_command(client=client, args={'sprint_id': '4'})
    assert parsed_response.to_context() == expected_parsed_response


def test_jira_sprint_issue_move(mocker):
    """Check that the jira-sprint-issue-move returns the correct CommandResults when no error is thrown
    """
    from JiraV3 import issues_to_sprint_command, requests, CommandResults
    client = jira_base_client_mock()
    mocker.patch.object(client, 'issues_to_sprint', return_value=requests.Response())
    expected_command_result = CommandResults(readable_output='Issues were moved to the Sprint successfully')
    assert expected_command_result.to_context() == issues_to_sprint_command(client=client, args={}).to_context()


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

    def test_apply_issue_status(self, mocker):
        ...

    def test_apply_issue_transition(self, mocker):
        ...

    def test_create_issue_fields(self, mocker):
        ...

    def test_create_issue_fields_for_update(self, mocker):
        ...
