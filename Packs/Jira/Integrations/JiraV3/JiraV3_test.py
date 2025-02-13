import json
import pytest
from pytest_mock import MockerFixture
import demistomock as demisto
from unittest.mock import patch
from JiraV3 import (JiraBaseClient, JiraCloudClient, JiraOnPremClient)
from CommonServerPython import *


def util_load_json(path: str):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def util_load_bytes_file(path: str):
    with open(path, mode='rb') as f:
        return f.read()
        # return json.loads(f.read())


@patch.object(JiraBaseClient, '__abstractmethods__', set())
def jira_base_client_mock(username: str = "", api_key: str = "") -> JiraBaseClient:
    """The way to mock an abstract class is using the trick @patch.object(Abstract_Class, __abstractmethods__, set()),
    since Python, behind the scenes, checks the __abstractmethods__ property, which contains a set of the names of all
    the abstract methods defined on the abstract class, if it is not empty, we won't be able to instantiate the abstract class,
    however, if this set is empty, the Python interpreter will happily instantiate our class without any problems.
    """
    return JiraBaseClient(base_url='dummy_url', proxy=False, verify=False, callback_url='dummy_callback',
                          api_version='999', username=username, api_key=api_key)


def jira_cloud_client_mock() -> JiraCloudClient:
    return JiraCloudClient(proxy=False, verify=False, client_id='dummy_client_id',
                           client_secret='dummy_secret', callback_url='dummy_url', cloud_id='dummy_cloud_id',
                           server_url='dummy_server_url', username="", api_key="")


def jira_onprem_client_mock() -> JiraOnPremClient:
    return JiraOnPremClient(proxy=False, verify=False, client_id='dummy_client_id',
                            client_secret='dummy_secret', callback_url='dummy_url',
                            server_url='dummy_server_url', username="", api_key="")


def test_v2_args_to_v3():
    from JiraV3 import map_v2_args_to_v3
    v2_args = {
        'startAt': 'dummy_start_at',
        'maxResults': 'dummy_max_results',
        'extraFields': 'dummy_fields',
        'getAttachments': 'dummy_get_attachments',
        'expandLinks': 'dummy_expand_links',
        'expand_links': 'not prioritized',
        'issueJson': 'dummy_issue_json',
        'projectKey': 'dummy_project_key',
        'issueTypeName': 'dummy_issue_type_name',
        'issueTypeId': 'dummy_issue_type_id',
        'projectName': 'dummy_project_name',
        'dueDate': 'dummy_due_date',
        'due_date': 'not prioritized',
        'parentIssueKey': 'dummy_parent_issue_key',
        'parentIssueId': 'dummy_parent_issue_id',
        'attachmentName': 'dummy_attachment_name',
        'globalId': 'dummy_global_id',
        'applicationType': 'dummy_application_type',
        'applicationName': 'dummy_application_name',
        'issueId': '1234',
        'issueIdOrKey': 'dummy_issue_key'
    }
    expected_v3_args = {
        'start_at': 'dummy_start_at',
        'max_results': 'dummy_max_results',
        'fields': 'dummy_fields',
        'get_attachments': 'dummy_get_attachments',
        'expand_links': 'dummy_expand_links',
        'issue_json': 'dummy_issue_json',
        'project_key': 'dummy_project_key',
        'issue_type_name': 'dummy_issue_type_name',
        'issue_type_id': 'dummy_issue_type_id',
        'project_name': 'dummy_project_name',
        'due_date': 'dummy_due_date',
        'parent_issue_key': 'dummy_parent_issue_key',
        'parent_issue_id': 'dummy_parent_issue_id',
        'attachment_name': 'dummy_attachment_name',
        'global_id': 'dummy_global_id',
        'application_type': 'dummy_application_type',
        'application_name': 'dummy_application_name',
        'issue_id': '1234',
        'issue_key': 'dummy_issue_key'
    }
    v3_args = map_v2_args_to_v3(args=v2_args)
    assert v3_args == expected_v3_args


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


@pytest.mark.parametrize('issue_id, issue_key', [('1234', 'key1'), ('', '')])
def test_get_issue_id_or_key_error(issue_id, issue_key):
    from JiraV3 import get_issue_id_or_key
    with pytest.raises(DemistoException):
        get_issue_id_or_key(issue_id, issue_key)


@pytest.mark.parametrize('issue_id, issue_key, expected_issue_id_or_key',
                         [('1234', '', '1234'), ('', 'key-1', 'key-1')])
def test_get_issue_id_or_key(issue_id, issue_key, expected_issue_id_or_key):
    from JiraV3 import get_issue_id_or_key
    issue_id_or_key = get_issue_id_or_key(issue_id, issue_key)
    assert issue_id_or_key == expected_issue_id_or_key


@pytest.mark.parametrize(
    "username, api_key",
    [
        (
            "dummy_username",
            "dummy_api_key",
        ),
        ("", ""),
    ],
)
def test_http_request(mocker, username: str, api_key: str):
    """
    Given:
        - username and api_key
    When:
        - run http_request method
    Then:
        - Ensure when the username and api_key are provided then only the 'get_headers_with_basic_auth' method is called
        - Ensure when the username and api_key are not provided then only the 'get_headers_with_access_token' method is called
    """
    client = jira_base_client_mock(username=username, api_key=api_key)

    basic_auth_mock = mocker.patch.object(
        client, "get_headers_with_basic_auth", return_value={}
    )
    oauth2_mock = mocker.patch.object(
        client, "get_headers_with_access_token", return_value={}
    )
    mocker.patch.object(client, "_http_request")
    client.http_request("GET")

    assert basic_auth_mock.call_count == int(bool(client.username))
    assert oauth2_mock.call_count == int(not bool(client.username))


def test_test_module_basic_auth(mocker):
    """
    Given:
        - mock client with username and api_key (basic auth)
    When:
        - run `test_module` function
    Then:
        - Ensure no error is raised, and return `ok`
    """
    from JiraV3 import test_module
    client = jira_base_client_mock("dummy_username", "dummy_api_key")
    mocker.patch.object(client, "test_instance_connection")
    assert test_module(client) == "ok"


def test_module_oauth2(mocker):
    """
    Given:
        - mock client without username and api_key (oauth2)
    When:
        - run `test_module` function
    Then:
        - Ensure that error msg is raised, with a guide how to connect through oauth2
    """
    from JiraV3 import test_module
    client = jira_base_client_mock()
    mocker.patch.object(client, "test_instance_connection")
    with pytest.raises(
        DemistoException,
        match="In order to authorize the instance, first run the command `!jira-oauth-start`."
    ):
        test_module(client)


@pytest.mark.parametrize(
    "params, expected_exception",
    [
        pytest.param(
            {"username": "", "api_key": "", "client_id": "", "client_secret": ""},
            "The required parameters were not provided. See the help window for more information.",
            id="no auth params provided"
        ),
        pytest.param(
            {
                "username": "dummy_username",
                "api_key": "dummy_api_key",
                "client_id": "dummy_client_id",
                "client_secret": "dummy_client_secret"
            },
            "The `User name` or `API key` parameters cannot be provided together"
            " with the `Client ID` or `Client Secret` parameters. See the help window"
            " for more information.",
            id="both types of auth params are provided"
        ),
        pytest.param(
            {"username": "dummy_username", "api_key": "", "client_id": "", "client_secret": ""},
            "To use basic authentication, the 'User name' and 'API key' parameters are mandatory",
            id="only `username` parameter was provided"
        ),
        pytest.param(
            {"username": "", "api_key": "", "client_id": "dummy_client_id", "client_secret": ""},
            "To use OAuth 2.0, the 'Client ID' and 'Client Secret' parameters are mandatory",
            id="only `client_id` parameter was provided"
        )
    ]
)
def test_validate_params_failure(params: dict[str, str], expected_exception: str):
    """
    Given:
        - auth params
    When:
        - run `validate_auth_params` function
    Then:
        - Ensure that as long as no valid auth params are sent an error is raised with a special message
    """
    from JiraV3 import validate_auth_params
    with pytest.raises(DemistoException, match=expected_exception):
        validate_auth_params(**params)


@pytest.mark.parametrize(
    "params",
    [
        pytest.param(
            {
                "username": "dummy_username",
                "api_key": "dummy_api_key",
                "client_id": "",
                "client_secret": ""
            },
            id="Only basic auth params were provided"
        ),
        pytest.param(
            {
                "username": "",
                "api_key": "",
                "client_id": "dummy_client_id",
                "client_secret": "dummy_client_secret"
            },
            id="Only oauth2 params were provided oauth2"
        )
    ]
)
def test_validate_auth_params(params: dict[str, str]):
    """
    Given:
        - auth params
    When:
        - run `validate_auth_params` function
    Then:
        - Ensure that when provided valid auth params
          the function does not raise
    """
    from JiraV3 import validate_auth_params
    validate_auth_params(**params)


@pytest.mark.parametrize(
    "username, api_key",
    [
        ("dummy_username", "dummy_api_key"),
        ("", "")
    ]
)
def test_client_is_basic_auth_or_oauth(username: str, api_key: str):
    """
    Given:
        - username and api_key
    When:
        - run `__init__` method for `JiraBaseClient` class
    Then:
        - Ensure that when the client class receives both username and api_key,
          the `is_basic_auth` flag is True otherwise False
    """
    client = jira_base_client_mock(username, api_key)
    assert client.is_basic_auth == bool(username)


class TestJiraGetIssueCommand:
    def test_create_file_info_from_attachment(self, mocker):
        """
        Given:
            - An attachment id
        When
            - Calling the get create_file_info_from_attachment function to create a file of type EntryType.ENTRY_INFO_FILE
        Then
            - Validate that the file has been created, is of the correct type, has the correct file name, and was created
            with the correct content.
        """
        from pathlib import Path
        from JiraV3 import create_file_info_from_attachment
        client = jira_base_client_mock()
        raw_response_attachment_metadata = util_load_json('test_data/get_issue_test/raw_response_attachment_metadata.json')
        dummy_attachment_content = util_load_bytes_file('test_data/get_issue_test/dummy_attachment_content.txt')
        mocker.patch.object(client, 'get_attachment_metadata', return_value=raw_response_attachment_metadata)
        mocker.patch.object(client, 'get_attachment_content', return_value=dummy_attachment_content)
        file_name = 'dummy_file_name.pdf'
        file_result_mocker = mocker.patch('JiraV3.fileResult', side_effect=fileResult)
        file_info_res = create_file_info_from_attachment(client=client, attachment_id='dummy_attachment_id',
                                                         file_name=file_name)
        assert file_result_mocker.call_args[1].get('data') == dummy_attachment_content
        assert file_info_res.get('Type') == EntryType.ENTRY_INFO_FILE
        assert file_info_res.get('File', '') == file_name
        assert Path.exists(Path(f"{demisto.investigation()['id']}_{file_info_res.get('FileID', '')}"))
        Path.unlink(Path(f"{demisto.investigation()['id']}_{file_info_res.get('FileID', '')}"))

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
        from JiraV3 import get_issue_command
        client = jira_base_client_mock()
        raw_issue_response = util_load_json('test_data/get_issue_test/raw_response.json')
        mocker.patch.object(client, 'get_issue', return_value=raw_issue_response)
        mocker.patch('JiraV3.create_file_info_from_attachment', return_value={'Contents': '', 'ContentsFormat': 'dummy_format',
                                                                              'Type': 'dummy_type', 'File': 'dummy_filename',
                                                                              'FileID': 'dummy_id'})
        demisto_results_mocker = mocker.patch.object(demisto, 'results')
        get_issue_command(client=client, args={'issue_id': '1234', 'get_attachments': get_attachments})
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
                "displayName": "Example User",
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
                "displayName": "Example User",
            },
            "created": "2023-03-23T07:45:29.056+0200",
            "updated": "2023-03-23T07:45:29.056+0200",
        }
        expected_comment_entry = {'Id': '18322', 'Comment': 'Hello there', 'User': 'Example User',
                                  'Created': '2023-03-23T07:45:29.056+0200', 'Updated': '2023-03-23T07:45:29.056+0200',
                                  'UpdateUser': 'Example User'}
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
            - Validate that get_transitions, and transition_issue method were called, which is in charge of changing the status
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

    @pytest.mark.parametrize('args', [
        ({'issue_key': 'dummy_key', 'status': 'Selected for development'}),
        ({'issue_key': 'dummy_key', 'transition': 'In Development'})
    ])
    def test_apply_issue_status_and_transition_with_arguments(self, mocker, args):
        """
        Given:
            - A Jira client, and the status, or transition argument to change the status of the issue.
        When
            - Calling the edit issue command, with additional arguments to edit the issue.
        Then
            - Validate that correct issue fields were sent as part of the request.
        """
        from JiraV3 import edit_issue_command
        client = jira_base_client_mock()
        transitions_raw_response = util_load_json('test_data/get_transitions_test/raw_response.json')
        mocker.patch.object(client, 'get_transitions', return_value=transitions_raw_response)
        mocker.patch.object(client, 'transition_issue', return_value=requests.Response())
        command_args = args | {'issue_key': 'dummy_key', 'description': 'dummy description', 'project_key': 'dummy_project_key',
                               'project_id': 'dummy_project_id',
                               'labels': 'label1,label2', 'components': 'comp1,comp2',
                               'customfield_1': 'dummy custom field'}
        # The transition ID is 21 since the mocked transition 'In Development' has an ID of 21 and the status
        # 'Selected for development' correlates to the transition 'In Development', which as stated, has an ID of 21
        expected_issue_fields = {'transition': {'id': '21'},
                                 'fields': {'description': 'dummy description', 'project':
                                            {'key': 'dummy_project_key', 'id':
                                             'dummy_project_id'}, 'labels': ['label1', 'label2'],
                                            'components': [{'name': 'comp1'}, {'name': 'comp2'}],
                                            'customfield_1': 'dummy custom field'}}
        mocker.patch.object(client, 'get_issue', return_value={})
        transition_issue_mocker = mocker.patch.object(client, 'transition_issue', return_value=requests.Response())
        edit_issue_command(client=client, args=command_args)
        assert expected_issue_fields == transition_issue_mocker.call_args[1].get('json_data')

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
        args = {'issue_key': 'dummy_key', 'components': 'comp1,comp2', 'labels': 'label1,label2',
                'summary': 'appended summary', 'action': 'append'}
        expected_issue_fields = {'fields': {'components':
                                            [{'name': 'current-comp1'}, {'name': 'current-comp2'},
                                             {'name': 'comp1'}, {'name': 'comp2'}],
                                            'labels': ['current-label1', 'current-label2', 'label1', 'label2'],
                                            'summary': 'current summary, appended summary'}}
        mocker.patch.object(client, 'get_issue', side_effect=[{
            'fields': {'components': [{'name': 'current-comp1'}, {'name': 'current-comp2'}],
                       'labels': ['current-label1', 'current-label2'], 'summary': 'current summary'}
        }, {}])
        edit_issue_mocker = mocker.patch.object(client, 'edit_issue', return_value=requests.Response())
        edit_issue_command(client=client, args=args)
        assert expected_issue_fields == edit_issue_mocker.call_args[1].get('json_data')

    def test_create_custom_issue_fields_for_update_with_action_append(self, mocker):
        """
        Given:
            - A Jira client, and custom issue fields (supplied using the issue_json argument) to edit the Jira issue,
            with the append action.
        When
            - Calling the edit issue command.
        Then
            - Validate that the edit_issue method (which is in charge of calling the endpoint with the relevant data
            to edit the issue) was called with the correct json data.
        """
        from JiraV3 import edit_issue_command
        client = jira_base_client_mock()
        args = {'issue_key': 'dummy_key',
                'issue_json': '{"fields": {"customfield_1": "new data", "customfield_2": ["new data"]}}', 'action': 'append'}
        expected_issue_fields = {'fields': {'customfield_1': 'old data, new data', 'customfield_2': ['old data', 'new data']}}
        mocker.patch.object(client, 'get_issue', side_effect=[{
            'fields': {'customfield_1': 'old data', 'customfield_2': ['old data']}}, {}])
        edit_issue_mocker = mocker.patch.object(client, 'edit_issue', return_value=requests.Response())
        edit_issue_command(client=client, args=args)
        assert expected_issue_fields == edit_issue_mocker.call_args[1].get('json_data')

    def test_edit_issue_command_with_issue_json_and_another_arg_error(self):
        from JiraV3 import edit_issue_command
        client = jira_base_client_mock()
        with pytest.raises(
            DemistoException,
            match=(
                "When using the `issue_json` argument, additional arguments cannot be used "
                "except `issue_id`, `issue_key`, `status`, `transition`, and `action` arguments.ֿֿֿ"
                "\n see the argument description"
            )
        ):
            edit_issue_command(
                client=client,
                args={"summary": "test", "issue_json": '{"fields": {"customfield_10037":"field_value"}}'}
            )

    @pytest.mark.parametrize(
        "extra_args",
        [
            {"action": "test"},
            {"status": "test"},
            {"transition": "test"},
            {"issue_key": "test"},
            {"issue_id": "test"},
        ]
    )
    def test_edit_issue_command_with_issue_json_and_another_arg_no_error(
        self, mocker: MockerFixture, extra_args: dict
    ):
        """
        Given:
            - The `issue_json` arg and one more arg allowed for use with `issue_json`
        When:
            - run edit_issue_command function
        Then:
            - Ensure that the validation process,
              which ensures that no additional arguments are present alongside the 'issue_json' argument,
              does not result in an error in cases where the additional arguments are one of:
              `action`, `status`, `transition`.

        """
        from JiraV3 import edit_issue_command

        client = jira_base_client_mock()
        mocker.patch("JiraV3.apply_issue_status")
        mocker.patch("JiraV3.apply_issue_transition")
        mocker.patch.object(client, "edit_issue")
        mocker.patch.object(client, "get_issue", return_value={})
        mocker.patch("JiraV3.create_issue_md_and_outputs_dict", return_value=({}, {}))
        mocker.patch("JiraV3.create_issue_fields", return_value={})
        mocker.patch("JiraV3.create_issue_fields_for_appending", return_value={})
        mocker.patch("JiraV3.get_issue_id_or_key", return_value="test")
        args = {"issue_json": '{"fields": {"customfield_10037":"field_value"}}'} | extra_args
        assert edit_issue_command(client=client, args=args)


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
        command_result = create_issue_command(client=client, args={"summary": "test"})
        assert command_result.to_context().get('EntryContext') == {'Ticket(val.Id && val.Id == obj.Id)': expected_outputs}

    def test_create_issue_command_with_issue_json(self, mocker):
        """
        Given:
            - A Jira client
            - Jira summary from issue_json
        When
            - Calling the create issue command.
        Then
            - Validate that the issue id and key of the newly created issue is returned.
        """
        from JiraV3 import create_issue_command
        client = jira_base_client_mock()
        raw_response = {'id': "1234", 'key': 'dummy_key', 'self': 'dummy_link'}
        expected_outputs = {'Id': '1234', 'Key': 'dummy_key'}
        mocker.patch.object(client, 'create_issue', return_value=raw_response)
        command_result = create_issue_command(client=client, args={"issue_json": '{"fields": {"summary": "test"}}'})
        assert command_result.to_context().get('EntryContext') == {'Ticket(val.Id && val.Id == obj.Id)': expected_outputs}

    def test_create_issue_command_with_issue_json_and_another_arg(self):
        """
        Given:
            - A Jira client
            - issue_json and summary args
        When
            - Calling the create issue command.
        Then
            - Ensure an error is raised with an expected error message.
        """
        from JiraV3 import create_issue_command
        client = jira_base_client_mock()
        with pytest.raises(
            DemistoException,
            match="When using the argument `issue_json`, additional arguments cannot be used.ֿֿֿ\n see the argument description"
        ):
            create_issue_command(
                client=client,
                args={"summary": "test", "issue_json": '{"fields": {"customfield_10037":"field_value"}}'}
            )

    def test_create_issue_command_no_summary(self):
        """
        Given:
            - A Jira client
            - no Jira summary from issue_json / args
        When
            - Calling the create issue command.
        Then
            - Validate that DemistoException is raised
        """
        from JiraV3 import create_issue_command
        client = jira_base_client_mock()
        with pytest.raises(DemistoException) as e:
            create_issue_command(client=client, args={})
        assert 'The summary argument must be provided' in str(e)


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


class TestJiraDeleteAttachmentFileCommand:
    def test_delete_attachment_file_command(self, mocker: MockerFixture):
        """
        Given:
            - A Jira client.
        When
            - Calling the delete attachment file command.
        Then
            - Validate that the correct readable output is outputted to the user.
        """
        from JiraV3 import delete_attachment_file_command
        attachment_id = "dummy_id"
        client = jira_base_client_mock()
        mocker.patch.object(client, 'delete_attachment_file', return_value=requests.Response())
        command_result = delete_attachment_file_command(client=client, args={'attachment_id': attachment_id})
        assert f'Attachment id {attachment_id} was deleted successfully' in command_result.to_context().get('HumanReadable')


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
        assert run_query_mocker.call_args[1].get('query_params', {}).get('jql') == 'ORDER BY created ASC'
        assert command_result.to_context()['EntryContext'] == {'Ticket': {'idOffSet': '10161'}}

    def test_get_id_offset_command_with_custom_query_argument(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the get_id_offset_command, with the argument `query` in order to retrieve the first issue id with respect
            to the given query.
        Then
            - Validate that the correct query is being sent with the API call.
        """
        from JiraV3 import get_id_offset_command
        client = jira_base_client_mock()
        raw_response = util_load_json('test_data/issue_query_test/raw_response.json')
        run_query_mocker = mocker.patch.object(client, 'run_query', return_value=raw_response)
        get_id_offset_command(client=client, args={'query': 'project = "Dummy Project"'})
        assert run_query_mocker.call_args[1].get('query_params', {}).get(
            'jql') == 'project = "Dummy Project" ORDER BY created ASC'

    def test_get_id_offset_empty_results(self, mocker):
        """
        Given:
            - A Jira client
        When
            - Calling the get_id_offset_command, and getting no issues from the API.
        Then
            - Validate that the correct message is returned to the user.
        """
        from JiraV3 import get_id_offset_command
        client = jira_base_client_mock()
        mocker.patch.object(client, 'run_query', return_value={})
        command_result = get_id_offset_command(client=client, args={})
        assert command_result.to_context().get('HumanReadable') == 'No issues found to retrieve the ID offset'

    def test_edit_comment_command(self, mocker):
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
    def test_list_fields_command(self, mocker, pagination_args):
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
        assert command_results.to_context()['HumanReadable'] == 'Issue link created successfully'


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
        assert command_results.to_context()['HumanReadable'] == 'Issues were moved to the Sprint successfully'


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
    def test_delete_comment_command(self, mocker):
        """
        Given:
            - A Jira client.
        When
            - Calling the jira-issue-delete-comment.
        Then
            - Validate that the correct message is returned to the user.
        """
        from JiraV3 import delete_comment_command
        client = jira_base_client_mock()
        mocker.patch.object(client, 'delete_comment', return_value=requests.Response())
        command_results = delete_comment_command(client=client, args={'issue_key': 'dummy_issue_key'})
        assert 'Comment deleted successfully' in command_results.to_context()['HumanReadable']


class TestJiraGetIssueAttachmentsCommand:
    @pytest.mark.parametrize('args,number_of_calls', [
        ({'attachment_id': '1,2,3'}, 3), ({'attachment_id': '1234'}, 1)
    ])
    def test_get_issue_attachments_command(self, mocker, args, number_of_calls):
        """
        Given:
            - A Jira client, and attachment ids to retrieve the content of the attachments.
        When
            - Calling the jira-issue-get-attachment.
        Then
            - Validate that the number of times the function that is in charge of creating the files to display in the War Room
            is called with correspondence to the number of attachment ids supplied (The function that is in charge of creating
            the file themselves has been tested in the class TestJiraGetIssueCommand).
        """
        from JiraV3 import issue_get_attachment_command
        client = jira_base_client_mock()
        create_file_info_mocker = mocker.patch('JiraV3.create_file_info_from_attachment', return_value={})
        issue_get_attachment_command(client=client, args=args)
        assert len(create_file_info_mocker.mock_calls) == number_of_calls


class TestJiraUploadFileCommand:
    def test_get_file_name_and_content(self, mocker):
        """
        Given:
            - An entry id, that is found in a War Room
        When
            - Getting the file name and content of it, in order to upload to Jira
        Then
            - Validate that the function that is in charge of retrieving the name and content of the file returns
            the required data.
        """
        from JiraV3 import get_file_name_and_content
        file_path = 'test_data/get_issue_test/dummy_attachment_content.txt'
        expected_file_name = 'dummy_attachment_content.txt'
        mocker.patch.object(demisto, 'getFilePath',
                            return_value={'name': expected_file_name,
                                          'path': file_path})
        file_name, file_bytes = get_file_name_and_content(entry_id='dummy_entry_id')
        expected_file_bytes: bytes = b''
        with open(file_path, 'rb') as f:
            expected_file_bytes = f.read()
        assert expected_file_bytes == file_bytes
        assert expected_file_name == file_name

    def test_upload_file_command(self, mocker):
        """
        Given:
            - A Jira client.
        When
            - When calling the jira-issue-upload-file command.
        Then
            - Validate that correct message is outputted to the user.
        """
        from JiraV3 import upload_file_command
        client = jira_base_client_mock()
        upload_file_raw_response = util_load_json('test_data/upload_file_test/raw_response.json')
        expected_command_results_context = util_load_json('test_data/upload_file_test/parsed_result.json')
        mocker.patch('JiraV3.get_file_name_and_content', return_value=('dummy_file_name.pdf', b'dummy content'))
        mocker.patch.object(client, 'upload_attachment', return_value=upload_file_raw_response)
        command_results = upload_file_command(client=client, args={'issue_key': 'COMPANYSA-35'})
        assert command_results.to_context()['HumanReadable'] == expected_command_results_context['HumanReadable']

    def test_upload_XSOAR_attachment_to_jira_mime_type_check(self, mocker):
        """
        Given:
            - A Jira client.
        When
            - When calling the jira-issue-upload-file command.
        Then
            - Validate that correct mime_type was given to the file.
        """
        from JiraV3 import upload_XSOAR_attachment_to_jira
        client = jira_base_client_mock()
        file_name = 'dummy_file_name.pdf'
        issue_key = 'COMPANYSA-35'
        file_bytes = b'dummy content'
        expected_file_mime_type = 'application/pdf'
        upload_file_raw_response = util_load_json('test_data/upload_file_test/raw_response.json')
        files = {'file': (file_name, file_bytes, expected_file_mime_type)}
        mocker.patch('JiraV3.get_file_name_and_content', return_value=('dummy_file_name.pdf', b'dummy content'))
        mocker.patch('JiraV3.guess_type', return_value=(expected_file_mime_type, ''))
        mock_request = mocker.patch.object(client, 'upload_attachment', return_value=upload_file_raw_response)
        upload_XSOAR_attachment_to_jira(client=client,
                                        entry_id='',
                                        issue_id_or_key=issue_key)
        mock_request.assert_called_with(issue_id_or_key=issue_key,
                                        files=files)

    def test_upload_XSOAR_attachment_to_jira_mime_type_fail(self, mocker):
        """
        Given:
            - A Jira client.
        When
            - When calling the jira-issue-upload-file command.
        Then
            - Validate that in case of unsuccessful upload to Jira due to mime type issue,
            we will try again with the default mime type.
        """
        from JiraV3 import upload_XSOAR_attachment_to_jira
        client = jira_base_client_mock()
        issue_key = 'COMPANYSA-35'
        mocker.patch('JiraV3.get_file_name_and_content', return_value=('dummy_file_name.pdf', b'dummy content'))
        mocker.patch('JiraV3.guess_type', return_value=('application/pdf', ''))
        mocker.patch.object(client, 'upload_attachment', side_effect=DemistoException('failed to upload', res={}))
        mock_request = mocker.patch.object(client, 'upload_attachment',
                                           side_effect=[DemistoException('failed to upload', res={}), {}])
        upload_XSOAR_attachment_to_jira(client=client, entry_id='', issue_id_or_key=issue_key)

        # Validate that we run upload_attachment twice, once with an error, and second time to use default file type
        assert mock_request.call_count == 2
        # Validate that the second call uses the default file type (application-type)
        mock_request.assert_called_with(files={'file': ('dummy_file_name.pdf', b'dummy content', 'application-type')},
                                        issue_id_or_key=issue_key)

    def test_create_files_to_upload(self, mocker):
        """
        Given:
            - An empty file mime type, a file name and a file bytes.
        When
            - When calling the jira-issue-upload-file command.
        Then
            - Validate that correct mime_type was given to the file, and the object to upload is correct.
        """
        from JiraV3 import create_files_to_upload
        file_name = 'dummy_file_name.pdf'
        file_bytes = b'dummy content'
        expected_file_mime_type = 'application/pdf'
        expected_files = {'file': (file_name, file_bytes, expected_file_mime_type)}
        mocker.patch('JiraV3.guess_type', return_value=(expected_file_mime_type, ''))
        result_files, result_mime_type = create_files_to_upload('', file_name, file_bytes)
        assert result_files == expected_files
        assert result_mime_type == expected_file_mime_type

    def test_create_files_to_upload_none_type(self, mocker):
        """
        Given:
            - An empty file mime type, a file name and a file bytes.
        When
            - When calling the jira-issue-upload-file command.
        Then
            - Validate that in case of unsuccessful type guess, the default mime type is given (application-type),
            and the object to upload is correct.
        """
        from JiraV3 import create_files_to_upload
        file_name = 'dummy_file_name.pdf'
        file_bytes = b'dummy content'
        expected_file_mime_type = 'application-type'
        expected_files = {'file': (file_name, file_bytes, expected_file_mime_type)}
        mocker.patch('JiraV3.guess_type', return_value=(None, ''))
        result_files, result_mime_type = create_files_to_upload('', file_name, file_bytes)
        assert result_files == expected_files
        assert result_mime_type == expected_file_mime_type

    def test_create_files_to_upload_given_type(self, mocker):
        """
        Given:
            - An application-type file mime type, a file name and a file bytes.
        When
            - When calling the jira-issue-upload-file command.
        Then
            - Validate that in case of a given mime type the function guess_type wasn't called,
            and the object to upload is correct.
        """
        from JiraV3 import create_files_to_upload
        file_name = 'dummy_file_name.pdf'
        file_bytes = b'dummy content'
        expected_file_mime_type = 'application-type'
        expected_files = {'file': (file_name, file_bytes, expected_file_mime_type)}
        mock_guess_type = mocker.patch('JiraV3.guess_type', return_value=(None, ''))
        result_files, result_mime_type = create_files_to_upload(expected_file_mime_type, file_name, file_bytes)
        assert result_files == expected_files
        assert result_mime_type == expected_file_mime_type
        mock_guess_type.assert_not_called()


class TestJiraGetIdByAttribute:
    @pytest.mark.parametrize('raw_response_path,parsed_result_path', [
        ('test_data/get_id_by_attribute_test/raw_response_cloud.json',
         'test_data/get_id_by_attribute_test/parsed_result_cloud.json'),
        ('test_data/get_id_by_attribute_test/raw_response_onprem.json',
         'test_data/get_id_by_attribute_test/parsed_result_onprem.json')
    ])
    def test_get_id_when_response_returns_one_user(self, mocker, raw_response_path, parsed_result_path):
        """
        Given:
            - A Jira client
        When
            - When calling the jira-get-id-by-attribute command, and only getting one user in the response.
        Then
            - Validate that the user is returned.
        """
        from JiraV3 import get_id_by_attribute_command
        client = jira_base_client_mock()
        user_search_raw_response = util_load_json(raw_response_path)
        expected_command_results_context = util_load_json(parsed_result_path)
        mocker.patch.object(client, 'get_id_by_attribute', return_value=user_search_raw_response)
        command_results = get_id_by_attribute_command(client=client, args={'attribute': 'fred@example.com'})
        assert expected_command_results_context == command_results.to_context()

    @pytest.mark.parametrize('client, raw_response_path', [
        (jira_cloud_client_mock(), 'test_data/get_id_by_attribute_test/raw_response_cloud.json'),
        (jira_onprem_client_mock(), 'test_data/get_id_by_attribute_test/raw_response_onprem.json')
    ])
    def test_id_not_found_when_response_returns_multiple_users(self, mocker, client, raw_response_path):
        """
        Given:
            - A Jira client, once for Cloud, and once for OnPrem
        When
            - When calling the jira-get-id-by-attribute command, and getting multiple responses, and not being able
            to extract the account id (probably because the attribute was an email, and the email can sometimes not be
            returned for privacy reasons)
        Then
            - Validate that an appropriate message is returned to the user.
        """
        from JiraV3 import get_id_by_attribute_command
        user_search_raw_response = util_load_json(raw_response_path)
        attribute = 'fred@example.com'
        command_results_message = (f'Multiple accounts found, but it was not possible to resolve which one'
                                   f' of them is most relevant to attribute {attribute}. Please try to provide'
                                   ' the "DisplayName" attribute if not done so before, or supply the full'
                                   ' attribute.')
        user_search_raw_response = user_search_raw_response * 2  # To mock that the response returned multiple users
        mocker.patch.object(client, 'get_id_by_attribute', return_value=user_search_raw_response)
        command_results = get_id_by_attribute_command(client=client, args={'attribute': attribute})
        assert command_results_message in command_results.to_context()['HumanReadable']

    @pytest.mark.parametrize('client, raw_response_path', [
        (jira_cloud_client_mock(), 'test_data/get_id_by_attribute_test/raw_response_cloud.json'),
        (jira_onprem_client_mock(), 'test_data/get_id_by_attribute_test/raw_response_onprem.json')
    ])
    def test_multiple_ids_found_when_response_returns_multiple_users(self, mocker, client, raw_response_path):
        """
        Given:
            - A Jira client, once for Cloud, and once for OnPrem
        When
            - When calling the jira-get-id-by-attribute command, and getting multiple responses, and extracting
            multiple account ids
        Then
            - Validate that an appropriate message is returned to the user.
        """
        from JiraV3 import get_id_by_attribute_command
        # client = jira_onprem_client_mock()
        user_search_raw_response = util_load_json(raw_response_path)
        attribute = 'fred@example.com'
        command_results_message = (f'Multiple account IDs were found for attribute: {attribute}.\n'
                                   f'Please try to provide the other attributes available - Email or DisplayName'
                                   ' (and Name in the case of Jira OnPrem).')
        user_search_raw_response = user_search_raw_response * 2  # To mock that the response returned multiple users
        user_search_raw_response[0]['emailAddress'] = attribute
        mocker.patch.object(client, 'get_id_by_attribute', return_value=user_search_raw_response)
        command_results = get_id_by_attribute_command(client=client, args={'attribute': attribute})
        assert command_results_message in command_results.to_context()['HumanReadable']

    @pytest.mark.parametrize('client, raw_response_path, parsed_result_path', [
        (jira_cloud_client_mock(), 'test_data/get_id_by_attribute_test/raw_response_cloud.json',
         'test_data/get_id_by_attribute_test/parsed_result_cloud.json'),
        (jira_onprem_client_mock(), 'test_data/get_id_by_attribute_test/raw_response_onprem.json',
         'test_data/get_id_by_attribute_test/parsed_result_onprem.json')
    ])
    def test_get_id_from_multiple_ids_when_response_returns_multiple_users(self, mocker, client, raw_response_path,
                                                                           parsed_result_path):
        """
        Given:
            - A Jira client, once for Cloud, and once for OnPrem
        When
            - When calling the jira-get-id-by-attribute command, and getting multiple responses, and extracting
            the correct account id.
        Then
            - Validate that the user is returned.
        """
        from JiraV3 import get_id_by_attribute_command
        user_search_raw_response = util_load_json(raw_response_path)
        user = user_search_raw_response[0]  # The test data contains only one user in the raw response
        expected_command_results_context = util_load_json(parsed_result_path)
        attribute = 'fred@example.com'
        # To mock that the response returned multiple users
        user_search_raw_response = [user, user.copy()]
        user_search_raw_response[0]['emailAddress'] = attribute
        user_search_raw_response[1]['emailAddress'] = 'wrong attribute'
        mocker.patch.object(client, 'get_id_by_attribute', return_value=user_search_raw_response)
        command_results = get_id_by_attribute_command(client=client, args={'attribute': attribute})
        assert expected_command_results_context == command_results.to_context()


class TestJiraGetSpecificField:
    def test_get_specific_field_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - When calling the jira-get-specific-field
        Then
            - Validate that the specified fields are returned in the context data
        """
        from JiraV3 import get_specific_fields_command
        client = jira_base_client_mock()
        issue_raw_response = util_load_json('test_data/get_specific_field_test/raw_response.json')
        expected_command_results = util_load_json('test_data/get_specific_field_test/parsed_result.json')
        mocker.patch.object(client, 'get_issue', return_value=issue_raw_response)
        command_results = get_specific_fields_command(client=client, args={'issue_key': 'COMPANYSA-35',
                                                                           'fields': 'watches,rank'})
        assert expected_command_results['EntryContext'] == command_results.to_context()['EntryContext']
        assert expected_command_results['HumanReadable'] == command_results.to_context()['HumanReadable']


class TestJiraIssueQueryField:
    def test_issue_query_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - When calling the jira-issue-query, with the `fields` argument
        Then
            - Validate that the context data and human readable of the queried issues are returned.
        """
        from JiraV3 import issue_query_command
        client = jira_base_client_mock()
        issue_query_raw_response = util_load_json('test_data/get_issue_query_test/raw_response.json')
        expected_command_results = util_load_json('test_data/get_issue_query_test/parsed_result.json')
        mocker.patch.object(client, 'run_query', return_value=issue_query_raw_response)
        command_results = issue_query_command(client=client, args={'fields': 'watches,rank'})
        command_results = command_results if isinstance(command_results, list) else [command_results]
        for expected_command_result, command_result in zip(expected_command_results, command_results):
            assert expected_command_result['EntryContext'] == command_result.to_context()['EntryContext']
            assert expected_command_result['HumanReadable'] == command_result.to_context()['HumanReadable']


class TestJiraAddUrlLink:
    def test_add_url_link(self, mocker):
        """
        Given:
            - A Jira client
        When
            - When calling the jira-issue-add-link
        Then
            - Validate that the correct human readable is returned to the user
        """
        from JiraV3 import add_link_command
        client = jira_base_client_mock()
        mocker.patch.object(client, 'add_link', return_value={
            "id": 10000,
            "self": "https://your-domain.atlassian.net/rest/api/issue/MKY-1/remotelink/10000"
        })
        command_result = add_link_command(client=client, args={'issue_key': 'dummy_issue_key'})
        markdown_dict = {'id': 10000, 'key': None, 'comment': '',
                         'ticket_link': 'https://your-domain.atlassian.net/rest/api/issue/MKY-1/remotelink/10000'}
        expected_human_readable = tableToMarkdown(name='Remote Issue Link', t=markdown_dict, removeNull=True)
        assert command_result.to_context()['HumanReadable'] == expected_human_readable


class TestJiraGetModifiedRemoteIds():
    USER_INFO_RES = {"accountId": "dummy_account_id", "accountType": "atlassian",
                     "emailAddress": "admin@example.com", "displayName": "Example Example", "timeZone": "Asia/Jerusalem",
                     "locale": "en_US"}
    LAST_UPDATE_TIME = '2023-05-01'

    def test_get_modified_issue_ids(self, mocker):
        """
        Given:
            - A Jira client, the last updated time of an incident, and a timezone
        When
            - When calling get_modified_issue_ids in order to get the issues that have an updated time greater than
            the last updated time of the incident
        Then
            - Validate that the correct ids are returned
        """
        from JiraV3 import get_modified_issue_ids
        client = jira_base_client_mock()
        modified_issues = {'issues': [{'id': '1234'}, {'id': '2345'}]}
        mocker.patch.object(client, 'run_query', return_value=modified_issues)
        modified_issues = get_modified_issue_ids(client=client, last_update_date=self.LAST_UPDATE_TIME,
                                                 timezone_name=self.USER_INFO_RES.get('timeZone', ''))
        assert modified_issues == ['1234', '2345']

    def test_get_modified_remote_data_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - When calling the mirroring mechanism the command get_modified_remote_data_command is called in order
            to retrieve the Jira issues that have been updated since the last update time of the incident.
        Then
            - Validate that the correct ids are returned
        """
        from JiraV3 import get_modified_remote_data_command
        client = jira_base_client_mock()
        mocker.patch('JiraV3.get_modified_issue_ids', return_value=['1234', '2345'])
        mocker.patch.object(client, 'get_user_info', return_value=self.USER_INFO_RES)
        get_modified_remote_data = get_modified_remote_data_command(client=client,
                                                                    args={'lastUpdate': self.LAST_UPDATE_TIME})
        assert get_modified_remote_data.modified_incident_ids == ['1234', '2345']


class TestJiraGetMappingFields:
    ISSUE_FIELDS_RES = [
        {"id": "statuscategorychangedate", "key": "statuscategorychangedate", "name": "Status Category Changed"},
        {"id": "parent", "key": "parent", "name": "Parent"}]

    def test_get_mapping_fields_command(self, mocker):
        """
        Given:
            - A Jira client
        When
            - When calling get-mapping-fields command.
        Then
            - Validate that we are able to extract the ids from the response from the API.
        """
        from JiraV3 import get_mapping_fields_command
        client = jira_base_client_mock()
        mocker.patch.object(client, 'get_issue_fields', return_value=self.ISSUE_FIELDS_RES)
        mapping_fields = get_mapping_fields_command(client=client)
        assert list(mapping_fields.scheme_types_mappings[0].fields.keys()) == [
            "statuscategorychangedate", "parent", "issue_id", "summary",
            "description", "labels", "components", "priority", "due_date", "assignee", "status", "assignee_id",
            "original_estimate"
        ]


class TestJiraUpdateRemoteSystem:
    def test_update_remote_system_using_delta(self, mocker):
        """
        Given:
            - A Jira client
        When
            - When the mirror out mechanism is called, which calls the update-remote-system command, and
            we need to edit the issue
        Then
            - Validate that the API call to edit the issue was called with the correct data, which was
            extracted from the delta and data arguments.
        """
        from JiraV3 import update_remote_system_command
        client = jira_base_client_mock()
        args = {
            "incidentChanged": "17757",
            "remoteId": "17757",
            "data": {"summary": "data", "not_changes_key": "not_changes_val"},
            "delta": {"summary": "changes", "dbotMirrorDirection": "test"},
        }
        edit_issue_mocker = mocker.patch.object(client, 'edit_issue', return_value=requests.Response())
        update_remote_system_res = update_remote_system_command(client=client, args=args,
                                                                comment_tag_to_jira='', attachment_tag_to_jira='')
        assert update_remote_system_res == '17757'
        assert edit_issue_mocker.call_args[1]['json_data'] == {'fields': {'summary': 'data'}}

    def test_update_remote_system_using_file_entry_with_correct_tag(self, mocker):
        """
        Given:
            - A Jira client
        When
            - When the mirror out mechanism is called, which calls the update-remote-system command, and
            we get an attachment with the appropriate attachment tag.
        Then
            - Validate that the attachment gets uploaded to Jira, and that the name of the file contains the
            constant ATTACHMENT_MIRRORED_FROM_XSOAR
        """
        from JiraV3 import (update_remote_system_command, ATTACHMENT_MIRRORED_FROM_XSOAR)
        client = jira_base_client_mock()
        args = {
            "remoteId": "17757",
            'entries': [{'entry_id': '1234', 'type': EntryType.FILE, 'tags': ['attachment_tag']}],
        }
        upload_attachment_mocker = mocker.patch('JiraV3.upload_XSOAR_attachment_to_jira', return_value=[])
        update_remote_system_res = update_remote_system_command(client=client, args=args,
                                                                comment_tag_to_jira='',
                                                                attachment_tag_to_jira='attachment_tag')
        assert update_remote_system_res == '17757'
        assert ATTACHMENT_MIRRORED_FROM_XSOAR in upload_attachment_mocker.call_args[1]['attachment_name']

    @pytest.mark.parametrize('client', [
        (jira_cloud_client_mock()),
        (jira_onprem_client_mock())
    ])
    def test_update_remote_system_using_entry_with_correct_comment_tag(self, mocker, client):
        """
        Given:
            - A Jira client
        When
            - When the mirror out mechanism is called, which calls the update-remote-system command, and
            we get a comment with the appropriate comment tag.
        Then
            - Validate that the comment gets uploaded to Jira, and the content of the comment contains the
            constant COMMENT_MIRRORED_FROM_XSOAR
        """
        from JiraV3 import (update_remote_system_command, COMMENT_MIRRORED_FROM_XSOAR)
        args = {
            "remoteId": "17757",
            'entries': [{'entry_id': '1234', 'tags': ['comment_tag'], 'contents': 'some comment'}],
        }
        add_comment_mocker = mocker.patch.object(client, 'add_comment', return_value={})
        update_remote_system_res = update_remote_system_command(client=client, args=args,
                                                                comment_tag_to_jira='comment_tag',
                                                                attachment_tag_to_jira='')

        assert update_remote_system_res == '17757'
        assert COMMENT_MIRRORED_FROM_XSOAR in str(add_comment_mocker.call_args[1]['json_data'])


class TestJiraGetRemoteData:
    def test_entries_returned_when_configured_not_to_return(self, mocker):
        """
        Given:
            - A Jira client
        When
            - When the mirror in mechanism is called, which calls the get-remote-data command, and
            the user configured not to return comments nor attachments
        Then
            - Validate that no entries are returned
        """
        from JiraV3 import (get_updated_remote_data, ATTACHMENT_MIRRORED_FROM_XSOAR)
        attachments_entries = [{'File': 'dummy_file_name', 'FileID': 'id1'},
                               {'File': f'dummy_file_name{ATTACHMENT_MIRRORED_FROM_XSOAR}', 'FileID': 'id2'}]
        comments_entries = [
            {'Comment': 'Comment 1', 'Updated': '2023-01-01', 'UpdatedUser': 'User 1'},
            {'Comment': 'Comment 2', 'Updated': '2023-05-01', 'UpdatedUser': 'User 2'},
            {'Comment': 'Comment 3', 'Updated': '2023-05-01', 'UpdatedUser': 'User 3'}, ]
        client = jira_base_client_mock()
        mocker.patch('JiraV3.get_attachments_entries_for_fetched_incident', return_value=attachments_entries)
        mocker.patch('JiraV3.get_comments_entries_for_fetched_incident', return_value=comments_entries)
        updated_incident: Dict[str, Any] = {}
        parsed_entries = get_updated_remote_data(client=client, issue={}, updated_incident=updated_incident, issue_id='1234',
                                                 mirror_resolved_issue=False, attachment_tag_from_jira='attachment from jira',
                                                 comment_tag_from_jira='', user_timezone_name='',
                                                 incident_modified_date=None,
                                                 fetch_comments=False, fetch_attachments=False)
        assert parsed_entries == []

    def test_get_attachment_entries(self, mocker):
        """
        Given:
            - A Jira client
        When
            - When the mirror in mechanism is called, which calls the get-remote-data command, and
            we want to extract the attachments of the Jira issue
        Then
            - Validate that the attachments get added to the appropriate incident field, and only the entries
            that don't contain the constant ATTACHMENT_MIRRORED_FROM_XSOAR in their names, get the tag added to
            them.
        """
        from JiraV3 import (get_updated_remote_data, ATTACHMENT_MIRRORED_FROM_XSOAR)
        attachments_entries = [{'File': 'dummy_file_name_old', 'FileID': 'id1', 'created': '2024-01-01T00:00:00.000+0300'},
                               {'File': 'dummy_file_name', 'FileID': 'id1', 'created': '2024-02-01T00:00:00.000+0300'},
                               {'File': f'dummy_file_name{ATTACHMENT_MIRRORED_FROM_XSOAR}', 'FileID': 'id2',
                                'created': '2024-02-01T00:00:00.000+0300'}]
        create_file_mock_res = [{k: v for k, v in item.items() if k != 'created'} for item in attachments_entries[1:]]
        client = jira_base_client_mock()
        mocker.patch('JiraV3.create_file_info_from_attachment', side_effect=create_file_mock_res)
        mocker.patch('demistomock.get', return_value=attachments_entries)
        mocker.patch('JiraV3.get_comments_entries_for_fetched_incident', return_value=[])
        updated_incident: Dict[str, Any] = {}
        user_timezone = 'Asia/Jerusalem'
        parsed_entries = get_updated_remote_data(client=client, issue={}, updated_incident=updated_incident, issue_id='1234',
                                                 mirror_resolved_issue=False, attachment_tag_from_jira='attachment from jira',
                                                 comment_tag_from_jira='', user_timezone_name=user_timezone,
                                                 incident_modified_date=arg_to_datetime('2024-01-01T00:00:00.000+0300'),
                                                 fetch_comments=False, fetch_attachments=True)
        expected_extracted_attachments = [{"path": "id1", "name": "dummy_file_name"},
                                          {"path": "id2", "name": "dummy_file_name_mirrored_from_xsoar"}]
        expected_parsed_entries = [{"File": "dummy_file_name", "FileID": "id1", "Tags": ["attachment from jira"]}]
        assert updated_incident.get('extractedAttachments') == expected_extracted_attachments
        assert parsed_entries == expected_parsed_entries

    def test_get_comment_entries(self, mocker):
        """
        Given:
            - A Jira client
        When
            - When the mirror in mechanism is called, which calls the get-remote-data command, and
            we want to extract the comments of the Jira issue
        Then
            - Validate that the comments get added to the appropriate incident field, and only the entries
            that don't contain the constant ATTACHMENT_MIRRORED_FROM_XSOAR in their names, and have an updated time
            that is greater than the last incident update get the tag added to them
        """
        from JiraV3 import (get_updated_remote_data, COMMENT_MIRRORED_FROM_XSOAR)
        comments_entries = [
            {'Comment': f'Comment 1 {COMMENT_MIRRORED_FROM_XSOAR}', 'Updated': '2023-01-01', 'UpdatedUser': 'User 1'},
            {'Comment': f'Comment 2 {COMMENT_MIRRORED_FROM_XSOAR}', 'Updated': '2023-05-01', 'UpdatedUser': 'User 2'},
            {'Comment': 'Comment 3', 'Updated': '2023-05-01', 'UpdatedUser': 'User 3'}, ]
        client = jira_base_client_mock()
        mocker.patch('JiraV3.get_comments_entries_for_fetched_incident', return_value=comments_entries)
        mocker.patch('JiraV3.get_attachments_entries_for_fetched_incident', return_value=[])
        user_timezone = 'Asia/Jerusalem'
        dateparser_parse_mocker = mocker.patch('JiraV3.dateparser.parse', side_effect=dateparser.parse)
        updated_incident: Dict[str, Any] = {}
        parsed_entries = get_updated_remote_data(client=client, issue={}, updated_incident=updated_incident, issue_id='1234',
                                                 mirror_resolved_issue=False, attachment_tag_from_jira='',
                                                 comment_tag_from_jira='comment from jira', user_timezone_name=user_timezone,
                                                 incident_modified_date=dateparser.parse('2023-04-01'),
                                                 fetch_comments=True, fetch_attachments=False)
        expected_extracted_attachments = [
            {"Comment": f'Comment 1 {COMMENT_MIRRORED_FROM_XSOAR}', "Updated": "2023-01-01", "UpdatedUser": "User 1"},
            {"Comment": f'Comment 2 {COMMENT_MIRRORED_FROM_XSOAR}', "Updated": "2023-05-01", "UpdatedUser": "User 2"},
            {"Comment": "Comment 3", "Updated": "2023-05-01", "UpdatedUser": "User 3"}]
        expected_parsed_entries = [
            {"Type": 1, "Contents": "Comment 3\nJira Author: None",
                "ContentsFormat": "text", "Tags": ["comment from jira"], "Note": True}
        ]
        assert updated_incident.get('extractedComments') == expected_extracted_attachments
        assert parsed_entries == expected_parsed_entries
        assert dateparser_parse_mocker.call_args[1]['settings']['TIMEZONE'] == user_timezone

    @pytest.mark.parametrize('issue, should_be_closed', [
        ({'id': '1234', 'fields': {'status': {'name': 'Done'}, 'resolutiondate': ''}},
         True),
        ({'id': '1234', 'fields': {'status': {'name': 'Fixed'}, 'resolutiondate': '2023-01-01'}},
         True),
        ({'id': '1234', 'fields': {'status': {'name': 'Fixed'}, 'resolutiondate': ''}},
         False)
    ])
    def test_close_incident_entry(self, mocker, issue, should_be_closed):
        """
        Given:
            - A Jira client
        When
            - When the mirror in mechanism is called, which calls the get-remote-data command, and
            the remote Jira issue has been marked as resolved, or status has been changed to Done
        Then
            - Validate that correct entry is returned, which contains data about closing the incident in XSOAR
        """
        from JiraV3 import get_updated_remote_data
        client = jira_base_client_mock()
        mocker.patch('JiraV3.get_comments_entries_for_fetched_incident', return_value=[])
        mocker.patch('JiraV3.get_attachments_entries_for_fetched_incident', return_value=[])
        parsed_entries = get_updated_remote_data(client=client, issue=issue, updated_incident=issue, issue_id='1234',
                                                 mirror_resolved_issue=True, attachment_tag_from_jira='',
                                                 comment_tag_from_jira=' from jira', user_timezone_name='',
                                                 incident_modified_date=None, fetch_comments=False, fetch_attachments=False)
        if should_be_closed:
            close_reason = "Issue was marked as \"Resolved\", or status was changed to \"Done\""
            closed_entry = [{"Type": 1, "Contents": {"dbotIncidentClose": True,
                                                     "closeReason": close_reason}, "ContentsFormat": "json"}]
            assert parsed_entries == closed_entry
        else:
            assert parsed_entries == []

    def test_get_remote_data_response_is_returned(self, mocker):
        """
        Given:
            - A Jira client
        When
            - When the mirror in mechanism is called, which calls the get-remote-data command
        Then
            - Validate that correct entries are indeed returned
        """
        from JiraV3 import get_remote_data_command
        client = jira_base_client_mock()
        issue_response = {'id': '1234', 'fields': {'summary': 'dummy summary', 'updated': '2023-01-01'}}
        mocker.patch.object(client, 'get_issue', return_value=issue_response)
        mocker.patch('JiraV3.get_user_timezone', return_value='Asia/Jerusalem')
        close_reason = "Issue was marked as \"Resolved\", or status was changed to \"Done\""
        expected_parsed_entries = [
            {"Type": 1, "Contents": "Comment 3\nJira Author: None",
                "ContentsFormat": "text", "Tags": ["comment from jira"], "Note": True},
            {"File": "dummy_file_name", "FileID": "id1", "Tags": ["attachment from jira"]},
            {"Type": 1, "Contents": {"dbotIncidentClose": True,
                                     "closeReason": close_reason}, "ContentsFormat": "json"}
        ]
        mocker.patch('JiraV3.get_updated_remote_data', return_value=expected_parsed_entries)
        remote_data_response = get_remote_data_command(client=client, args={'id': '1234', 'lastUpdate': '2023-01-01'},
                                                       attachment_tag_from_jira='',
                                                       comment_tag_from_jira='', mirror_resolved_issue=True,
                                                       fetch_comments=True, fetch_attachments=True)
        assert remote_data_response.entries == expected_parsed_entries


class TestJiraFetchIncidents:
    FETCH_INCIDENTS_QUERY_CASES = [
        ('id', 'status!=done', '1234', '2023-05-01', '2023-05-02', '2023-02-01', [1, 2, 3, 4],
         'status!=done AND id >= 1234 AND ID NOT IN (1, 2, 3, 4) ORDER BY id ASC'),
        ('id', 'status!=done', '1234', '2023-05-01', '2023-05-02', '2023-02-01', [],
         'status!=done AND id >= 1234 ORDER BY id ASC'),
        ('created date', 'status!=done', '1234', '2023-05-01', '2023-05-02', '2023-02-01', [1, 2, 3, 4],
         'status!=done AND created >= "2023-05-01" AND ID NOT IN (1, 2, 3, 4) ORDER BY created ASC'),
        ('created date', 'status!=done', '1234', '2023-05-01', '2023-05-02', '2023-02-01', [],
         'status!=done AND created >= "2023-05-01" ORDER BY created ASC'),
        ('created date', 'status!=done', '1234', '', '2023-05-02', '2023-02-01', [],
         'status!=done AND created >= "2023-02-01" ORDER BY created ASC'),
        ('created date', 'status!=done', '1234', '', '2023-05-02', '2023-02-01', [1, 2, 3, 4],
         'status!=done AND created >= "2023-02-01" AND ID NOT IN (1, 2, 3, 4) ORDER BY created ASC'),

        ('updated date', 'status!=done', '1234', '2023-05-01', '2023-05-02', '2023-02-01', [1, 2, 3, 4],
         'status!=done AND updated >= "2023-05-02" AND ID NOT IN (1, 2, 3, 4) ORDER BY updated ASC'),
        ('updated date', 'status!=done', '1234', '2023-05-01', '2023-05-02', '2023-02-01', [],
         'status!=done AND updated >= "2023-05-02" ORDER BY updated ASC'),
        ('updated date', 'status!=done', '1234', '2023-05-01', '', '2023-02-01', [],
         'status!=done AND updated >= "2023-02-01" ORDER BY updated ASC'),
        ('updated date', 'status!=done', '1234', '2023-05-01', '', '2023-02-01', [1, 2, 3, 4],
         'status!=done AND updated >= "2023-02-01" AND ID NOT IN (1, 2, 3, 4) ORDER BY updated ASC')
    ]

    @pytest.mark.parametrize(('issue_field_to_fetch_from, fetch_query, last_fetch_id,'
                              'last_fetch_created_time, last_fetch_updated_time,'
                              'first_fetch_interval, issue_ids_to_exclude, expected_fetch_query'), FETCH_INCIDENTS_QUERY_CASES)
    def test_create_fetch_incidents_query(self, issue_field_to_fetch_from: str, fetch_query: str, last_fetch_id: int,
                                          last_fetch_created_time: str, last_fetch_updated_time: str,
                                          first_fetch_interval: str, issue_ids_to_exclude: List[int], expected_fetch_query: str):
        """
        Given:
            - Arguments to create the fetch query, which are:
                1. issue_field_to_fetch_from: the issue field to fetch by
                2. fetch_query: the query to include in every fetch
                3. last_fetch_id: the last fetched id
                4. last_fetch_created_time: the created time of the last fetch issue
                5. last_fetch_updated_time: the updated time of the last fetch issue
                6. first_fetch_interval: the first fetch interval to fetch from if the fetch timestamp is empty,
                    and we are fetching using created or updated time.
                7. issue_ids_to_exclude: the ids of the issues that we want to exclude.
        When
            - When fetching incidents
        Then
            - Validate that the correct fetch query is created given the above arguments
        """
        from JiraV3 import create_fetch_incidents_query
        fetch_query = create_fetch_incidents_query(issue_field_to_fetch_from, fetch_query, last_fetch_id, last_fetch_created_time,
                                                   last_fetch_updated_time, first_fetch_interval, issue_ids_to_exclude)
        assert fetch_query == expected_fetch_query

    def test_get_comments_entries_for_fetched_incident(self, mocker):
        """
        Given:
            - A Jira client, and an issue id or key
        When
            - When extracting the issue's comments as entries to put in the incident field
        Then
            - Validate that the correct data is extracted and returned
        """
        from JiraV3 import get_comments_entries_for_fetched_incident
        client = jira_base_client_mock()
        comments_raw_response = util_load_json('test_data/get_comments_test/raw_response.json')
        mocker.patch.object(client, 'get_comments', return_value=comments_raw_response)
        comments_entries = get_comments_entries_for_fetched_incident(client=client, issue_id_or_key='1234')
        expected_comments_entries = [
            {'Id': '18322', 'Comment': 'Hello there', 'User': 'Example User', 'Created': '2023-03-23T07:45:29.056+0200',
             'Updated': '2023-03-23T07:45:29.056+0200', 'UpdateUser': 'Example User'},
            {'Id': '18329', 'Comment': 'Second comment', 'User': 'Example User', 'Created': '2023-03-27T20:54:15.878+0300',
             'Updated': '2023-03-27T20:54:15.878+0300', 'UpdateUser': 'Example User'},
            {'Id': '18394', 'Comment': 'This is a comment from Jira demo', 'User': 'Example User',
             'Created': '2023-04-24T15:41:54.472+0300', 'Updated': '2023-04-24T15:41:54.472+0300', 'UpdateUser': 'Example User'}
        ]
        assert expected_comments_entries == comments_entries

    def test_get_attachments_entries_for_fetched_incident(self, mocker):
        """
        Given:
            - A Jira client, and an issue id or key
        When
            - When extracting the issue's attachments as entries to put in the incident field
        Then
            - Validate that the correct data is extracted and returned
        """
        from JiraV3 import get_attachments_entries_for_fetched_incident
        client = jira_base_client_mock()
        attachment_metadata_raw_response = util_load_json('test_data/get_issue_test/raw_response_attachment_metadata.json')
        expected_attachments_entries = [
            {'Contents': '', 'ContentsFormat': 'dummy_format', 'Type': 'dummy_type', 'File': 'dummy_filename_1',
             'FileID': 'dummy_id_1'}, {
                'Contents': '', 'ContentsFormat': 'dummy_format', 'Type': 'dummy_type', 'File': 'dummy_filename_2', 'FileID':
                    'dummy_id_2'}]
        mocker.patch('JiraV3.create_file_info_from_attachment', side_effect=expected_attachments_entries)
        attachments_entries = get_attachments_entries_for_fetched_incident(
            client=client,
            attachments_metadata=[attachment_metadata_raw_response,
                                  attachment_metadata_raw_response]
        )
        assert expected_attachments_entries == attachments_entries

    def test_get_fetched_attachments(self, mocker):
        """
        Given:
            - A Jira client, and the issue response
        When
            - Extracting the attachments of the fetched issue
        Then
            - Validate that the correct data is extracted and returned
        """
        from JiraV3 import get_fetched_attachments
        attachments_entries = [
            {'Contents': '', 'ContentsFormat': 'dummy_format', 'Type': 'dummy_type', 'File': 'dummy_filename_1',
             'FileID': 'dummy_id_1'}, {
                'Contents': '', 'ContentsFormat': 'dummy_format', 'Type': EntryType.ERROR, 'File': 'dummy_filename_2', 'FileID':
                    'dummy_id_2'}]
        mocker.patch('JiraV3.get_attachments_entries_for_fetched_incident', return_value=attachments_entries)
        client = jira_base_client_mock()
        expected_fetched_attachments = [{'path': 'dummy_id_1', 'name': 'dummy_filename_1'}]
        fetched_attachments = get_fetched_attachments(client=client, issue={})
        assert expected_fetched_attachments == fetched_attachments

    def test_get_fetched_comments(self, mocker):
        """
        Given:
            - A Jira client, and an issue id.
        When
            - Extracting the comments' entries of the fetched issue.
        Then
            - Validate that the correct data is extracted and returned.
        """
        from JiraV3 import get_fetched_comments
        expected_comments_entries = [
            {'Id': '18322', 'Comment': 'Hello there', 'User': 'Example User', 'Created': '2023-03-23T07:45:29.056+0200',
             'Updated': '2023-03-23T07:45:29.056+0200', 'UpdateUser': 'Example User'},
            {'Id': '18329', 'Comment': 'Second comment', 'User': 'Example User', 'Created': '2023-03-27T20:54:15.878+0300',
             'Updated': '2023-03-27T20:54:15.878+0300', 'UpdateUser': 'Example User'}]
        mocker.patch('JiraV3.get_comments_entries_for_fetched_incident', return_value=expected_comments_entries)
        attachments_entries = [
            {'Contents': '', 'ContentsFormat': 'dummy_format', 'Type': 'dummy_type', 'File': 'dummy_filename_1',
             'FileID': 'dummy_id_1'}, {
                'Contents': '', 'ContentsFormat': 'dummy_format', 'Type': EntryType.ERROR, 'File': 'dummy_filename_2', 'FileID':
                    'dummy_id_2'}]
        mocker.patch('JiraV3.get_attachments_entries_for_fetched_incident', return_value=attachments_entries)
        client = jira_base_client_mock()
        comments_entries = get_fetched_comments(client=client, issue_id='1234')
        assert comments_entries == expected_comments_entries

    def test_add_extracted_data_to_incident(self):
        """
        Given:
            - An issue response
        When
            - Extracting data from the issue raw response, to insert it to the respective incident fields
        Then
            - Validate that the correct data is extracted and returned
        """
        from JiraV3 import add_extracted_data_to_incident
        issue = util_load_json('test_data/get_issue_test/raw_response.json')
        expected_issue = add_extracted_data_to_incident(issue=issue)
        expected_extracted_issue_data = {'extractedSubtasks': [
            {'id': '21525', 'key': 'COMPANYSA-63'}, {'id': '21538', 'key': 'COMPANYSA-70'}],
            'extractedCreator': 'Example User(admin@test.com)', 'extractedComponents': [
                'Almost-Done', 'dummy-comp', 'Integration', 'New-Component']}
        assert expected_extracted_issue_data.items() <= expected_issue.items()

    @pytest.mark.parametrize('issue_field_priority, severity', [
        ({'name': 'Highest'}, 4),
        ({'name': 'High'}, 3),
        ({'name': 'Medium'}, 2),
        ({'name': 'Low'}, 1),
        ({'name': 'Lowest'}, 1),
        ({'name': 'Extreme'}, 0),
    ])
    def test_get_jira_issue_severity(self, issue_field_priority, severity):
        """
        Given:
            - The priority field of an issue
        When
            - Determining the severity of the incident
        Then
            - Validate that the priority of the issue is mapped to the correct severity
        """
        from JiraV3 import get_jira_issue_severity
        assert severity == get_jira_issue_severity(issue_field_priority)

    def test_parse_custom_fields(self):
        """
        Given:
            - An issue response
        When
            - Parsing the custom fields in the response to a more human readable form
        Then
            - Validate that the data of the custom fields get parsed and show the correct data
        """
        from JiraV3 import parse_custom_fields
        issue = util_load_json('test_data/get_issue_test/raw_response.json')
        expected_parsed_custom_fields = util_load_json('test_data/parsed_issue_custom_fields.json')
        parse_custom_fields(issue=issue, issue_fields_id_to_name_mapping=issue.get('names', {}) or {})
        assert expected_parsed_custom_fields == issue

    def test_set_last_run_when_first_time_running_fetch(self, mocker):
        """
        Given:
            - Arguments to use when calling the fetch incidents mechanism
        When
            - Calling the fetch incidents mechanism for the first time (last_run is empty)
        Then
            - Validate that the last run object gets saved with the correct data
        """
        from JiraV3 import (fetch_incidents, DEFAULT_FETCH_LIMIT)
        client = jira_base_client_mock()
        mocker.patch('JiraV3.demisto.getLastRun', return_value={})
        mocker.patch('JiraV3.create_incident_from_issue', return_value={})
        set_last_run_mocker = mocker.patch('JiraV3.demisto.setLastRun', side_effect=demisto.setLastRun)
        query_raw_response = {
            'issues': [
                {'id': '1', 'fields': {'created': '2023-12-11 21:09', 'updated': '2023-12-12 21:09'}},
                {'id': '2', 'fields': {'created': '2023-12-11 22:09', 'updated': '2023-12-12 22:09'}}
            ]
        }
        mocker.patch.object(client, 'run_query', return_value=query_raw_response)
        fetch_incidents(
            client=client,
            issue_field_to_fetch_from='created date',
            fetch_query='status!=done',
            id_offset=1234,
            fetch_attachments=True,
            fetch_comments=True,
            max_fetch_incidents=DEFAULT_FETCH_LIMIT,
            first_fetch_interval='3 days',
            mirror_direction='Incoming And Outgoing',
            comment_tag_to_jira="comment_tag_to_jira",
            comment_tag_from_jira='comment_tag_from_jira',
            attachment_tag_to_jira='attachment_tag_to_jira',
            attachment_tag_from_jira='attachment_tag_from_jira'
        )
        expected_last_run = {'issue_ids': [1, 2], 'id': 2, 'created_date': '2023-12-11 22:09',
                             'updated_date': '2023-12-12 22:09'}
        assert expected_last_run == set_last_run_mocker.call_args[0][0]

    def test_set_last_run_when_last_run_is_not_empty(self, mocker):
        """
        Given:
            - Arguments to use when calling the fetch incidents mechanism
        When
            - Calling the fetch incidents mechanism, and the last_run object is not empty
        Then
            - Validate that the last run object gets saved with the correct data
        """
        from JiraV3 import (fetch_incidents, DEFAULT_FETCH_LIMIT)
        client = jira_base_client_mock()
        mocker.patch('JiraV3.demisto.getLastRun',
                     return_value={'issue_ids': ['1', '2'], 'id': '2', 'created_date': '2023-12-11 22:09',
                                   'updated_date': '2023-12-12 22:09'})
        mocker.patch('JiraV3.create_incident_from_issue', return_value={})
        set_last_run_mocker = mocker.patch('JiraV3.demisto.setLastRun', side_effect=demisto.setLastRun)
        query_raw_response = {
            'issues': [
                {'id': '3', 'fields': {'created': '2024-01-11 21:09', 'updated': '2024-01-12 21:09'}},
                {'id': '4', 'fields': {'created': '2024-01-11 22:09', 'updated': '2024-01-12 22:09'}}
            ]
        }
        mocker.patch.object(client, 'run_query', return_value=query_raw_response)
        fetch_incidents(
            client=client,
            issue_field_to_fetch_from='created date',
            fetch_query='status!=done',
            id_offset=1234,
            fetch_attachments=True,
            fetch_comments=True,
            max_fetch_incidents=DEFAULT_FETCH_LIMIT,
            first_fetch_interval='3 days',
            mirror_direction='Incoming And Outgoing',
            comment_tag_to_jira='comment_tag_to_jira',
            comment_tag_from_jira='comment_tag_from_jira',
            attachment_tag_to_jira='attachment_tag_to_jira',
            attachment_tag_from_jira='attachment_tag_from_jira'
        )
        expected_last_run = {'issue_ids': [3, 4], 'id': 4, 'created_date': '2024-01-11 22:09',
                             'updated_date': '2024-01-12 22:09'}
        assert expected_last_run == set_last_run_mocker.call_args[0][0]

    def test_set_last_run_when_we_did_not_progress_in_created_time(self, mocker):
        """
        Given:
            - Arguments to use when calling the fetch incidents mechanism
        When
            - Fetching incidents by the created date field, and we did no progress in terms of
            time (the created time stayed the same as the last fetch)
        Then
            - Validate that the issue ids from the last run get also added as part of the
            last_run object, since we did not progress in time
        """
        from JiraV3 import (fetch_incidents, DEFAULT_FETCH_LIMIT)
        client = jira_base_client_mock()
        mocker.patch('JiraV3.demisto.getLastRun',
                     return_value={'issue_ids': ['1', '2'], 'id': '2', 'created_date': '2023-12-11 22:09',
                                   'updated_date': '2023-12-12 22:09'})
        mocker.patch('JiraV3.create_incident_from_issue', return_value={})
        set_last_run_mocker = mocker.patch('JiraV3.demisto.setLastRun', side_effect=demisto.setLastRun)
        query_raw_response = {
            'issues': [
                {'id': '3', 'fields': {'created': '2023-12-11 22:09', 'updated': '2024-01-12 21:09'}},
                {'id': '4', 'fields': {'created': '2023-12-11 22:09', 'updated': '2024-01-12 22:09'}}
            ]
        }
        mocker.patch.object(client, 'run_query', return_value=query_raw_response)
        fetch_incidents(
            client=client,
            issue_field_to_fetch_from='created date',
            fetch_query='status!=done',
            id_offset=1234,
            fetch_attachments=True,
            fetch_comments=True,
            max_fetch_incidents=DEFAULT_FETCH_LIMIT,
            first_fetch_interval='3 days',
            mirror_direction='Incoming And Outgoing',
            comment_tag_to_jira='comment_tag_to_jira',
            comment_tag_from_jira='comment_tag_from_jira',
            attachment_tag_to_jira='attachment_tag_to_jira',
            attachment_tag_from_jira='attachment_tag_from_jira'
        )
        expected_last_run = {'issue_ids': [3, 4, 1, 2], 'id': 4, 'created_date': '2023-12-11 22:09',
                             'updated_date': '2024-01-12 22:09'}
        assert expected_last_run == set_last_run_mocker.call_args[0][0]

    def test_set_last_run_when_we_did_not_progress_in_updated_time(self, mocker):
        """
        Given:
            - Arguments to use when calling the fetch incidents mechanism
        When
            - Fetching incidents by the updated date field, and we did no progress in terms of
            time (the created time stayed the same as the last fetch)
        Then
            - Validate that the issue ids from the last run get also added as part of the
            last_run object, since we did not progress in time
        """
        from JiraV3 import (fetch_incidents, DEFAULT_FETCH_LIMIT)
        client = jira_base_client_mock()
        mocker.patch('JiraV3.demisto.getLastRun',
                     return_value={'issue_ids': ['1', '2'], 'id': '2', 'created_date': '2023-12-11 22:09',
                                   'updated_date': '2023-12-12 22:09'})
        mocker.patch('JiraV3.create_incident_from_issue', return_value={})
        set_last_run_mocker = mocker.patch('JiraV3.demisto.setLastRun', side_effect=demisto.setLastRun)
        query_raw_response = {
            'issues': [
                {'id': '3', 'fields': {'created': '2022-01-12 22:09', 'updated': '2023-12-12 22:09'}},
                {'id': '4', 'fields': {'created': '2022-01-11 22:09', 'updated': '2023-12-12 22:09'}}
            ]
        }
        mocker.patch.object(client, 'run_query', return_value=query_raw_response)
        fetch_incidents(
            client=client,
            issue_field_to_fetch_from='updated date',
            fetch_query='status!=done',
            id_offset=1234,
            fetch_attachments=True,
            fetch_comments=True,
            max_fetch_incidents=DEFAULT_FETCH_LIMIT,
            first_fetch_interval='3 days',
            mirror_direction='Incoming And Outgoing',
            comment_tag_to_jira='comment_tag_to_jira',
            comment_tag_from_jira='comment_tag_from_jira',
            attachment_tag_to_jira='attachment_tag_to_jira',
            attachment_tag_from_jira='attachment_tag_from_jira'
        )
        expected_last_run = {'issue_ids': [3, 4, 1, 2], 'id': 4, 'created_date': '2022-01-11 22:09',
                             'updated_date': '2023-12-12 22:09'}
        assert expected_last_run == set_last_run_mocker.call_args[0][0]

    def test_create_incident_from_issue(self, mocker):
        """
        Given:
            - Arguments to use when calling the fetch incidents mechanism
        When
            - Fetching incidents (in this unit test, we fetch two incidents, but only check on the first
            incident)
        Then
            - Validate that the correct value of the rawJSON key is returned, which will be used for the
            incident fields
        """
        from JiraV3 import fetch_incidents
        query_raw_response = util_load_json('test_data/issue_query_test/raw_response.json')
        issue_incident = util_load_json('test_data/fetch_incidents_test/issue_incident.json')
        client = jira_base_client_mock()
        mocker.patch.object(client, 'run_query', return_value=query_raw_response)
        mocker.patch('JiraV3.get_fetched_attachments', return_value=[{'FileID': '1'}, {'FileID': '2'}])
        comments_entries = [
            {'Id': '18322', 'Comment': 'Hello there', 'User': 'Example User', 'Created': '2023-03-23T07:45:29.056+0200',
             'Updated': '2023-03-23T07:45:29.056+0200', 'UpdateUser': 'Example User'}]
        mocker.patch('JiraV3.get_comments_entries_for_fetched_incident', return_value=comments_entries)
        incidents = fetch_incidents(
            client=client,
            issue_field_to_fetch_from='updated date',
            fetch_query='status!=done',
            id_offset=1234,
            fetch_attachments=True,
            fetch_comments=True,
            max_fetch_incidents=3,
            first_fetch_interval='3 days',
            mirror_direction='Incoming And Outgoing',
            comment_tag_to_jira='comment_tag_to_jira',
            comment_tag_from_jira='comment_tag_from_jira',
            attachment_tag_to_jira='attachment_tag_to_jira',
            attachment_tag_from_jira='attachment_tag_from_jira'
        )
        assert json.dumps(issue_incident) == incidents[0].get('rawJSON')

    def test_retrieve_smallest_issue_id_when_fetching_by_id_and_offset_is_zero(self, mocker):
        """
        Given:
            - Arguments to use when calling the fetch incidents mechanism
        When
            - We are fetching by the issue ID, and the ID offset is set to 0
        Then
            - Validate that the correct query is being called in order to retrieve the smallest issue ID
            with respect to the fetch query
        """
        from JiraV3 import (fetch_incidents, DEFAULT_FETCH_LIMIT)
        client = jira_base_client_mock()
        mocker.patch('JiraV3.create_incident_from_issue', return_value={})
        smallest_issue_id = '10161'
        run_query_mocker = mocker.patch.object(client, 'run_query', side_effect=[{'issues': [{'id': smallest_issue_id}]}, {}])
        fetch_query = 'status!=done'
        fetch_incidents(
            client=client,
            issue_field_to_fetch_from='id',
            fetch_query=fetch_query,
            id_offset=0,
            fetch_attachments=True,
            fetch_comments=True,
            max_fetch_incidents=DEFAULT_FETCH_LIMIT,
            first_fetch_interval='3 days',
            mirror_direction='Incoming And Outgoing',
            comment_tag_to_jira='comment_tag_to_jira',
            comment_tag_from_jira='comment_tag_from_jira',
            attachment_tag_to_jira='attachment_tag_to_jira',
            attachment_tag_from_jira='attachment_tag_from_jira'
        )
        assert run_query_mocker.call_args_list[0][1].get('query_params', {}).get(
            'jql', '') == f'{fetch_query} ORDER BY created ASC'
        assert run_query_mocker.call_args_list[1][1].get('query_params', {
        }).get('jql', '') == f'{fetch_query} AND id >= {smallest_issue_id} ORDER BY id ASC'

    def test_fetch_incidents_by_id_incorrect_id_offset_error(self, mocker):
        """
        Given:
            - Arguments to use when calling the fetch incidents mechanism
        When
            - We are fetching by the issue ID, and the ID offset is set to an arbitrary number, other than 0
        Then
            - Validate that the error is caught, that stems from configuring an incorrect (does not exist) ID offset
        """
        from JiraV3 import (fetch_incidents, DEFAULT_FETCH_LIMIT)
        client = jira_base_client_mock()
        mocker.patch('JiraV3.create_incident_from_issue', return_value={})
        smallest_issue_id = '10161'
        mocker.patch.object(
            client, 'run_query',
            side_effect=[Exception('Issue does not exist or you do not have permission to see it'),
                         {'issues': [{'id': smallest_issue_id}]}])
        fetch_query = 'status!=done'
        with pytest.raises(DemistoException) as e:
            fetch_incidents(
                client=client,
                issue_field_to_fetch_from='id',
                fetch_query=fetch_query,
                id_offset=1,
                fetch_attachments=True,
                fetch_comments=True,
                max_fetch_incidents=DEFAULT_FETCH_LIMIT,
                first_fetch_interval='3 days',
                mirror_direction='Incoming And Outgoing',
                comment_tag_to_jira='comment_tag_to_jira',
                comment_tag_from_jira='comment_tag_from_jira',
                attachment_tag_to_jira='attachment_tag_to_jira',
                attachment_tag_from_jira='attachment_tag_from_jira'
            )
        assert f'The smallest issue ID with respect to the fetch query is {smallest_issue_id}' in str(e)

    def test_fetch_incidents_by_id_and_offset_is_zero_error(self, mocker):
        """
        Given:
            - Arguments to use when calling the fetch incidents mechanism
        When
            - We are fetching by the issue ID, the ID offset is set to 0, we try to acquire the smallest issue ID
            with respect to the fetch query, but there are no issues returned from the fetch query
        Then
            - Validate that an error is returned, stating that there are no issues with respect to the configured fetch query
        """
        from JiraV3 import (fetch_incidents, DEFAULT_FETCH_LIMIT)
        client = jira_base_client_mock()
        mocker.patch('JiraV3.create_incident_from_issue', return_value={})
        mocker.patch.object(
            client, 'run_query',
            return_value={'issues': []})
        fetch_query = 'status!=done'
        with pytest.raises(DemistoException) as e:
            fetch_incidents(
                client=client,
                issue_field_to_fetch_from='id',
                fetch_query=fetch_query,
                id_offset=0,
                fetch_attachments=True,
                fetch_comments=True,
                max_fetch_incidents=DEFAULT_FETCH_LIMIT,
                first_fetch_interval='3 days',
                mirror_direction='Incoming And Outgoing',
                comment_tag_to_jira='comment_tag_to_jira',
                comment_tag_from_jira='comment_tag_from_jira',
                attachment_tag_to_jira='attachment_tag_to_jira',
                attachment_tag_from_jira='attachment_tag_from_jira'
            )
        assert 'The fetch query configured returned no Jira issues, please update it' in str(e)


class TestJiraIssueAssign:
    @pytest.mark.parametrize(
        'assignee, assignee_id, excpected_body_request',
        [
            ("server_assignee", None, {"name": "server_assignee"}),
            (None, "cloud_assignee", {"accountId": "cloud_assignee"})
        ]
    )
    def test_update_issue_assignee_command(self, mocker, assignee, assignee_id, excpected_body_request):
        """
        Given:
            - issue id, and assignees for cloud/server jira
        When
            - Running the update_issue_assignee_command
        Then
            - Ensure the body request is ok for both cloud/server jira
        """
        from JiraV3 import update_issue_assignee_command
        get_issue_response = util_load_json('test_data/get_issue_test/raw_response.json')
        args = {
            'assignee': assignee,           # For Jira OnPrem
            'assignee_id': assignee_id,     # For Jira Cloud
            'issue_id': 21487,
        }
        client: JiraBaseClient = jira_base_client_mock()
        if assignee_id:
            client = jira_cloud_client_mock()
        else:
            client = jira_onprem_client_mock()

        jira_req_mocker = mocker.patch.object(client, 'update_assignee', return_value=None)
        mocker.patch.object(client, 'get_issue', return_value=get_issue_response)
        assert update_issue_assignee_command(client=client, args=args)
        assert jira_req_mocker.call_args[1].get('assignee_body') == excpected_body_request

    def test_test_update_issue_assignee_command_no_assignees(self):
        """
        Given:
            - issue id, without assignee / assignee_id
        When
            - Running the update_issue_assignee_command
        Then
            - Ensure an exception is raised
        """
        from JiraV3 import update_issue_assignee_command

        args = {
            'assignee': None,       # For Jira OnPrem
            'assignee_id': None,    # For Jira Cloud
            'issue_id': 21487,
        }

        client = jira_base_client_mock()

        with pytest.raises(DemistoException):
            update_issue_assignee_command(client=client, args=args)


class TestJiraIssueGetForms:
    @pytest.mark.parametrize(
        'issue_id',
        [
            ("TES-2"),
            ("")
        ]
    )
    def test_issue_get_forms_command(self, mocker, issue_id):
        """
        Given:
            - issue_id
        When
            - Running the issue_get_forms_command
        Then
            - Ensure the body request is ok
        """
        from JiraV3 import issue_get_forms_command

        args = {
            'issue_id': issue_id
        }
        client: JiraBaseClient = jira_base_client_mock()
        client = jira_onprem_client_mock()

        raw_response_path = "test_data/get_issue_forms_test/raw_response.json"
        parsed_result_path = "test_data/get_issue_forms_test/parsed_result.json"
        issue_get_forms_response = util_load_json(raw_response_path)
        expected_command_results_context = util_load_json(parsed_result_path)
        mock_request = mocker.patch.object(client, 'issue_get_forms', return_value=issue_get_forms_response)

        if issue_id:
            command_results = issue_get_forms_command(client=client, args=args)
            for command_result in command_results:
                assert expected_command_results_context == command_result.to_context()
            mock_request.assert_called_with(issue_id=issue_id)
        else:
            with pytest.raises(ValueError):
                issue_get_forms_command(client=client, args=args)


class TestJiraGetUserInfo:
    @pytest.mark.parametrize(
        'key, username, account_id, raw_response_path, parsed_result_path',
        [
            ("JIRAUSER10000", None, None, "test_data/get_user_info_test/onprem_raw_response.json",
             "test_data/get_user_info_test/onprem_parsed_result.json"),
            (None, "firstlast", None, "test_data/get_user_info_test/onprem_raw_response.json",
             "test_data/get_user_info_test/onprem_parsed_result.json"),
            (None, None, "user@example.com", "test_data/get_user_info_test/cloud_raw_response.json",
             "test_data/get_user_info_test/cloud_parsed_result.json"),
            (None, None, None, None, None)
        ]
    )
    def test_get_user_info_command(self, mocker, key, username, account_id, raw_response_path, parsed_result_path):
        """
        Given:
            - key, username or account_id for cloud/server jira
        When
            - Running the get_user_info_command
        Then
            - Ensure the body request is ok for both cloud/server jira
        """
        from JiraV3 import get_user_info_command

        args = {
            'key': key,                 # For Jira OnPrem
            'username': username,       # For Jira OnPrem
            'account_id': account_id,     # For Jira Cloud
        }
        client: JiraBaseClient = jira_base_client_mock()
        if account_id:
            client = jira_cloud_client_mock()
            identifier = f"accountId={account_id}"
        elif key or username:
            client = jira_onprem_client_mock()
            if key:
                identifier = f"key={key}"
            else:
                identifier = f"username={username}"
        else:
            identifier = ""

        if identifier:
            get_user_info_response = util_load_json(raw_response_path)
            expected_command_results_context = util_load_json(parsed_result_path)
            mock_request = mocker.patch.object(client, 'get_user_info', return_value=get_user_info_response)

            command_results = get_user_info_command(client=client, args=args)
            assert expected_command_results_context == command_results.to_context()
            mock_request.assert_called_with(identifier)
        else:
            with pytest.raises(ValueError):
                get_user_info_command(client=client, args=args)


class TestJiraCreateMetadataIssueTypes:
    @pytest.mark.parametrize(
        "project_id_or_key",
        [
            ("test_project_id"),
            ("")
        ]
    )
    def test_get_create_metadata_issue_types(self, mocker, project_id_or_key):
        """
        Given:
            - project_id_or_key
        When:
            - running get_create_metadata_issue_types_command
        Then:
            - ensure the body request is ok
        """

        from JiraV3 import get_create_metadata_issue_types_command

        args = {
            "project_id_or_key": project_id_or_key,
        }

        client: JiraBaseClient = jira_base_client_mock()

        raw_response_path = "test_data/get_create_metadata_issue_types_test/raw_response.json"
        parsed_result_path = "test_data/get_create_metadata_issue_types_test/parsed_result.json"
        metadata_response = util_load_json(raw_response_path)
        expected_context = util_load_json(parsed_result_path)
        mock_request = mocker.patch.object(
            client,
            "get_create_metadata_issue_types",
            return_value=metadata_response
        )

        if project_id_or_key:
            command_results = get_create_metadata_issue_types_command(client=client, args=args)
            assert expected_context == command_results.to_context()
            mock_request.assert_called_with(project_id_or_key=project_id_or_key, start_at=0, max_results=50)
        else:
            with pytest.raises(ValueError):
                get_create_metadata_issue_types_command(client=client, args=args)


class TestJiraCreateMetadataField:
    @pytest.mark.parametrize(
        "project_id_or_key, issue_type_id",
        [
            ("test_project_id", "100"),
            ("", "")
        ]
    )
    def test_get_create_metadata_field(self, mocker, project_id_or_key, issue_type_id):
        """
        Given:
            - project_id_or_key
            - issue_type_id
        When:
            - running get_create_metadata_field_command
        Then:
            - ensure the body request is ok
        """

        from JiraV3 import get_create_metadata_field_command

        args = {
            "project_id_or_key": project_id_or_key,
            "issue_type_id": issue_type_id,
        }

        client: JiraBaseClient = jira_base_client_mock()

        raw_response_path = "test_data/get_create_metadata_field_test/raw_response.json"
        parsed_result_path = "test_data/get_create_metadata_field_test/parsed_result.json"
        metadata_response = util_load_json(raw_response_path)
        expected_context = util_load_json(parsed_result_path)
        mock_request = mocker.patch.object(
            client,
            "get_create_metadata_field",
            return_value=metadata_response
        )

        if project_id_or_key and issue_type_id:
            command_results = get_create_metadata_field_command(client=client, args=args)
            assert expected_context == command_results.to_context()
            mock_request.assert_called_with(project_id_or_key=project_id_or_key,
                                            issue_type_id=issue_type_id, start_at=0, max_results=50)
        else:
            with pytest.raises(ValueError):
                get_create_metadata_field_command(client=client, args=args)
