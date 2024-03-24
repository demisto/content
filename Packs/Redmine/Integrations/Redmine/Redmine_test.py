import pytest
from Redmine import Client


@pytest.fixture
def redmine_client(url: str = 'url', verify_certificate: bool = True, proxy: bool = False, auth=('username', 'password')):
    return Client(url, verify_certificate, proxy, auth=auth)


''' COMMAND FUNCTIONS TESTS '''


def test_create_issue_command(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed without list id
    When:
        - redmine-issue-create command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import create_issue_command
    http_request = mocker.patch.object(redmine_client, '_http_request')
    http_request.return_value = {"issue": {"id": "1"}}
    args = {'project_id': '1', 'issue_id': '1', 'subject': 'changeFromCode', 'tracker_id': 'Bug', 'watcher_user_ids': '[1]'}
    create_issue_command(redmine_client, args=args)
    http_request.assert_called_with('POST', '/issues.json', params={},
                                    json_data={'issue': {'issue_id': '1', 'subject': 'changeFromCode',
                                                         'tracker_id': '1', 'watcher_user_ids': [1], 'project_id': '1'}},
                                    headers={'Content-Type': 'application/json', 'X-Redmine-API-Key': True})


def test_create_issue_command_response(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed without list id
    When:
        - redmine-issue-create command is executed
    Then:
        - The http request return with the expected response
    """
    from Redmine import create_issue_command
    args = {
        'project_id': '1',
        'issue_id': '1',
        'subject': 'testResponse',
        'tracker_id': 'Bug'
    }
    create_issue_request_mock = mocker.patch.object(redmine_client, 'create_issue_request')
    create_issue_request_mock.return_value = {'issue': {'id': '789', 'project': {'name': 'testing', 'id': '1'},
                                                        'subject': 'testResponse', 'tracker': {'name': 'Bug', 'id': '1'}
                                                        }
                                              }
    result = create_issue_command(redmine_client, args)
    assert result.readable_output == ("### The issue you created:\n|Id|Project|Tracker|Subject|\n|---|---|---|---|\n"
                                      "| 789 | testing | Bug | testResponse |\n")


def test_create_issue_command_invalid_custom_fields(redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed and invalid custom field format
    When:
        - redmine-issue-create command is executed
    Then:
        - A DemistoException is raised
    """
    from Redmine import create_issue_command
    from CommonServerPython import DemistoException
    args = {'project_id': '1', 'custom_fields': 'jnlnj', 'issue_id': '1', 'subject': 'testSub', 'tracker_id': 'Bug',
            'watcher_user_ids': '[1]', 'status_id': 'New', 'priority_id': 'High'}
    with pytest.raises(DemistoException) as e:
        create_issue_command(redmine_client, args)
    assert e.value.message == "Custom fields not in format, please follow the instructions"


def test_create_issue_command_no_token_created_for_file(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-issue-create command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import create_issue_command
    from CommonServerPython import DemistoException
    create_file_token_request_mock = mocker.patch.object(redmine_client, 'create_file_token_request')
    create_file_token_request_mock.return_value = {'token': 'token123'}
    args = {'project_id': '1', 'status_id': 'New', 'file_entry_id': 'a.png', 'issue_id': '1',
            'subject': 'testSub', 'tracker_id': 'Bug', 'watcher_user_ids': '[1]'}
    with pytest.raises(DemistoException) as e:
        create_issue_command(redmine_client, args)
        create_file_token_request_mock.assert_called_with({}, 'a.png')
    assert e.value.message == "Could not upload file with entry id a.png, please try again."


def test_create_issue_command_with_file(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-issue-create command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import create_issue_command
    http_request = mocker.patch.object(redmine_client, '_http_request')
    http_request.return_value = {"issue": {"id": "1"}}
    create_file_token_request_mock = mocker.patch.object(redmine_client, 'create_file_token_request')
    create_file_token_request_mock.return_value = {'upload': {'token': 'token123'}}
    args = {'project_id': '1', 'file_entry_id': 'a.png', 'issue_id': '1', 'subject': 'testSub', 'tracker_id': 'Bug',
            'watcher_user_ids': '[1]'}
    create_issue_command(redmine_client, args=args)
    create_file_token_request_mock.assert_called_with({}, 'a.png')
    http_request.assert_called_with('POST', '/issues.json', params={}, json_data={'issue': {'issue_id': '1', 'subject': 'testSub',
                                                                                            'uploads': [{'token': 'token123'}],
                                                                                            'tracker_id': '1',
                                                                                            'watcher_user_ids': [1],
                                                                                            'project_id': '1'}},
                                    headers={'Content-Type': 'application/json', 'X-Redmine-API-Key': True})


def test_create_issue_command_with_file_response(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-issue-create command is executed
    Then:
        - The http request return with the expected response with file
    """
    from Redmine import create_issue_command
    args = {
        'project_id': '1',
        'subject': 'testResponse',
        'tracker_id': 'Bug',
        'file_entry_id': '139i401hivnaflkm',
        'file_name': 'test file response'
    }
    create_file_token_request_mock = mocker.patch.object(redmine_client, 'create_file_token_request')
    create_file_token_request_mock.return_value = {'upload': {'token': '111111'}}
    create_issue_request_mock = mocker.patch.object(redmine_client, 'create_issue_request')
    create_issue_request_mock.return_value = {'issue': {'id': '789', 'project': {'name': 'testing', 'id': '1'},
                                                        'subject': 'testResponse', 'tracker': {'name': 'Bug', 'id': '1'}
                                                        }
                                              }
    result = create_issue_command(redmine_client, args)
    assert args.get('uploads', {})[0].get('token') == '111111'
    assert args.get('uploads', {})[0].get('filename') == 'test file response'
    assert result.readable_output == ("### The issue you created:\n|Id|Project|Tracker|Subject|\n"
                                      "|---|---|---|---|\n| 789 | testing | Bug | testResponse |\n")


def test_create_issue_command_with_file_invalid_token_response(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-issue-create command is executed
    Then:
        - Raises an error on token response
    """
    from Redmine import create_issue_command
    from CommonServerPython import DemistoException
    args = {
        'project_id': '1',
        'subject': 'testResponse',
        'tracker_id': 'Bug',
        'file_entry_id': '139i401hivnaflkm',
        'file_name': 'test file response'
    }
    create_file_token_request_mock = mocker.patch.object(redmine_client, 'create_file_token_request')
    create_file_token_request_mock.return_value = {'upload': {'tokens': '111111'}}
    with pytest.raises(DemistoException) as e:
        create_issue_command(redmine_client, args)
    assert e.value.message == "Could not upload file with entry id 139i401hivnaflkm, please try again."


def test_update_issue_command(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-issue-update command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import update_issue_command
    http_request = mocker.patch.object(redmine_client, '_http_request')
    args = {'issue_id': '1', 'subject': 'changeFromCode', 'tracker_id': 'Bug', 'watcher_user_ids': '[1]'}
    update_issue_command(redmine_client, args=args)
    http_request.assert_called_with('PUT', '/issues/1.json', json_data={'issue': {'subject': 'changeFromCode',
                                                                                  'tracker_id': '1', 'watcher_user_ids': [1]}},
                                    headers={'Content-Type': 'application/json', 'X-Redmine-API-Key': True},
                                    empty_valid_codes=[204], return_empty_response=True)


def test_update_issue_command_response(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-issue-update command is executed
    Then:
        - The http request returns the right response
    """
    from Redmine import update_issue_command
    update_issue_request_mock = mocker.patch.object(redmine_client, 'update_issue_request')
    args = {'issue_id': '1', 'subject': 'changefortest', 'tracker_id': 'Bug', 'watcher_user_ids': '[1]'}
    update_issue_request_mock.return_value = {}
    result = update_issue_command(redmine_client, args=args)
    assert result.readable_output == 'Issue with id 1 was successfully updated.'


def test_update_issue_command_invalid_custom_fields(redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-issue-update command is executed
    Then:
        - Raises a custom fields not in format error
    """
    from Redmine import update_issue_command
    from CommonServerPython import DemistoException
    args = {'custom_fields': 'jnlnj', 'issue_id': '1', 'subject': 'testSub', 'tracker_id': 'Bug', 'watcher_user_ids': '[1]',
            'status_id': 'New', 'priority_id': 'High'}
    with pytest.raises(DemistoException) as e:
        update_issue_command(redmine_client, args)
    assert e.value.message == "Custom fields not in format, please follow the instructions"


def test_update_issue_command_no_token_created_for_file(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-issue-delete command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import update_issue_command
    from CommonServerPython import DemistoException
    create_file_token_request_mock = mocker.patch.object(redmine_client, 'create_file_token_request')
    create_file_token_request_mock.return_value = {'token': 'token123'}
    args = {'status_id': 'New', 'file_entry_id': 'a.png', 'issue_id': '1',
            'subject': 'testSub', 'tracker_id': 'Bug', 'watcher_user_ids': '[1]'}
    with pytest.raises(DemistoException) as e:
        update_issue_command(redmine_client, args)
        create_file_token_request_mock.assert_called_with({}, 'a.png')
    assert e.value.message == ("Could not upload file with entry id a.png, please try again.")


def test_update_issue_command_with_file(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed without list id
    When:
        - redmine-issue-update command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import update_issue_command
    http_request = mocker.patch.object(redmine_client, '_http_request')
    create_file_token_request_mock = mocker.patch.object(redmine_client, 'create_file_token_request')
    create_file_token_request_mock.return_value = {'upload': {'token': 'token123'}}
    args = {'file_entry_id': 'a.png', 'issue_id': '1', 'subject': 'testSub', 'tracker_id': 'Bug', 'watcher_user_ids': '[1]'}
    update_issue_command(redmine_client, args=args)
    create_file_token_request_mock.assert_called_with({}, 'a.png')
    http_request.assert_called_with('PUT', '/issues/1.json', json_data={'issue': {'subject': 'testSub', 'tracker_id': '1',
                                                                                  'uploads': [{'token': 'token123'}],
                                                                                  'watcher_user_ids': [1]}}, headers={
                                    'Content-Type': 'application/json', 'X-Redmine-API-Key': True}, empty_valid_codes=[204],
                                    return_empty_response=True)


def test_get_issues_list_command(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed with asset id
    When:
        - redmine-issue-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import get_issues_list_command
    http_request = mocker.patch.object(redmine_client, '_http_request')
    args = {'sort': 'priority:desc', 'limit': '1'}
    get_issues_list_command(redmine_client, args)
    http_request.assert_called_with('GET', '/issues.json', params={'status_id': 'open', 'offset': 0, 'limit': 1,
                                                                   'sort': 'priority:desc'}, headers={'X-Redmine-API-Key': True})


def test_get_issues_list_command_response(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed with asset id
    When:
        - redmine-issue-list command is executed
    Then:
        - The http request returns the right response
    """
    from Redmine import get_issues_list_command
    get_issues_list_request_mock = mocker.patch.object(redmine_client, 'get_issues_list_request')
    get_issues_list_request_mock.return_value = {"issues": [{"id": "1",
                                                            "tracker": {"name": "Bug", "id": "1"},
                                                             "status": {"name": "new", "id": "1"},
                                                             "priority": {"name": "High", "id": "1"},
                                                             "subject": "helloTest"
                                                             }]
                                                 }
    args = {'sort': 'priority:desc', 'limit': '1'}
    result = get_issues_list_command(redmine_client, args)
    assert result.readable_output == ("#### Showing 1 results from page 1:\n### Issues Results:\n"
                                      "|Id|Tracker|Status|Priority|Subject|\n|---|---|---|---|---|\n"
                                      "| 1 | Bug | new | High | helloTest |\n")


def test_get_issues_list_command_invalid_response(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed with asset id
    When:
        - redmine-issue-list command is executed
    Then:
        - raises a response format error
    """
    from Redmine import get_issues_list_command
    from CommonServerPython import DemistoException
    get_issues_list_request_mock = mocker.patch.object(redmine_client, 'get_issues_list_request')
    get_issues_list_request_mock.return_value = {"issue": [{"id": "1",
                                                            "tracker": {"name": "Bug", "id": "1"},
                                                            "status": {"name": "new", "id": "1"},
                                                            "priority": {"name": "High", "id": "1"},
                                                            "subject": "helloTest"
                                                            }]
                                                 }
    args = {'sort': 'priority:desc', 'limit': '1'}
    with pytest.raises(DemistoException) as e:
        get_issues_list_command(redmine_client, args)
    assert e.value.message == "The request succeeded, but a parse error occurred."


def test_get_issues_list_command_invalid_custom_field(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed with asset id
    When:
        - redmine-issue-list command is executed
    Then:
        - Raises an exception for invalid custom field
    """
    from Redmine import get_issues_list_command
    from CommonServerPython import DemistoException
    with pytest.raises(DemistoException) as e:
        get_issues_list_command(redmine_client, {'custom_field': 'frf2rg2'})
    assert e.value.message == ("Invalid custom field format, please follow the command description."
                               " Error: list index out of range.")


def test_get_issues_list_command_use_both_exclude_subproject(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed with asset id
    When:
        - redmine-issue-list command is executed
    Then:
        - Raises an exception for invalid usage of both exclude and subproject fields
    """
    from Redmine import get_issues_list_command
    from CommonServerPython import DemistoException
    with pytest.raises(DemistoException) as e:
        get_issues_list_command(redmine_client, {'subproject_id': '1', 'exclude': '2'})
    assert e.value.message == "Specify only one of the following, subproject_id or exclude."


def test_get_issues_list_command_invalid_status(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed with asset id
    When:
        - redmine-issue-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import get_issues_list_command
    from CommonServerPython import DemistoException
    with pytest.raises(DemistoException) as e:
        get_issues_list_command(redmine_client, {'status_id': 'hhjuhkk'})
    assert e.value.message == "Invalid status ID, please use only predefined values."


def test_get_issue_by_id_command(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed without asset id
    When:
        - redmine-issue-show command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import get_issue_by_id_command
    http_request = mocker.patch.object(redmine_client, '_http_request')
    http_request.return_value = {"issue": {"id": "1"}}
    args = {'issue_id': '1', 'include': 'watchers,attachments'}
    get_issue_by_id_command(redmine_client, args)
    http_request.assert_called_with('GET', '/issues/1.json',
                                    params={'include': 'watchers,attachments'}, headers={'X-Redmine-API-Key': True})


def test_get_issue_by_id_command_response(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed without asset id
    When:
        - redmine-issue-show command is executed
    Then:
        - The http request returns the right response
    """
    from Redmine import get_issue_by_id_command
    get_issue_by_id_request_mock = mocker.patch.object(redmine_client, 'get_issue_by_id_request')
    get_issue_by_id_request_mock.return_value = {"issue": {"id": "1",
                                                           "tracker": {"name": "Bug", "id": "1"},
                                                           "status": {"name": "new", "id": "1"},
                                                           "priority": {"name": "High", "id": "1"},
                                                           "subject": "helloTest",
                                                           "watchers": [{"name": "testingWatch", "id": "1"}]
                                                           }
                                                 }
    args = {'issue_id': '1', 'include': 'watchers,attachments'}
    result = get_issue_by_id_command(redmine_client, args)
    assert result.readable_output == ("### Issues List:\n|Id|Tracker|Status|Priority|Subject|Watchers|\n|---|---|---|---|---|---|"
                                      "\n| 1 | Bug | new | High | helloTest | **-**	***name***: testingWatch |\n")


def test_get_issue_by_id_command_invalid_response(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed without asset id
    When:
        - redmine-issue-show command is executed
    Then:
        - raises a response format error
    """
    from Redmine import get_issue_by_id_command
    from CommonServerPython import DemistoException
    get_issue_by_id_request_mock = mocker.patch.object(redmine_client, 'get_issue_by_id_request')
    get_issue_by_id_request_mock.return_value = {"id": "1",
                                                 "tracker": {"name": "Bug", "id": "1"},
                                                 "status": {"name": "new", "id": "1"},
                                                 "priority": {"name": "High", "id": "1"},
                                                 "subject": "helloTest",
                                                 "watchers": {"name": "testingWatch", "id": "1"}
                                                 }
    args = {'issue_id': '1', 'include': 'watchers,attachments'}
    with pytest.raises(DemistoException) as e:
        get_issue_by_id_command(redmine_client, args)
    assert e.value.message == "The request succeeded, but a parse error occurred."


def test_get_issue_by_id_command_invalid_include_argument(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-issue-show command is executed
    Then:
        - No issue id raises a DemistoException
    """
    from Redmine import get_issue_by_id_command
    from CommonServerPython import DemistoException
    args = {'sort': 'priority:desc', 'limit': '1', 'include': 'beikbfqi'}
    with pytest.raises(DemistoException) as e:
        get_issue_by_id_command(redmine_client, args)
    assert e.value.message == ("The 'include' argument should only contain values from ['children', 'attachments', 'relations', "
                               "'changesets', 'journals', 'watchers', 'allowed_statuses'], separated by commas. "
                               "These values are not in options {'beikbfqi'}.")


def test_delete_issue_by_id_command_response(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-issue-delete command is executed
    Then:
        - The http request returns the right response
    """
    from Redmine import delete_issue_by_id_command
    delete_issue_by_id_request_mock = mocker.patch.object(redmine_client, 'delete_issue_by_id_request')
    delete_issue_by_id_request_mock.return_value = {}
    args = {'issue_id': '41'}
    result = delete_issue_by_id_command(redmine_client, args)
    assert result.readable_output == "Issue with id 41 was deleted successfully."


def test_delete_issue_by_id_command(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-issue-delete command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import delete_issue_by_id_command
    http_request = mocker.patch.object(redmine_client, '_http_request')
    args = {'issue_id': '41'}
    delete_issue_by_id_command(redmine_client, args)
    http_request.assert_called_with('DELETE', '/issues/41.json', headers={'Content-Type': 'application/json',
                                    'X-Redmine-API-Key': True}, empty_valid_codes=[200, 204, 201], return_empty_response=True)


def test_delete_issue_by_id_command_invalid_issue_id(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-issue-delete command is executed
    Then:
        - No issue id raises a DemistoException
    """
    from Redmine import add_issue_watcher_command
    from CommonServerPython import DemistoException
    args = {'issue_id': '-1'}
    http_request = mocker.patch.object(redmine_client, '_http_request')
    http_request.side_effect = DemistoException(
        "Invalid ID for one or more fields that request IDs. Please make sure all IDs are correct.")
    with pytest.raises(DemistoException) as e:
        add_issue_watcher_command(redmine_client, args)
    assert e.value.message == "Invalid ID for one or more fields that request IDs. Please make sure all IDs are correct."


def test_add_issue_watcher_command_response(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-issue-watcher-add command is executed
    Then:
        - The http request returns the right response
    """
    from Redmine import add_issue_watcher_command
    add_issue_watcher_request_mock = mocker.patch.object(redmine_client, 'add_issue_watcher_request')
    add_issue_watcher_request_mock.return_value = {}
    args = {'issue_id': '1', 'watcher_id': '1'}
    result = add_issue_watcher_command(redmine_client, args)
    assert result.readable_output == "Watcher with id 1 was added successfully to issue with id 1."


def test_add_issue_watcher_command(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-issue-watcher-add command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import add_issue_watcher_command
    http_request = mocker.patch.object(redmine_client, '_http_request')
    args = {'issue_id': '1', 'watcher_id': '1'}
    add_issue_watcher_command(redmine_client, args)
    http_request.assert_called_with('POST', '/issues/1/watchers.json', params={'user_id': '1'},
                                    headers={'Content-Type': 'application/json', 'X-Redmine-API-Key': True},
                                    empty_valid_codes=[200, 204, 201], return_empty_response=True)


def test_add_issue_watcher_command_invalid_issue_watcher_id(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-issue-watcher-add command is executed
    Then:
        - No issue id raises a DemistoException
    """
    from Redmine import add_issue_watcher_command
    from CommonServerPython import DemistoException
    args = {'issue_id': '-1', 'watcher_id': '-20'}
    http_request = mocker.patch.object(redmine_client, '_http_request')
    http_request.side_effect = DemistoException(
        "Invalid ID for one or more fields that request IDs. Please make sure all IDs are correct.")
    with pytest.raises(DemistoException) as e:
        add_issue_watcher_command(redmine_client, args)
    assert e.value.message == "Invalid ID for one or more fields that request IDs. Please make sure all IDs are correct."


def test_remove_issue_watcher_command(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-issue-watcher-remove command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import remove_issue_watcher_command
    http_request = mocker.patch.object(redmine_client, '_http_request')
    args = {'issue_id': '1', 'watcher_id': '1'}
    remove_issue_watcher_command(redmine_client, args)
    http_request.assert_called_with('DELETE', '/issues/1/watchers/1.json', headers={'Content-Type': 'application/json',
                                                                                    'X-Redmine-API-Key': True},
                                    empty_valid_codes=[200, 204, 201], return_empty_response=True)


def test_remove_issue_watcher_command_response(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-issue-watcher-remove command is executed
    Then:
        - The http request returns the right response
    """
    from Redmine import remove_issue_watcher_command
    remove_issue_watcher_request_mock = mocker.patch.object(redmine_client, 'remove_issue_watcher_request')
    remove_issue_watcher_request_mock.return_value = {}
    args = {'issue_id': '1', 'watcher_id': '1'}
    result = remove_issue_watcher_command(redmine_client, args)
    assert result.readable_output == "Watcher with id 1 was removed successfully from issue with id 1."


def test_remove_issue_watcher_command_invalid_issue_watcher_id(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-issue-watcher-remove command is executed
    Then:
        - No issue id raises a DemistoException
    """
    from Redmine import remove_issue_watcher_command
    from CommonServerPython import DemistoException
    args = {'issue_id': '-1', 'watcher_id': '-20'}
    http_request = mocker.patch.object(redmine_client, '_http_request')
    http_request.side_effect = DemistoException(
        "Invalid ID for one or more fields that request IDs. Please make sure all IDs are correct.")
    with pytest.raises(DemistoException) as e:
        remove_issue_watcher_command(redmine_client, args)
    assert e.value.message == "Invalid ID for one or more fields that request IDs. Please make sure all IDs are correct."


def test_get_project_list_command(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-project-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import get_project_list_command
    http_request = mocker.patch.object(redmine_client, '_http_request')
    http_request.return_value = {"projects": [{"id": "1", "status": "active", "is_public": "true"}]}
    args = {'include': 'time_entry_activities'}
    get_project_list_command(redmine_client, args)
    http_request.assert_called_with('GET', '/projects.json', params={'include': 'time_entry_activities'},
                                    headers={'X-Redmine-API-Key': True})


def test_get_project_list_command_response(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-project-list command is executed
    Then:
        - The http request returns the right response
    """
    from Redmine import get_project_list_command
    get_project_list_request_mock = mocker.patch.object(redmine_client, 'get_project_list_request')
    get_project_list_request_mock.return_value = {"projects": [{"id": "1", "name": "testProject", "issue_custom_fields":
                                                                {"id": "1", "name": "custom"}, "status": "open",
                                                                "is_public": True}]}
    args = {"include": "issue_custom_fields"}
    result = get_project_list_command(redmine_client, args)
    assert result.readable_output == ("### Projects List:\n|Id|Name|Status|IsPublic|IssueCustomFields|\n|---|---|---|---|---|"
                                      "\n| 1 | testProject | open | True | ***id***: 1<br>***name***: custom |\n")


def test_get_project_list_command_invalid_include(redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-project-list command is executed
    Then:
        - No issue id raises a DemistoException
    """
    from Redmine import get_project_list_command
    from CommonServerPython import DemistoException
    args = {'include': 'time_entry_activities,jissue_categories'}
    with pytest.raises(DemistoException) as e:
        get_project_list_command(redmine_client, args)
    assert e.value.message == ("The 'include' argument should only contain values from ['trackers', 'issue_categories', "
                               "'enabled_modules', 'time_entry_activities', 'issue_custom_fields'], separated by commas."
                               " These values are not in options {'jissue_categories'}.")


def test_get_project_list_command_invalid_response(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-user-id-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import get_project_list_command
    from CommonServerPython import DemistoException
    args = {'status_id': 'open'}
    mocker.patch.object(Client, 'get_project_list_request', return_value={'projectsss': {}})
    with pytest.raises(DemistoException) as e:
        get_project_list_command(redmine_client, args)
    assert e.value.message == "The request succeeded, but a parse error occurred."


def test_get_custom_fields_command(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-custom-field-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import get_custom_fields_command
    http_request = mocker.patch.object(redmine_client, '_http_request')
    http_request.return_value = {"custom_fields": [{"id": "1", "is_required": True, "is_filter": False}]}
    get_custom_fields_command(redmine_client, {})
    http_request.assert_called_with('GET', '/custom_fields.json', headers={'X-Redmine-API-Key': True})


def test_get_custom_fields_command_response(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-custom-field-list command is executed
    Then:
        - The http request returns the right response
    """
    from Redmine import get_custom_fields_command
    get_custom_fields_request_mocker = mocker.patch.object(redmine_client, 'get_custom_fields_request')
    get_custom_fields_request_mocker.return_value = {"custom_fields": [{"id": "1", "name": "custom_test", "is_required": False,
                                                                       "is_filter": True, "trackers": {"name": "Bug", "id": "1"}
                                                                        }
                                                                       ]
                                                     }
    result = get_custom_fields_command(redmine_client, {})
    assert result.readable_output == ("### Custom Fields List:\n|Id|Name|IsRequired|IsFilter|Trackers|\n|---|---|---|---|---|\n"
                                      "| 1 | custom_test | False | True | ***name***: Bug<br>***id***: 1 |\n")


def test_get_custom_fields_command_invalid_response(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-custom-field-list command is executed
    Then:
        - raises a response format error
    """
    from Redmine import get_custom_fields_command
    from CommonServerPython import DemistoException
    get_custom_fields_request_mocker = mocker.patch.object(redmine_client, 'get_custom_fields_request')
    get_custom_fields_request_mocker.return_value = {"custom_fieldsss": [{"id": "1", "name": "custom_test", "is_required": False,
                                                                         "is_filter": True, "trackers": {"name": "Bug", "id": "1"}
                                                                          }
                                                                         ]
                                                     }
    args = {}
    with pytest.raises(DemistoException) as e:
        get_custom_fields_command(redmine_client, args)
    assert e.value.message == "The request succeeded, but a parse error occurred."


def test_get_users_command(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-user-id-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import get_users_command
    http_request = mocker.patch.object(redmine_client, '_http_request')
    get_users_command(redmine_client, {'status': 'Active'})
    http_request.assert_called_with('GET', '/users.json', params={'status': '1'}, headers={'X-Redmine-API-Key': True})


def test_get_users_command_response(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-user-id-list command is executed
    Then:
        - The http request returns rhe right response
    """
    from Redmine import get_users_command
    get_users_request_mock = mocker.patch.object(redmine_client, 'get_users_request')
    get_users_request_mock.return_value = {"users": [{"id": "1", "login": "admin", "admin": True, "firstname": "test",
                                                      "lastname": "response"}]}
    result = get_users_command(redmine_client, {})
    assert result.readable_output == ("### Users List:\n|Id|Login|Admin|Firstname|Lastname|\n|---|---|---|---|---|\n"
                                      "| 1 | admin | True | test | response |\n")


def test_get_users_command_invalid_response(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-user-id-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import get_users_command
    from CommonServerPython import DemistoException
    args = {'status_id': 'open'}
    mocker.patch.object(Client, 'get_users_request', return_value={'usersss': {}})
    # Execute and assert
    with pytest.raises(DemistoException) as e:
        get_users_command(redmine_client, args)
    assert str(e.value) == "The request succeeded, but a parse error occurred."


def test_get_users_command_status_invalid(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-user-id-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import get_users_command
    from CommonServerPython import DemistoException
    with pytest.raises(DemistoException) as e:
        get_users_command(redmine_client, {'status': 'hbvkbk'})
    assert e.value.message == "Invalid status value- please use the predefined options only."


''' HELPER FUNCTIONS TESTS '''


@pytest.mark.parametrize('page_size, page_number, expected_output',
                         [(1, 10, '#### Showing 1 results from page 10:\n')])
def test_create_paging_header(page_size, page_number, expected_output):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - redmine-user-id-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import create_paging_header
    assert create_paging_header(page_size, page_number) == expected_output


@pytest.mark.parametrize('args, expected_output',
                         [({'page_number': '2', 'page_size': '20'}, (20, 20, 2))])
def test_adjust_paging_to_request(args, expected_output):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - adjust_paging_to_request function is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import adjust_paging_to_request
    assert adjust_paging_to_request(args['page_number'], args['page_size'], None) == expected_output


def test_convert_args_to_request_format():
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - convert_args_to_request_format command is executed
    Then:
        - The key or value is being converted
    """
    from Redmine import convert_args_to_request_format
    args = {'tracker_id': 'Bug'}
    convert_args_to_request_format(args)
    assert args['tracker_id'] == '1'


def test_convert_args_to_request_format_invalid():
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - convert_args_to_request_format command is executed
    Then:
        - raises prriority_id is invalid
    """
    from CommonServerPython import DemistoException
    from Redmine import convert_args_to_request_format
    args = {'priority_id': 'lknljkl'}
    with pytest.raises(DemistoException) as e:
        convert_args_to_request_format(args)
    assert e.value.message == "Predefined value for priority_id is not in format."
