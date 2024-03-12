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
        - redmine-issue-update command is executed
    Then:
        - The http request is called with the right arguments
    """
    from Redmine import create_issue_command
    http_request = mocker.patch.object(redmine_client, '_http_request')
    args = {'project_id': '1', 'issue_id': '1', 'subject': 'changeFromCode', 'tracker_id': 'Bug', 'watcher_user_ids': '[1]'}
    create_issue_command(redmine_client, args=args)
    http_request.assert_called_with('POST', '/issues.json', params={},
                                    json_data={'issue': {'issue_id': '1', 'subject': 'changeFromCode',
                                                         'tracker_id': '1', 'watcher_user_ids': [1], 'project_id': '1'}},
                                    headers={'Content-Type': 'application/json', 'X-Redmine-API-Key': True})


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
    assert e.value.message == ("Could not create a token for your file- "
                               "please try again.With error Could not upload file with entry id a.png.")


def test_create_issue_command_with_file(mocker, redmine_client):
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


def test_update_issue_command(mocker, redmine_client):
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
    args = {'issue_id': '1', 'subject': 'changeFromCode', 'tracker_id': 'Bug', 'watcher_user_ids': '[1]'}
    update_issue_command(redmine_client, args=args)
    http_request.assert_called_with('PUT', '/issues/1.json', json_data={'issue': {'subject': 'changeFromCode', 'tracker_id': '1',
                                                                                  'watcher_user_ids': [1]}}, headers={'Content-Type': 'application/json',
                                                                                                                      'X-Redmine-API-Key': True}, empty_valid_codes=[204], return_empty_response=True)


def test_update_issue_command_invalid_custom_fields(redmine_client):
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
    assert e.value.message == ("Could not create a token for your file- please try again."
                               "With error Could not upload file with entry id a.png.")


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


def test_get_issues_list_command_invalid_custom_field(mocker, redmine_client):
    """
    Given:
        - All relevant arguments for the command that is executed with asset id
    When:
        - redmine-issue-list command is executed
    Then:
        - Raises an exception
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
        - Raises an exception
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
    args = {'issue_id': '1', 'include': 'watchers,attachments'}
    get_issue_by_id_command(redmine_client, args)
    http_request.assert_called_with('GET', '/issues/1.json',
                                    params={'include': 'watchers,attachments'}, headers={'X-Redmine-API-Key': True})


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
    assert e.value.message == "The 'include' argument should only contain values from ['children', 'attachments', 'relations', 'changesets', 'journals', 'watchers', 'allowed_statuses'], separated by commas. These values are not in options {'beikbfqi'}."


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
    args = {'include': 'time_entry_activities'}
    get_project_list_command(redmine_client, args)
    http_request.assert_called_with('GET', '/projects.json', params={'include': 'time_entry_activities'},
                                    headers={'X-Redmine-API-Key': True})


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


def test_get_project_list_command_response(mocker, redmine_client):
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
    # Execute and assert
    with pytest.raises(DemistoException) as e:
        get_project_list_command(redmine_client, args)
    assert str(e.value) == "Request Succeeded, Response not in correct format."


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
    get_custom_fields_command(redmine_client, {})
    http_request.assert_called_with('GET', '/custom_fields.json', headers={'X-Redmine-API-Key': True})


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
    assert str(e.value) == "Request Succeeded, Response not in correct format."


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


@pytest.mark.parametrize('header_name, expected_output',
                         [('id', '#### Showing 1 results from page 10:\n')])
def test_map_header(header_name, expected_output):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - map_header command is executed
    Then:
        - The header is being converted
    """
    from Redmine import map_header
    assert map_header(header_name) == 'ID'


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
    args = {}
    convert_args_to_request_format('Bug', None, None, None, args)
    assert args['tracker_id'] == '1'
