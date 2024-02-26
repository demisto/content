import pytest

from Redmine import Client
# from test_data import input_data


@pytest.fixture
def redmine_client(url: str = 'url', verify_certificate: bool = True, proxy: bool = False, auth=('username', 'password')):
    return Client(url, verify_certificate, proxy, auth=auth)


''' COMMAND FUNCTIONS TESTS '''


def test_create_issue_command_without_file(mocker, redmine_client):
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
    args = {'status_id': '1', 'priority_id': '1', 'subject': 'newSubject', 'project_id': '1'}
    create_issue_command(redmine_client, args=args)
    http_request.assert_called_with('POST', '/issues.json', params={'status_id': '1', 'priority_id': '1', 'project_id': '1'},
                                    json_data={'issue': {'subject': 'newSubject'}}, headers={'Content-Type': 'application/json'})


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
    create_file_token_request_mock = mocker.patch.object(redmine_client, 'create_file_token_request')
    create_file_token_request_mock.return_value = {'upload': {'token': 'token123'}}
    http_request = mocker.patch.object(redmine_client, '_http_request')
    args = {'entry_id': 'a.png', 'status_id': '1', 'priority_id': '1', 'subject': 'newSubject', 'project_id': '1'}
    create_issue_command(redmine_client, args=args)
    create_file_token_request_mock.assert_called_with({}, 'a.png')
    http_request.assert_called_with('POST', '/issues.json',
                                    params={'entry_id': 'a.png', 'status_id': '1', 'priority_id': '1', 'project_id': '1'},
                                    json_data={'issue': {'subject': 'newSubject', 'uploads': [{'token': 'token123'}]}},
                                    headers={'Content-Type': 'application/json'})


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
    args = {'issue_id': '1', 'subject': 'changeFromCode', 'tracker_id': '1', 'watcher_user_ids': '[1]'}
    update_issue_command(redmine_client, args=args)
    http_request.assert_called_with('PUT', '/issues/1.json', json_data={'issue': {'subject': 'changeFromCode',
                                                                                  'tracker_id': '1', 'watcher_user_ids': '[1]'}}, headers={'Content-Type': 'application/json'})


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
    args = {'entry_id': 'a.png', 'issue_id': '1', 'subject': 'changeFromCode', 'tracker_id': '1', 'watcher_user_ids': '[1]'}
    update_issue_command(redmine_client, args=args)
    create_file_token_request_mock.assert_called_with({}, 'a.png')
    http_request.assert_called_with('PUT', '/issues/1.json', json_data={'issue': {'subject': 'changeFromCode',
                                    'tracker_id': '1', 'watcher_user_ids': '[1]', 'uploads':
                                                                                  [{'token': 'token123', 'file_name': '', 'description': '',
                                                                                   'content_type': ''}]}}, headers={'Content-Type': 'application/json'})


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
    http_request.assert_called_with('GET', '/issues.json', params={'offset': 0, 'limit': '1', 'sort': 'priority:desc'},
                                    headers={})


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
    args = {'issue_id': '1', 'include': ['watchers', 'attachments']}
    get_issue_by_id_command(redmine_client, args)
    http_request.assert_called_with('GET', '/issues/1.json', params={'include': 'watchers,attachments'},
                                    headers={'Content-Type': 'application/json'})


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
    http_request.assert_called_with('DELETE', '/issues/41.json', headers={'Content-Type': 'application/json'})


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
                                    headers={'Content-Type': 'application/json'})


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
    http_request.assert_called_with('DELETE', '/issues/1/watchers/1.json', headers={'Content-Type': 'application/json'})


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
    http_request.assert_called_with('GET', '/projects.json', params={'include': 'time_entry_activities'}, headers={})


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
    get_custom_fields_command(redmine_client)
    http_request.assert_called_with('GET', '/custom_fields.json', headers={})


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
    args = {'name': 'Redmine', 'status': '1'}
    get_users_command(redmine_client, args)
    http_request.assert_called_with('GET', 'users.json', params={'name': 'Redmine', 'status': '1'}, headers={})


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
