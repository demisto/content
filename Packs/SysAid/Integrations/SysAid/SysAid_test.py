import pytest
from unittest.mock import patch

from SysAid import Client

COOKIES = 'cookies'


@pytest.fixture
@patch('SysAid.Client._get_cookies')
def sysaid_client(mocker_get_cookies):
    mocker_get_cookies.return_value = COOKIES
    return Client(server_url='https://url/api/v1', verify=False, proxy=False, auth=('username', 'password'))


''' COMMAND FUNCTIONS TESTS '''


def test_table_list_command_with_list_id(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed with list id
    When:
        - sysaid-table-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import table_list_command
    http_request = mocker.patch.object(sysaid_client, '_http_request')
    args = {'list_id': 'known_error'}
    table_list_command(sysaid_client, args)
    http_request.assert_called_with('GET', 'list/known_error', params={}, cookies=COOKIES)


def test_table_list_command_no_list_id(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed without list id
    When:
        - sysaid-table-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import table_list_command
    http_request = mocker.patch.object(sysaid_client, '_http_request')
    args = {}
    table_list_command(sysaid_client, args)
    http_request.assert_called_with('GET', 'list', params={}, cookies=COOKIES)


def test_asset_list_command_with_asset_id(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed with asset id
    When:
        - sysaid-asset-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import asset_list_command
    http_request = mocker.patch.object(sysaid_client, '_http_request')
    args = {'asset_id': '0A-3E-E9-13-2B-E4', 'fields': 'all'}
    asset_list_command(sysaid_client, args)
    http_request.assert_called_with('GET', 'asset/0A-3E-E9-13-2B-E4', params={}, cookies=COOKIES)


def test_asset_list_command_no_asset_id(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed without asset id
    When:
        - sysaid-asset-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import asset_list_command
    http_request = mocker.patch.object(sysaid_client, '_http_request')
    args = {'fields': 'all'}
    asset_list_command(sysaid_client, args)
    http_request.assert_called_with('GET', 'asset', params={'limit': 100, 'offset': 0}, cookies=COOKIES)


def test_asset_search_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-asset-search command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import asset_search_command
    http_request = mocker.patch.object(sysaid_client, '_http_request')
    args = {'fields': 'all', 'query': 'Test'}
    asset_search_command(sysaid_client, args)
    http_request.assert_called_with('GET', 'asset/search', params={'limit': 100, 'offset': 0, 'query': 'Test'}, cookies=COOKIES)


def test_filter_list_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-filter-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import filter_list_command
    http_request = mocker.patch.object(sysaid_client, '_http_request')
    args = {'fields': 'all'}
    filter_list_command(sysaid_client, args)
    http_request.assert_called_with('GET', 'filters', params={}, cookies=COOKIES)


def test_user_list_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-user-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import user_list_command
    http_request = mocker.patch.object(sysaid_client, '_http_request')
    args = {'fields': 'all'}
    user_list_command(sysaid_client, args)
    http_request.assert_called_with('GET', 'users', params={'limit': 100, 'offset': 0}, cookies=COOKIES)


def test_user_search_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-user-search command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import user_search_command
    http_request = mocker.patch.object(sysaid_client, '_http_request')
    args = {'fields': 'all', 'query': 'dmst'}
    user_search_command(sysaid_client, args)
    http_request.assert_called_with('GET', 'users/search', params={'limit': 100, 'offset': 0, 'query': 'dmst'}, cookies=COOKIES)


def test_service_record_list_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-service-record-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import service_record_list_command
    http_request = mocker.patch.object(sysaid_client, '_http_request')
    args = {'fields': 'all', 'type': 'all'}
    service_record_list_command(sysaid_client, args)
    http_request.assert_called_with('GET', 'sr', params={'limit': 100, 'offset': 0, 'type': 'all'}, cookies=COOKIES)


def test_service_record_search_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-service-record-search command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import service_record_search_command
    http_request = mocker.patch.object(sysaid_client, '_http_request')
    args = {'fields': 'all', 'type': 'all', 'query': 'test'}
    service_record_search_command(sysaid_client, args)
    http_request.assert_called_with('GET', 'sr/search',
                                    params={'query': 'test', 'type': 'all', 'offset': 0, 'limit': 100}, cookies=COOKIES)


def test_service_record_update_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-service-record-update command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import service_record_update_command
    http_request = mocker.patch.object(sysaid_client, '_http_request')
    args = {'id': '6', 'status': '2'}
    service_record_update_command(sysaid_client, args)
    http_request.assert_called_with('PUT', 'sr/6', json_data={'id': '6', 'info': [{'key': 'status', 'value': '2'}]},
                                    cookies=COOKIES, resp_type='response')


def test_service_record_close_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-service-record-close command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import service_record_close_command
    http_request = mocker.patch.object(sysaid_client, '_http_request')
    args = {'id': '6', 'solution': 'Closing via API call'}
    service_record_close_command(sysaid_client, args)
    http_request.assert_called_with('PUT', 'sr/6/close', json_data={'solution': 'Closing via API call'},
                                    cookies=COOKIES, resp_type='response', ok_codes=(200, 400))


def test_service_record_template_get_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-service-record-template-get command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import service_record_template_get_command
    http_request = mocker.patch.object(sysaid_client, '_http_request')
    args = {'type': 'incident', 'fields': 'all'}
    service_record_template_get_command(sysaid_client, args)
    http_request.assert_called_with('GET', 'sr/template', params={'type': 'incident'}, cookies=COOKIES)


def test_service_record_create_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-service-record-create command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import service_record_create_command
    http_request = mocker.patch.object(sysaid_client, '_http_request')
    args = {'type': 'request', 'description': 'This is a test', 'title': 'Test SR from API', 'sr_type': '6', 'fields': 'all'}
    service_record_create_command(sysaid_client, args)
    http_request.assert_called_with('GET', 'sr/template', params={'type': 'request'}, json_data={
        'info': [{'key': 'description', 'value': 'This is a test'}, {'key': 'sr_type', 'value': '6'},
                 {'key': 'title', 'value': 'Test SR from API'}]}, cookies=COOKIES)


def test_service_record_delete_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-service-record-delete command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import service_record_delete_command
    http_request = mocker.patch.object(sysaid_client, '_http_request')
    args = {'ids': '2,32'}
    service_record_delete_command(sysaid_client, args)
    http_request.assert_called_with('DELETE', 'sr', params={'ids': '2,32'}, json_data={'solution': None}, cookies=COOKIES,
                                    resp_type='response', ok_codes=(200, 400))
