import json
from unittest.mock import patch

import pytest

from GoogleCalendar import MESSAGES, OUTPUT_PREFIX, GSuiteClient

with open('test_data/service_account_json.txt') as f:
    TEST_JSON = f.read()

MOCKER_HTTP_METHOD = 'GSuiteApiModule.GSuiteClient.http_request'


@pytest.fixture
def gsuite_client():
    headers = {
        'Content-Type': 'application/json'
    }
    return GSuiteClient(GSuiteClient.safe_load_non_strict_json(TEST_JSON), verify=False, proxy=False, headers=headers)


def test_main(mocker):
    """
    Scenario: Main should initialize Client class and called command respectively.

    Given:
    - params and args.

    When:
    - Initializing Client with the parameters provided and calling respective command.

    Then:
    - Ensure results is returned from command function.
    """
    from GoogleCalendar import demisto
    import GoogleCalendar
    params = {
        'user_service_account_json': TEST_JSON,

    }
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(GoogleCalendar, 'test_module', return_value='ok')
    GoogleCalendar.main()
    assert GoogleCalendar.test_module.called


@patch('GoogleCalendar.return_error')
def test_main_failure(mock_return_error, capfd, mocker):
    """
    Scenario: Main should handle error while initializing Client class and called command respectively.

    Given:
    - params and args.

    When:
    - Initializing Client with the parameters provided and calling respective command.

    Then:
    - Ensure exception is raised.
    """
    import GoogleCalendar
    params = {
        'user_service_account_json': TEST_JSON,

    }
    mocker.patch.object(GoogleCalendar.demisto, 'params', return_value=params)
    mocker.patch.object(GoogleCalendar.demisto, 'command', return_value='test-module')
    mocker.patch.object(GoogleCalendar, 'test_module', side_effect=Exception)
    with capfd.disabled():
        GoogleCalendar.main()

    mock_return_error.assert_called_once_with('Error: ')


def test_test_module(mocker, gsuite_client):
    """
    Scenario: Call to test-module should return 'ok' if API call succeeds.

    Given:
    - client object

    When:
    - Calling test module.

    Then:
    - Ensure 'ok' should be return.
    """
    from GoogleCalendar import test_module
    mocker.patch.object(GSuiteClient, 'set_authorized_http')
    mocker.patch.object(GSuiteClient, 'http_request')
    assert test_module(gsuite_client) == 'ok'


@patch(MOCKER_HTTP_METHOD)
def test_acl_add_command_success(mocker_http_request, gsuite_client):
    """
    Scenario: For google-calendar-acl-add command successful run.

    Given:
    - Command args.

    When:
    - Calling google-calendar-acl-add command with the parameters provided.

    Then:
    - Ensure command's  raw_response, outputs, readable_output, outputs_key_field, outputs_prefix should be as expected.
    """
    from GoogleCalendar import acl_add_command

    with open('test_data/acl_add_data.json', encoding='utf-8') as data:
        expected_res = json.load(data)
    mocker_http_request.return_value = expected_res['Contents']

    args = expected_res['args']
    result = acl_add_command(gsuite_client, args)

    assert result.raw_response == expected_res['Contents']
    assert result.outputs == expected_res['Outputs']
    assert result.readable_output == expected_res['HumanReadable']
    assert result.outputs_key_field == ['calendarId', 'id', 'userId']
    assert result.outputs_prefix == OUTPUT_PREFIX['ADD_ACL']


def test_acl_add_command_wrong_argument(gsuite_client):
    """
    Scenario: Wrong argument given google-calendar-acl-add command.

    Given:
    - Command args.

    When:
    - Calling google-calendar-acl-add command with the parameters provided.

    Then:
    - Ensure command should raise error as expected.
    """
    from GoogleCalendar import acl_add_command
    with open('test_data/acl_add_data.json', encoding='utf-8') as data:
        expected_res = json.load(data)
    args = expected_res['wrong_args']
    with pytest.raises(ValueError) as e:
        acl_add_command(gsuite_client, args)
    assert MESSAGES['BOOLEAN_ERROR'].format('send_notifications') == str(e.value)


@patch(MOCKER_HTTP_METHOD)
def test_acl_list_command_success(mocker_http_request, gsuite_client):
    """
    Scenario: For google-calendar-acl-list command successful run.

    Given:
    - Command args.

    When:
    - Calling google-calendar-acl-list command with the parameters provided.

    Then:
    - Ensure command's  raw_response, outputs and readable_output should be as expected.
    """
    from GoogleCalendar import acl_list_command

    with open('test_data/acl_list_data.json', encoding='utf-8') as data:
        expected_res = json.load(data)
    mocker_http_request.return_value = expected_res['Contents']

    args = expected_res['args']
    result = acl_list_command(gsuite_client, args)
    assert result.raw_response == expected_res['Contents']
    assert result.outputs == expected_res['EntryContext']
    assert result.readable_output == expected_res['HumanReadable']


def test_acl_list_command_wrong_argument():
    """
    Scenario: Wrong argument given google-calendar-acl-list command.

    Given:
    - Command args.

    When:
    - Calling google-calendar-acl-list command with the parameters provided.

    Then:
    - Ensure command should raise error as expected.
    """
    from GoogleCalendar import acl_list_command
    with open('test_data/acl_list_data.json', encoding='utf-8') as data:
        expected_res = json.load(data)
    args = expected_res['wrong_args']
    with pytest.raises(ValueError) as e:
        acl_list_command(gsuite_client, args)
    assert MESSAGES['BOOLEAN_ERROR'].format('show_deleted') == str(e.value)
