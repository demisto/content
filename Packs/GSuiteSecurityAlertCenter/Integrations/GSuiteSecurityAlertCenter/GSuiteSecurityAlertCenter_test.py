import json
import pytest

from GSuiteSecurityAlertCenter import MESSAGES, GSuiteClient, DemistoException
from unittest.mock import patch


def get_data_from_file(filepath):
    """
    Returns data of specified file.

    :param filepath: absolute or relative path of file
    """
    with open(filepath) as f:
        return f.read()


TEST_JSON = get_data_from_file('test_data/service_account_json.json')
MOCKER_HTTP_METHOD = 'GSuiteApiModule.GSuiteClient.http_request'
PARAMS = {
    'user_service_account_json': TEST_JSON,
    'admin_email': 'user@test.io'
}


@pytest.fixture
def gsuite_client():
    headers = {
        'Content-Type': 'application/json'
    }
    return GSuiteClient(GSuiteClient.safe_load_non_strict_json(TEST_JSON), verify=False, proxy=False, headers=headers)


def test_test_function(mocker, gsuite_client):
    """
    Scenario: Call to test-module should return 'ok' if API call succeeds.

    Given:
    - client object

    When:
    - Calling test function.

    Then:
    - Ensure 'ok' should be return.
    """
    from GSuiteSecurityAlertCenter import test_module, GSuiteClient, service_account
    mocker.patch.object(GSuiteClient, 'set_authorized_http')
    mocker.patch.object(GSuiteClient, 'http_request')
    mocker.patch.object(service_account.Credentials, 'refresh')
    gsuite_client.credentials.token = True
    assert test_module(gsuite_client, {}, {}) == 'ok'


def test_test_function_error(mocker, gsuite_client):
    """
    Scenario: Call to test-module should return error message.

    Given:
    - client object

    When:
    - Calling test function.

    Then:
    - Ensure message should be as expected.
    """
    from GSuiteSecurityAlertCenter import test_module, GSuiteClient, service_account
    mocker.patch.object(GSuiteClient, 'set_authorized_http')
    mocker.patch.object(GSuiteClient, 'http_request')
    mocker.patch.object(service_account.Credentials, 'refresh')
    gsuite_client.credentials.token = None
    with pytest.raises(DemistoException, match=MESSAGES['TEST_CONNECTIVITY_FAILED_ERROR']):
        test_module(gsuite_client, {}, {})


def test_validate_params_for_fetch_incidents_error():
    """
    Scenario: Parameters provided for fetch-incidents.

    Given:
    - Configuration parameters.

    When:
    - Calling validate_params_for_fetch_incidents with parameters.

    Then:
    - Ensure parameters validation.
    """
    from GSuiteSecurityAlertCenter import validate_params_for_fetch_incidents
    params = {
        'isFetch': True,
        'max_fetch': 'abc',
        'admin_email': 'hello',
    }

    with pytest.raises(ValueError, match=MESSAGES['MAX_INCIDENT_ERROR']):
        validate_params_for_fetch_incidents(params, {})


def test_prepare_args_for_invalid_args():
    """
    Tests prepare_args function.

    Should raise exception for invalid argument.
    """
    from GSuiteSecurityAlertCenter import validate_params_for_list_alerts
    args = {
        'page_size': -1,
        'filter': "createTime >= '2020-10-28T20:43:34.381Z' AND type='Suspicious login'"
    }
    with pytest.raises(Exception, match=MESSAGES['INTEGER_ERROR'].format('page_size')):
        validate_params_for_list_alerts(args)

    args.pop('page_size')
    params = validate_params_for_list_alerts(args)
    assert params['filter'] == 'createTime >= "2020-10-28T20:43:34.381Z" AND type="Suspicious login"'


def test_create_custom_context_for_batch_command():
    """
    Tests create_custom_context_for_batch_command function.

    Should return proper custom context response.
    """
    from GSuiteSecurityAlertCenter import create_custom_context_for_batch_command
    input_data = {
        "successAlertIds": [
            "dummy_alertId1"
        ],
        "failedAlertStatus": {
            "dummy_alertId2": {
                "code": 5,
                "message": "NOT_FOUND"
            }
        }
    }

    expected_data_success = [
        {
            "id": "dummy_alertId1"
        }
    ],
    expected_data_failed = [
        {
            "id": "dummy_alertId2",
            "code": 5,
            "message": "NOT_FOUND"
        }
    ]

    output_data = create_custom_context_for_batch_command(input_data)
    assert expected_data_success, expected_data_failed == output_data


def test_prepare_hr_for_batch_command():
    """
    Tests prepare_hr_for_batch_delete_command function.

    Should return proper hr response.
    """
    from GSuiteSecurityAlertCenter import prepare_hr_for_batch_command
    input_data = {
        "successAlertIds": [
            "dummy_alertId1"
        ],
        "failedAlertStatus": {
            "dummy_alertId2": {
                "code": 5,
                "message": "NOT_FOUND"
            }
        }
    }

    expected_data = "### Delete Alerts\n" \
                    "|Alert ID|Status|\n|---|---|" \
                    "\n| dummy_alertId1 | Success |\n| dummy_alertId2 | Fail (NOT_FOUND) |\n"

    output_data = prepare_hr_for_batch_command(input_data, 'Delete Alerts')
    assert expected_data == output_data


@patch(MOCKER_HTTP_METHOD)
def test_gsac_list_alerts_command_success(mocker_http_request, gsuite_client):
    """
    Scenario: For gsac_list_alerts command successful run.

    Given:
    - Command args.

    When:
    - Calling gsac_list_alerts command with the parameters provided.

    Then:
    - Ensure command's  raw_response, outputs and readable_output should be as expected.
    """
    from GSuiteSecurityAlertCenter import gsac_list_alerts_command

    with open('test_data/list_alert_response.json') as data:
        mock_response = json.load(data)

    with open('test_data/list_alert_context.json') as data:
        expected_res = json.load(data)

    with open('test_data/list_alert.md') as data:
        expected_hr = data.read()

    mocker_http_request.return_value = mock_response
    args = {'admin_email': 'user@test.com'}

    result = gsac_list_alerts_command(gsuite_client, args)

    assert result.raw_response == mock_response
    assert result.outputs == expected_res
    assert result.readable_output == expected_hr


@patch(MOCKER_HTTP_METHOD)
def test_gsac_list_alerts_command_with_empty_response(mocker_http_request, gsuite_client):
    """
    Scenario: For gsac_list_alerts returns message for empty response.

    Given:
    - Command args.

    When:
    - Calling gsac_list_alerts command with the parameters provided.

    Then:
    - Ensure command's readable_output should be as expected.
    """
    from GSuiteSecurityAlertCenter import gsac_list_alerts_command

    mocker_http_request.return_value = {}
    args = {'admin_email': 'user@test.com'}

    result = gsac_list_alerts_command(gsuite_client, args)

    assert result.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('alert(s)')


@patch(MOCKER_HTTP_METHOD)
def test_gsac_list_alerts_command_wrong_argument(mocker_http_request, gsuite_client):
    """
    Scenario: Wrong argument given gsac_list_alerts command.

    Given:
    - Command args.

    When:
    - Calling gsac_list_alerts command with the parameters provided.

    Then:
    - Ensure command should raise Exception as expected.
    """
    from GSuiteSecurityAlertCenter import gsac_list_alerts_command
    message = "message"
    mocker_http_request.side_effect = Exception(message)
    args = {'page_token': '1', 'admin_email': 'user@test.comm'}
    with pytest.raises(Exception, match=message):
        gsac_list_alerts_command(gsuite_client, args)


@patch(MOCKER_HTTP_METHOD)
def test_gsac_get_alert_command_success(mocker_http_request, gsuite_client):
    """
    Scenario: For gsac-get-alert command successful run.

    Given:
    - Command args.

    When:
    - Calling gsac-get-alert command with the parameters provided.

    Then:
    - Ensure command's  raw_response, outputs and readable_output should be as expected.
    """
    from GSuiteSecurityAlertCenter import gsac_get_alert_command

    with open('test_data/get_alert_response.json') as data:
        mock_response = json.load(data)

    with open('test_data/get_alert_context.json') as data:
        expected_res = json.load(data)

    with open('test_data/get_alert.md') as data:
        expected_hr = data.read()

    mocker_http_request.return_value = mock_response
    args = {'alert_id': 'demoId'}

    result = gsac_get_alert_command(gsuite_client, args)

    assert result.raw_response == mock_response
    assert result.outputs == expected_res
    assert result.readable_output == expected_hr


@patch(MOCKER_HTTP_METHOD)
def test_gsac_get_alert_command_with_empty_response(mocker_http_request, gsuite_client):
    """
    Scenario: For gsac-get-alert returns message for empty response.

    Given:
    - Command args.

    When:
    - Calling gsac-get-alert command with the parameters provided.

    Then:
    - Ensure command's  readable_output should be as expected.
    """
    from GSuiteSecurityAlertCenter import gsac_get_alert_command

    mocker_http_request.return_value = {}
    args = {'alert_id': 'demoId'}

    result = gsac_get_alert_command(gsuite_client, args)

    assert result.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('alert')


def test_gsac_get_alert_command_wrong_argument(gsuite_client):
    """
    Scenario: Wrong argument given gsac-get-alert command.

    Given:
    - Command args.

    When:
    - Calling gsac-get-alert command with the parameters provided.

    Then:
    - Ensure command should raise Exception as expected.
    """
    from GSuiteSecurityAlertCenter import gsac_get_alert_command
    args = {'alert_id': 'demo_id'}
    with pytest.raises(Exception):
        gsac_get_alert_command(gsuite_client, args)


@patch(MOCKER_HTTP_METHOD)
def test_gsac_create_alert_feedback_command_success(mocker_http_request, gsuite_client):
    """
    Scenario: For gsac_create_alert_feedback command successful run.

    Given:
    - Command args.

    When:
    - Calling gsac_create_alert_feedback command with the parameters provided.

    Then:
    - Ensure command's  raw_response, outputs and readable_output should be as expected.
    """
    from GSuiteSecurityAlertCenter import gsac_create_alert_feedback_command

    with open('test_data/create_alert_feedback_response.json') as data:
        mock_response = json.load(data)

    with open('test_data/create_alert_feedback_response.json') as data:
        expected_res = json.load(data)

    with open('test_data/create_alert_feedback.md') as data:
        expected_hr = data.read()

    mocker_http_request.return_value = mock_response
    args = {'feedback_type': 'NOT_USEFUL', 'alert_id': 'dummy_alertId'}

    result = gsac_create_alert_feedback_command(gsuite_client, args)

    assert result.raw_response == mock_response
    assert result.outputs == expected_res
    assert result.readable_output == expected_hr


@patch(MOCKER_HTTP_METHOD)
def test_gsac_create_alert_feedback_command_wrong_argument(mocker_http_request, gsuite_client):
    """
    Scenario: Wrong argument given gsac_create_alert_feedback command.

    Given:
    - Command args.

    When:
    - Calling gsac_create_alert_feedback command with the parameters provided.

    Then:
    - Ensure command should raise Exception as expected.
    """
    from GSuiteSecurityAlertCenter import gsac_create_alert_feedback_command
    message = MESSAGES['INVALID_FEEDBACK_TYPE_ERROR']
    mocker_http_request.side_effect = Exception(message)
    args = {'feedback_type': 'dummy', 'alert_id': 'dummy alertId'}
    with pytest.raises(Exception, match=message):
        gsac_create_alert_feedback_command(gsuite_client, args)


@patch(MOCKER_HTTP_METHOD)
def test_gsac_batch_delete_alerts_command_success(mocker_http_request, gsuite_client):
    """
    Scenario: For gsac_get_batch_delete_alerts command successful run.

    Given:
    - Command args.

    When:
    - Calling gsac_get_batch_delete_alerts command with the parameters provided.

    Then:
    - Ensure command's  raw_response, outputs and readable_output should be as expected.
    """
    from GSuiteSecurityAlertCenter import gsac_batch_delete_alerts_command

    with open('test_data/batch_delete_alerts_raw_response.json') as data:
        mock_response = json.load(data)

    with open('test_data/batch_delete_alerts_context.json') as data:
        expected_res = json.load(data)

    with open('test_data/batch_delete_alerts.md') as data:
        expected_hr = data.read()

    mocker_http_request.return_value = mock_response
    args = {'alert_id': 'dummy_alertId1,dummy_alertId2'}

    result = gsac_batch_delete_alerts_command(gsuite_client, args)

    assert result.raw_response == mock_response
    assert result.outputs == expected_res
    assert result.readable_output == expected_hr


@patch(MOCKER_HTTP_METHOD)
def test_gsac_batch_recover_alerts_command_success(mocker_http_request, gsuite_client):
    """
    Scenario: For gsac_get_batch_recover_alerts command successful run.

    Given:
    - Command args.

    When:
    - Calling gsac_get_batch_recover_alerts command with the parameters provided.

    Then:
    - Ensure command's  raw_response, outputs and readable_output should be as expected.
    """
    from GSuiteSecurityAlertCenter import gsac_batch_recover_alerts_command

    with open('test_data/batch_recover_alerts_raw_response.json') as data:
        mock_response = json.load(data)

    with open('test_data/batch_recover_alerts_context.json') as data:
        expected_res = json.load(data)

    with open('test_data/batch_recover_alerts.md') as data:
        expected_hr = data.read()

    mocker_http_request.return_value = mock_response
    args = {'alert_id': 'dummy_alertId1,dummy_alertId2'}

    result = gsac_batch_recover_alerts_command(gsuite_client, args)

    assert result.raw_response == mock_response
    assert result.outputs == expected_res
    assert result.readable_output == expected_hr


@patch(MOCKER_HTTP_METHOD)
def test_gsac_list_alert_feedback_command_success(mocker_http_request, gsuite_client):
    """
    Scenario: For gsac_list_alert_feedback command successful run.

    Given:
    - Command args.

    When:
    - Calling gsac_list_alert_feedback command with the parameters provided.

    Then:
    - Ensure command's  raw_response, outputs and readable_output should be as expected.
    """
    from GSuiteSecurityAlertCenter import gsac_list_alert_feedback_command

    with open('test_data/list_alert_feedback_response.json') as data:
        mock_response = json.load(data)

    with open('test_data/list_alert_feedback_context.json') as data:
        expected_res = json.load(data)

    with open('test_data/list_alert_feedback.md') as data:
        expected_hr = data.read()

    mocker_http_request.return_value = mock_response
    args = {'alert_id': 'dummy_alertId_1'}

    result = gsac_list_alert_feedback_command(gsuite_client, args)

    assert result.raw_response == mock_response
    assert result.outputs == expected_res
    assert result.readable_output == expected_hr


@patch(MOCKER_HTTP_METHOD)
def test_gsac_list_alert_feedback_command_with_empty_response(mocker_http_request, gsuite_client):
    """
    Scenario: For gsac_list_alert_feedback returns message for empty response.

    Given:
    - Command args.

    When:
    - Calling gsac_list_alert_feedback command with the parameters provided.

    Then:
    - Ensure command's  readable_output should be as expected.
    """
    from GSuiteSecurityAlertCenter import gsac_list_alert_feedback_command

    mocker_http_request.return_value = {}
    args = {'alert_id': 'demoId'}

    result = gsac_list_alert_feedback_command(gsuite_client, args)

    assert result.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('feedback(s)')


def test_validate_params_for_fetch_incidents():
    """
    Scenario: Parameters provided for fetch-incidents.

    Given:
    - Configuration parameters.

    When:
    - Calling validate_params_for_fetch_incidents with parameters.

    Then:
    - Ensure filter parameter validation.
    """
    from GSuiteSecurityAlertCenter import validate_params_for_fetch_incidents

    input = {
        'alert_type': ['Suspicious login', 'User spam spike'],
        'first_fetch': '3 days',
        'max_fetch': '1'
    }
    response, _ = validate_params_for_fetch_incidents(input, {})
    filter = response['filter'].split('AND')
    assert filter[1] == ' (type="Suspicious login" OR type="User spam spike")'


def test_fetch_incidents(gsuite_client, mocker):
    """
    Scenario: fetch_incidents called with valid arguments.

    Given:
    - Configuration parameters.

    When:
    - Calling fetch_incidents with parameters.

    Then:
    - Ensure successful execution of fetch_incidents.
    """
    from GSuiteSecurityAlertCenter import fetch_incidents
    params = {
        'filter': "type='Suspicious login'",
        'alert_type': 'Suspicious login',
        'first_fetch': '3 days',
        'max_fetch': '1',
        'admin_email': 'dummy'
    }
    with open('test_data/fetch_incidents_alert_response.json') as file:
        fetch_incidents_response = json.load(file)

    with open('test_data/fetch_incidents_output.json') as file:
        fetch_incidents_output = json.load(file)

    mocker.patch("demistomock.info", return_value=True)
    mocker.patch(MOCKER_HTTP_METHOD, return_value=fetch_incidents_response)
    fetch_incident = fetch_incidents(gsuite_client, {}, params)

    assert fetch_incident[0] == fetch_incidents_output['incidents']


def test_main_fetch_incidents(mocker):
    """
    Given working service integration
    When fetch-incidents is called from main()
    Then demistomock.incidents and demistomock.setLastRun should be called with respected values.

    :param args: Mocker objects.
    :return: None
    """
    from GSuiteSecurityAlertCenter import main, demisto
    with open('test_data/fetch_incidents_output.json') as file:
        fetch_incidents_output = json.load(file)
    mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch("demistomock.info", return_value=True)
    mocker.patch.object(demisto, 'params',
                        return_value={'user_service_account_json': TEST_JSON, 'max_incidents': 1,
                                      'first_fetch': '10 minutes', 'isFetch': True, 'user_id': 'hellod'})
    mocker.patch('GSuiteSecurityAlertCenter.fetch_incidents',
                 return_value=(fetch_incidents_output['incidents'], fetch_incidents_output['last_fetch']))
    main()

    demisto.incidents.assert_called_once_with(fetch_incidents_output['incidents'])
    demisto.setLastRun.assert_called_once_with(fetch_incidents_output['last_fetch'])
