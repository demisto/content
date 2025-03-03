"""Ignite Test File."""
import io
import json
import os.path
from datetime import timedelta
from unittest.mock import patch

import pytest

import Ignite
from CommonServerPython import DemistoException, get_current_time, urllib
from Ignite import DATE_FORMAT, MESSAGES, URL_SUFFIX, Client, demisto, main, remove_space_from_args, OUTPUT_PREFIX, \
    MAX_PRODUCT, MAX_PAGE_SIZE, SORT_DATE_VALUES, SORT_ORDER_VALUES, FILTER_DATE_VALUES, IS_FRESH_VALUES, \
    MAX_FETCH_LIMIT, QUERY, MAX_ALERTS_LIMIT, ALERT_STATUS_VALUES, ALERT_ORIGIN_VALUES, OUTPUT_KEY_FIELD

""" CONSTANTS """

API_KEY = 'api_key'
MOCK_URL = "https://mock_dummy.com"
BASIC_PARAMS = {'url': MOCK_URL, 'credentials': {'password': API_KEY}}
CURRENT_TIME = get_current_time()
CURRENT_TIME_STRING = CURRENT_TIME.strftime(DATE_FORMAT)
CURRENT_TIME_PLUS_ONE = CURRENT_TIME + timedelta(days=1)
CURRENT_TIME_PLUS_ONE_STRING = CURRENT_TIME_PLUS_ONE.strftime(DATE_FORMAT)

MESSAGES.update({
    "NO_SERVER_URL_PROVIDED": "Please provide the Server URL.",
    "NO_CREDENTIALS_PROVIDED": "Please provide the API Key.",
})

""" UTILITY FUNCTIONS AND FIXTURES """


def util_load_json(path: str) -> dict:
    """Load a json to python dict."""
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def util_load_text_data(path: str) -> str:
    """Load a text file."""
    with io.open(path, mode='r', encoding='utf-8') as f:
        return f.read()


@pytest.fixture
def mock_client():
    """Mock a client object with required data to mock."""
    client = Client(MOCK_URL, {}, False, None, True)
    return client


""" TEST CASES """


def test_test_module(mock_client, requests_mock):
    """Test test_module."""
    from Ignite import test_module

    response = util_load_json('test_data/indicator_search_1.json')
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["INDICATOR_SEARCH"]}?limit=1',
                      json=response, status_code=200)

    assert test_module(client=mock_client) == 'ok'


@patch("Ignite.return_results")
def test_test_module_using_main_function(mock_return, requests_mock, mocker):
    """
    Test case scenario for successful execution of test_module through main function.

    Given:
       - mocked client
    When:
       - Calling `test_module` function
    Then:
       - Returns an ok message
    """
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}',
                      json={}, status_code=200)

    params = {**BASIC_PARAMS, 'isFetch': True}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')

    main()
    assert "ok" == mock_return.call_args.args[0]


@pytest.mark.parametrize('params, err_msg', [
    ({}, MESSAGES['NO_SERVER_URL_PROVIDED']),
    ({'url': ' '}, MESSAGES['NO_SERVER_URL_PROVIDED']),
    ({'url': ' url ', 'cluster_id': ' cluster_id '},
     MESSAGES['NO_CREDENTIALS_PROVIDED']),
    ({'url': ' url ', 'cluster_id': ' cluster_id ',
     'credentials': {}}, MESSAGES['NO_CREDENTIALS_PROVIDED']),
    ({'url': ' url ', 'cluster_id': ' cluster_id ', 'credentials': {
     'password': ' '}}, MESSAGES['NO_CREDENTIALS_PROVIDED']),
    ({**BASIC_PARAMS.copy(), 'isFetch': True,
      'first_fetch': CURRENT_TIME_PLUS_ONE_STRING},
     MESSAGES["INVALID_FETCH_TIME"].format(CURRENT_TIME_PLUS_ONE_STRING)),
    ({**BASIC_PARAMS.copy(), 'isFetch': True,
      'max_fetch': MAX_FETCH_LIMIT + 1},
     MESSAGES['INVALID_MAX_FETCH'].format(MAX_FETCH_LIMIT + 1)),
    ({**BASIC_PARAMS.copy(), 'isFetch': True, 'fetch_type': 'Alerts',
      'max_fetch': MAX_FETCH_LIMIT + 1},
     MESSAGES['INVALID_MAX_FETCH'].format(MAX_FETCH_LIMIT + 1)),
])
def test_test_module_when_invalid_params_provided(params, err_msg, mocker, capfd):
    """
    Test case scenario for execution of test_module when invalid argument provided.

    Given:
        - Params for test_module.
    When:
        - Calling `test_module` function.
    Then:
        - Returns a valid error message.
    """
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'exit', return_value=None)
    mocker.patch.object(demisto, 'command', return_value='test-module')

    return_error = mocker.patch.object(Ignite, "return_error")
    main()

    assert err_msg in return_error.call_args[0][0]


@pytest.mark.parametrize('status_code, err_msg', [
    (400, MESSAGES["INVALID_ARGUMENT_RESPONSE"]),
    (401, MESSAGES['INVALID_API_KEY']),
    (521, MESSAGES["TEST_CONNECTIVITY_FAILED"]),
    (403, MESSAGES["TEST_CONNECTIVITY_FAILED"]),
    (404, MESSAGES["NO_RECORD_FOUND"]),
])
def test_test_module_invalid_response(requests_mock, mock_client, status_code, err_msg):
    """
    Test case scenario for the execution of test_module with invalid response with the different status code.

    Given:
       - mocked client
    When:
       - Calling `test_module` function
    Then:
       - Returns exception
    """
    from Ignite import test_module

    response = {'message': 'invalid_response'}
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["INDICATOR_SEARCH"]}?limit=1',
                      json=response, status_code=status_code)

    with pytest.raises(DemistoException) as err:
        test_module(mock_client)

    err_msg = err_msg + response.get('message') if status_code == 400 else err_msg
    assert MESSAGES['STATUS_CODE'].format(status_code, err_msg) == str(err.value)


def test_test_module_invalid_json_response(requests_mock, mock_client):
    """
    Test case scenario for the execution of test_module with invalid json response.

    Given:
       - mocked client
    When:
       - Calling `test_module` function
    Then:
       - Returns exception
    """
    from Ignite import test_module

    response = 'invalid_response'
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["INDICATOR_SEARCH"]}?limit=1',
                      text=response, status_code=200)

    with pytest.raises(DemistoException) as err:
        test_module(mock_client)

    assert MESSAGES['STATUS_CODE'].format(
        200, MESSAGES['INVALID_JSON_OBJECT'].format(response)) == str(err.value)


def test_fetch_incidents_when_valid_incidents_return(mocker, mock_client, requests_mock):
    """
    Test case scenario for execution of fetch_incidents for fetch compromised credentials.

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Returns a valid command output.
    """
    from Ignite import fetch_incidents

    last_run = {}

    mock_response: dict = util_load_json('test_data/fetch_compromised_credentials.json')

    incidents_response = util_load_json('test_data/incidents_compromised_credentials.json')

    params: dict = {
        'fetch_type': '',
        'first_fetch': '2024-05-16T10:22:38Z',
        'is_fresh': 'true',
        'max_fetch': 1
    }
    demisto_params = {**BASIC_PARAMS, 'severity': 'Medium'}
    mocker.patch.object(demisto, 'params', return_value=demisto_params)

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response, status_code=200)
    next_run, incidents = fetch_incidents(client=mock_client, last_run=last_run, params=params)

    END_TIME = next_run.get('end_time')
    expected_next_run = {'fetch_count': 1, 'fetch_sum': 1, 'total': 31, 'end_time': END_TIME,
                         'last_time': '2021-03-31T19:42:05Z', 'hit_ids': ['sample_id_1'], 'last_timestamp': 1617219725,
                         'start_time': '2024-05-16T10:22:38Z'}

    assert incidents == incidents_response
    assert next_run == expected_next_run


def test_fetch_incidents_when_params_not_provided_and_last_run_provided(mocker, mock_client, requests_mock):
    """
    Test case scenario of fetch_incidents for fetch compromised credentials when params not provided and last run is provided.

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Returns a valid command output.
    """
    from Ignite import fetch_incidents

    last_run = {'fetch_count': 1,
                'start_time': '2024-05-16T10:22:38Z',
                'total': 31,
                'fetch_sum': 30,
                'end_time': '2024-05-30T19:42:05Z',
                'last_timestamp': 1617219726
                }

    expected_next_run = {'fetch_count': 0, 'start_time': '2021-03-31T19:42:05Z', 'total': None, 'fetch_sum': 0,
                         'end_time': '2024-05-30T19:42:05Z', 'last_time': '2021-03-31T19:42:05Z',
                         'hit_ids': ['sample_id_1'], 'last_timestamp': 1617219725}

    mock_response: dict = util_load_json('test_data/fetch_compromised_credentials.json')

    incidents_response = util_load_json('test_data/incidents_compromised_credentials.json')

    demisto_params = {**BASIC_PARAMS, 'severity': 'Medium'}
    mocker.patch.object(demisto, 'params', return_value=demisto_params)
    mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response, status_code=200)
    next_run, incidents = fetch_incidents(client=mock_client, last_run=last_run, params={'max_fetch': 201})

    assert incidents == incidents_response
    assert next_run == expected_next_run


def test_fetch_incidents_when_invalid_arguments_provided(mock_client):
    """
    Test case scenario for execution of fetch_incidents for fetch compromised credentials when invalid arguments provided.

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Raise error message.
    """
    from Ignite import fetch_incidents

    error_message = MESSAGES['INVALID_MAX_FETCH'].format('0')
    with pytest.raises(DemistoException) as error:
        fetch_incidents(client=mock_client, last_run={}, params={'max_fetch': 0})

    assert str(error.value) == error_message


def test_fetch_incidents_when_max_product_exceed_total_limit(mock_client, requests_mock):
    from Ignite import fetch_incidents

    mock_response: dict = util_load_json('test_data/fetch_incidents_with_check_max_product.json')

    error_message = MESSAGES['TIME_RANGE_ERROR'].format("10005")
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response, status_code=200)

    with pytest.raises(ValueError) as error:
        fetch_incidents(client=mock_client, last_run={'total': 10005}, params={})

    assert str(error.value) == error_message


def test_fetch_incidents_to_check_duplicates_compromised_credentials(mocker, mock_client, requests_mock):
    """
    Test case scenario for execution of fetch_incidents for fetch compromised credentials to check duplicate records in response.

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Returns a valid command output.
    """
    from Ignite import fetch_incidents

    last_run = {'fetch_count': 1,
                'start_time': '2024-05-16T10:22:38Z',
                'total': 31,
                'fetch_sum': 30,
                'end_time': '2024-05-30T19:42:05Z',
                'hit_ids': ['sample_id_2']
                }

    expected_next_run = {'fetch_count': 0, 'start_time': '2021-03-31T19:42:05Z', 'total': None, 'fetch_sum': 0,
                         'end_time': '2024-05-30T19:42:05Z', 'last_time': '2021-03-31T19:42:05Z',
                         'hit_ids': ['sample_id_1', 'sample_id_2'], 'last_timestamp': 1617219725}

    mock_response: dict = util_load_json('test_data/fetch_incidents_compromised_credentials_check_duplicate.json')

    incidents_response = util_load_json('test_data/incidents_compromised_credentials.json')

    demisto_params = {**BASIC_PARAMS, 'severity': 'Medium'}
    mocker.patch.object(demisto, 'params', return_value=demisto_params)

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response, status_code=200)
    next_run, incidents = fetch_incidents(client=mock_client, last_run=last_run, params={})

    assert incidents == incidents_response
    assert next_run == expected_next_run


def test_fetch_incidents_compromised_credentials_when_email_not_present(mocker, mock_client, requests_mock):
    """
     Test case scenario for execution of fetch_incidents for fetch compromised credentials when email not provided in response.

     Given:
         - mock client
     When:
         - Calling `fetch_incidents` function.
     Then:
         - Returns a valid command output.
     """
    from Ignite import fetch_incidents

    last_run = {'fetch_count': 1,
                'start_time': '2024-05-16T10:22:38Z',
                'total': 31,
                'fetch_sum': 30,
                'end_time': '2024-05-30T19:42:05Z',
                'last_timestamp': 1617219725,
                'hit_ids': []
                }

    expected_next_run = {'fetch_count': 0, 'start_time': '2021-03-31T19:42:05Z', 'total': None, 'fetch_sum': 0,
                         'end_time': '2024-05-30T19:42:05Z', 'last_time': '2021-03-31T19:42:05Z',
                         'hit_ids': ['sample_id_1'], 'last_timestamp': 1617219725}

    mock_response: dict = util_load_json('test_data/fetch_compromised_credentials.json')

    del mock_response['hits']['hits'][0]['_source']['email']
    incidents_response = util_load_json('test_data/incidents_compromised_credentials_when_email_not_present.json')

    demisto_params = {**BASIC_PARAMS, 'severity': 'Medium'}
    mocker.patch.object(demisto, 'params', return_value=demisto_params)
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response, status_code=200)
    next_run, incidents = fetch_incidents(client=mock_client, last_run=last_run, params={})

    assert incidents == incidents_response
    assert next_run == expected_next_run


def test_fetch_incidents_compromised_credentials_when_email_and_username_not_present(mocker, mock_client, requests_mock):
    """
     Test case scenario for execution of fetch_incidents for compromised credentials when email and username not present.

     Given:
         - mock client
     When:
         - Calling `fetch_incidents` function.
     Then:
         - Returns a valid command output.
     """
    from Ignite import fetch_incidents

    last_run = {'fetch_count': 1,
                'start_time': '2024-05-16T10:22:38Z',
                'total': 31,
                'fetch_sum': 30,
                'end_time': '2024-05-30T19:42:05Z',
                'last_timestamp': 1617219725,
                'hit_ids': []
                }

    expected_next_run = {'fetch_count': 0, 'start_time': '2021-03-31T19:42:05Z', 'total': None, 'fetch_sum': 0,
                         'end_time': '2024-05-30T19:42:05Z', 'last_time': '2021-03-31T19:42:05Z',
                         'hit_ids': ['sample_id_1'], 'last_timestamp': 1617219725}

    mock_response: dict = util_load_json('test_data/fetch_compromised_credentials.json')

    del mock_response['hits']['hits'][0]['_source']['email']
    del mock_response['hits']['hits'][0]['_source']['username']
    incidents_response = util_load_json(
        'test_data/incidents_compromised_credentials_when_email_username_not_present.json')

    demisto_params = {**BASIC_PARAMS, 'severity': 'Medium'}
    mocker.patch.object(demisto, 'params', return_value=demisto_params)
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response, status_code=200)
    next_run, incidents = fetch_incidents(client=mock_client, last_run=last_run, params={})

    assert incidents == incidents_response
    assert next_run == expected_next_run


def test_fetch_incidents_compromised_credentials_when_fpid_not_present(mocker, mock_client, requests_mock):
    """
     Test case scenario for execution of fetch_incidents for fetch compromised credentials when fpid not provided in response.

     Given:
         - mock client
     When:
         - Calling `fetch_incidents` function.
     Then:
         - Returns a valid command output.
     """
    from Ignite import fetch_incidents

    last_run = {'fetch_count': 1,
                'start_time': '2024-05-16T10:22:38Z',
                'total': 31,
                'fetch_sum': 30,
                'end_time': '2024-05-30T19:42:05Z'
                }

    expected_next_run = {'fetch_count': 0, 'start_time': '2021-03-31T19:42:05Z', 'total': None, 'fetch_sum': 0,
                         'end_time': '2024-05-30T19:42:05Z', 'last_time': '2021-03-31T19:42:05Z',
                         'hit_ids': ['sample_id_1'], 'last_timestamp': 1617219725}

    mock_response: dict = util_load_json('test_data/fetch_compromised_credentials.json')

    del mock_response['hits']['hits'][0]['_source']['email']
    del mock_response['hits']['hits'][0]['_source']['username']
    del mock_response['hits']['hits'][0]['_source']['fpid']

    incidents_response = util_load_json('test_data/incidents_compromised_credentials_when_fpid_not_present.json')

    demisto_params = {**BASIC_PARAMS, 'severity': 'Medium'}
    mocker.patch.object(demisto, 'params', return_value=demisto_params)
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response, status_code=200)
    next_run, incidents = fetch_incidents(client=mock_client, last_run=last_run, params={})

    assert incidents == incidents_response
    assert next_run == expected_next_run


def test_get_reports_command_success(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-report-search command.

    Given:
       - command arguments for get_reports_command
    When:
       - Calling `get_reports_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import get_reports_command

    get_reports = util_load_json('test_data/get_reports_success.json')
    get_reports_context = util_load_json('test_data/get_reports_success_context.json')
    with open('test_data/get_reports_success_hr.md') as file:
        hr_output_for_reports = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["REPORT_SEARCH"]}?query=report_search&limit=5', json=get_reports, status_code=200)

    resp = get_reports_command(mock_client, {'report_search': 'report_search'})

    assert resp.outputs_prefix == OUTPUT_PREFIX['REPORT']
    assert resp.outputs_key_field == OUTPUT_KEY_FIELD['REPORT_ID']
    assert resp.readable_output == hr_output_for_reports
    assert resp.outputs == get_reports_context
    assert resp.raw_response == get_reports


def test_get_reports_command_success_when_empty_response(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-report-search command with empty response.

    Given:
       - command arguments for get_reports_command
    When:
       - Calling `get_reports_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import get_reports_command

    get_reports_empty_data = util_load_json('test_data/get_reports_success_empty_response.json')
    with open('test_data/get_reports_success_empty_response_hr.md') as file:
        hr_output_for_reports = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["REPORT_SEARCH"]}?query=report_search&limit=5', json=get_reports_empty_data,
                      status_code=200)

    resp = get_reports_command(mock_client, {'report_search': 'report_search'})

    assert resp.readable_output == hr_output_for_reports
    assert resp.raw_response == get_reports_empty_data


def test_get_reports_command_when_invalid_argument(mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-report-search command
    when invalid argument provided.
    Given:
       - command arguments for get_reports_command
    When:
       - Calling `get_reports_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import get_reports_command
    args = {'report_search': ' '}
    with pytest.raises(ValueError) as err:
        get_reports_command(mock_client, remove_space_from_args(args))

    assert str(err.value) == MESSAGES['MISSING_REQUIRED_ARGS'].format('report_search')


def test_event_list_command_success(requests_mock, mock_client):
    """
    Test case scenario for successful execution of event_list_command function.

    Given:
        - command arguments for event_list_command
    When:
        - Calling `event_list_command` function
    Then:
        - Returns a valid output
    """
    from Ignite import event_list_command

    mock_response_events = util_load_json('test_data/event_list_2_response.json')

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["EVENT_LIST"]}', json=mock_response_events, status_code=200)

    resp = event_list_command(mock_client, args={'time_period': '1 month', 'limit': 2, 'attack_ids': 'T1001',
                                                 'report_fpid': '0000000000000000000001'})

    output_list_events = util_load_json('test_data/event_list_2_output.json')

    hr_output_for_events = util_load_text_data('test_data/event_list_2_hr.md')

    assert resp.outputs_prefix == OUTPUT_PREFIX['EVENT']
    assert resp.outputs_key_field == OUTPUT_KEY_FIELD['EVENT_ID']
    assert resp.readable_output == hr_output_for_events
    assert resp.outputs == output_list_events
    assert resp.raw_response == mock_response_events


def test_event_list_command_no_result(requests_mock, mock_client):
    """
    Test case scenario with no results execution of event_list_command function.

    Given:
        - command arguments for event_list_command
    When:
        - Calling `event_list_command` function
    Then:
        - Returns a valid output
    """
    from Ignite import event_list_command

    mock_response_events = []

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["EVENT_LIST"]}', json=mock_response_events, status_code=200)

    resp = event_list_command(mock_client, args={})

    assert resp.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('events')
    assert resp.raw_response == mock_response_events


@pytest.mark.parametrize(
    "args,error_message",
    [
        ({'limit': "10001"}, MESSAGES['LIMIT_ERROR'].format('10001', MAX_PRODUCT)),
        ({'limit': '-1'}, MESSAGES['LIMIT_ERROR'].format('-1', MAX_PRODUCT)),
        ({'limit': '0'}, MESSAGES['LIMIT_ERROR'].format('0', MAX_PRODUCT)),
    ],
)
def test_event_list_command_with_invalid_args(args, error_message, mock_client):
    """
    Test case scenario for execution of event_list_command with invalid arguments provided.

    Given:
        - arguments for event_list_command.
    When:
        - Calling `event_list_command` function.
    Then:
        - Returns a valid error message.
    """
    from Ignite import event_list_command

    with pytest.raises(DemistoException) as error:
        event_list_command(mock_client, args=args)

    assert str(error.value) == error_message


def test_event_get_command_success(requests_mock, mock_client):
    """
    Test case scenario for successful execution of event_get_command function.

    Given:
        - command arguments for event_get_command
    When:
        - Calling `event_get_command` function
    Then:
        - Returns a valid output
    """
    from Ignite import event_get_command

    mock_response_events = util_load_json('test_data/event_get_response.json')

    requests_mock.get(
        f'{MOCK_URL}{URL_SUFFIX["EVENT_GET"].format("1")}', json=mock_response_events, status_code=200)

    resp = event_get_command(mock_client, args={'event_id': '1'})

    output_list_events = util_load_json('test_data/event_get_output.json')

    hr_output_for_events = util_load_text_data('test_data/event_get_hr.md')

    assert resp.outputs_prefix == OUTPUT_PREFIX['EVENT']
    assert resp.outputs_key_field == OUTPUT_KEY_FIELD['EVENT_ID']
    assert resp.readable_output == hr_output_for_events
    assert resp.outputs == output_list_events
    assert resp.raw_response == mock_response_events


def test_event_get_command_no_result(requests_mock, mock_client):
    """
    Test case scenario with no results execution of event_get_command function.

    Given:
        - command arguments for event_get_command
    When:
        - Calling `event_get_command` function
    Then:
        - Returns a valid output
    """
    from Ignite import event_get_command

    mock_response_events = []

    requests_mock.get(
        f'{MOCK_URL}{URL_SUFFIX["EVENT_GET"].format("1")}', json=mock_response_events, status_code=200)

    resp = event_get_command(mock_client, args={'event_id': '1'})

    assert resp.readable_output == MESSAGES['NO_RECORDS_FOUND'].format('event')
    assert resp.raw_response == mock_response_events


def test_event_get_command_with_empty_argument(mock_client):
    """
    Test case scenario for the execution of event_get_command with empty argument.

    Given:
       - mocked client
    When:
       - Calling `event_get_command` function
    Then:
       - Returns exception
    """
    from Ignite import event_get_command

    with pytest.raises(DemistoException) as err:
        event_get_command(mock_client, args={})

    assert MESSAGES['MISSING_REQUIRED_ARGS'].format('event_id') in str(err.value)


def test_flashpoint_ignite_compromised_credentials_command_with_arguments(requests_mock, mock_client):
    """
    Test case scenario for execution of flashpoint-ignite-compromised-credentials-list with arguments provided.

    Given:
        - mocked client
    When:
        - Calling `flashpoint_ignite_compromised_credentials_list_command` function.
    Then:
        - Returns valid command output
    """
    from Ignite import flashpoint_ignite_compromised_credentials_list_command

    args = {'end_date': 'now', 'filter_date': 'first_observed_at', 'is_fresh': 'true', 'page_number': '1', 'page_size': '1',
            'sort_date': 'created_at', 'sort_order': 'asc', 'start_date': '3 years'}

    mock_response: dict = util_load_json(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'test_data/get_compromised_credentials_list.json',
        )
    )

    with open(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'test_data/get_compromised_credentials_hr_output.md',
        )
    ) as file:
        hr_output = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response['raw_response'], status_code=200)
    response = flashpoint_ignite_compromised_credentials_list_command(client=mock_client, args=args)

    assert response.raw_response == mock_response['raw_response']
    assert response.outputs_prefix == OUTPUT_PREFIX['COMPROMISED_CREDENTIALS']
    assert response.outputs_key_field == '_id'
    assert response.outputs == mock_response['outputs']
    assert response.readable_output == hr_output


def test_flashpoint_ignite_compromised_credentials_with_no_response(mock_client, requests_mock):
    """
    Test case scenario for execution of flashpoint-ignite-compromised-credentials-list with no response.

    Given:
        - mocked client
    When:
        - Calling `flashpoint_ignite_compromised_credentials_list_command` function.
    Then:
        - Returns valid command output
    """
    from Ignite import flashpoint_ignite_compromised_credentials_list_command

    mock_response: dict = {}

    args = {'end_date': 'now', 'filter_date': 'created_at', 'is_fresh': 'false', 'page_number': '1',
            'page_size': '1',
            'sort_date': 'first_observed_at', 'sort_order': 'asc', 'start_date': 'now'}

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response, status_code=200)
    response = flashpoint_ignite_compromised_credentials_list_command(client=mock_client, args=args)

    assert response.readable_output == 'No compromised credentials were found for the given argument(s).'
    assert response.raw_response == mock_response


@pytest.mark.parametrize(
    "args,error_message",
    [
        ({'page_size': "1001"}, MESSAGES['PAGE_SIZE_ERROR'].format('1001', MAX_PAGE_SIZE)),
        ({'page_size': '-1'}, MESSAGES['PAGE_SIZE_ERROR'].format('-1', MAX_PAGE_SIZE)),
        ({'page_number': '-1'}, MESSAGES['PAGE_NUMBER_ERROR'].format('-1')),
        ({'sort_order': 'abc'}, MESSAGES['SORT_ORDER_ERROR'].format('abc', SORT_ORDER_VALUES)),
        ({'page_size': '1000', 'page_number': '100'}, MESSAGES['PRODUCT_ERROR'].format(MAX_PRODUCT, 100000)),
        ({'end_date': '2 days'}, MESSAGES['START_DATE_ERROR']),
        ({'sort_date': 'updated_at'}, MESSAGES['SORT_DATE_ERROR'].format('updated_at', SORT_DATE_VALUES)),
        ({'start_date': '2 days'}, MESSAGES['MISSING_FILTER_DATE_ERROR']),
        ({'is_fresh': 'wrong', 'sort_date': 'created_at'}, MESSAGES['IS_FRESH_ERROR'].format('wrong', IS_FRESH_VALUES)),
        ({'filter_date': 'updated_at'}, MESSAGES['FILTER_DATE_ERROR'].format('updated_at', FILTER_DATE_VALUES)),
        ({'sort_order': 'asc'}, MESSAGES['MISSING_SORT_DATE_ERROR'])
    ],
)
def test_flashpoint_ignite_compromised_credentials_with_invalid_args(args, error_message, mock_client):
    """
    Test case scenario for execution of flashpoint-ignite-compromised-credentials-list with invalid arguments provided.

    Given:
        - arguments for flashpoint_ignite_compromised_credentials_list_command.
    When:
        - Calling `flashpoint_ignite_compromised_credentials_list_command` function.
    Then:
        - Returns a valid error message.
    """
    from Ignite import flashpoint_ignite_compromised_credentials_list_command

    with pytest.raises(ValueError) as error:
        flashpoint_ignite_compromised_credentials_list_command(mock_client, args=args)

    assert str(error.value) == error_message


def test_get_report_by_id_command_success(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-report-get command.

    Given:
       - command arguments for  get_report_by_id_command
    When:
       - Calling ` get_report_by_id_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import get_report_by_id_command

    get_report = util_load_json('test_data/get_report_by_id_success.json')
    get_report_context = util_load_json('test_data/get_report_by_id_success_context.json')
    with open('test_data/get_report_by_id_success_hr.md') as file:
        hr_output_for_report = file.read()

    requests_mock.get(
        f'{MOCK_URL}{URL_SUFFIX["GET_REPORT_BY_ID"].format("0000000000000000000001")}', json=get_report, status_code=200)

    resp = get_report_by_id_command(mock_client, {'report_id': '0000000000000000000001'})

    assert resp.outputs_prefix == OUTPUT_PREFIX['REPORT']
    assert resp.outputs_key_field == OUTPUT_KEY_FIELD['REPORT_ID']
    assert resp.readable_output == hr_output_for_report
    assert resp.outputs == get_report_context
    assert resp.raw_response == get_report


def test_get_report_by_id_command_when_report_not_found(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-report-get command when report not found.

    Given:
       - command arguments for  get_report_by_id_command
    When:
       - Calling ` get_report_by_id_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import get_report_by_id_command

    get_report_invalid_id = util_load_json('test_data/get_report_by_id_when_report_not_found.json')

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["GET_REPORT_BY_ID"].format("0000000000000000000001")}',
                      json=get_report_invalid_id, status_code=404)

    with pytest.raises(DemistoException) as err:
        get_report_by_id_command(mock_client, {'report_id': '0000000000000000000001'})

    assert str(err.value) == MESSAGES['STATUS_CODE'].format(404, MESSAGES['NO_RECORD_FOUND'])


def test_get_report_by_id_command_when_invalid_argument(mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-report-get command
    when invalid argument provided.
    Given:
       - command arguments for get_report_by_id_command
    When:
       - Calling `get_report_by_id_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import get_report_by_id_command
    args = {'report_id': ' '}
    with pytest.raises(ValueError) as err:
        get_report_by_id_command(mock_client, remove_space_from_args(args))

    assert str(err.value) == MESSAGES['MISSING_REQUIRED_ARGS'].format('report_id')


def test_related_report_list_command_success(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-related-report-list command.

    Given:
       - command arguments for related_report_list_command
    When:
       - Calling `related_report_list_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import related_report_list_command

    related_report_lists = util_load_json('test_data/related_report_list_success.json')
    related_report_lists_context = util_load_json('test_data/related_report_list_success_context.json')
    with open('test_data/hr_output_for_related_report_list_success.md') as file:
        hr_output_for_related_reports = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["RELATED_REPORT_LIST"].format("0000000000000000000001")}?limit=5',
                      json=related_report_lists, status_code=200)

    resp = related_report_list_command(mock_client, {'report_id': '0000000000000000000001'})

    assert resp.outputs_prefix == OUTPUT_PREFIX['REPORT']
    assert resp.outputs_key_field == OUTPUT_KEY_FIELD['REPORT_ID']
    assert resp.readable_output == hr_output_for_related_reports
    assert resp.outputs == related_report_lists_context
    assert resp.raw_response == related_report_lists


def test_related_report_list_command_success_when_empty_response(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-related-report-list command with empty response.

    Given:
       - command arguments for related_report_list_command
    When:
       - Calling `related_report_list_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import related_report_list_command

    related_report_lists_empty_data = util_load_json('test_data/related_report_list_success_empty_response.json')
    with open('test_data/hr_output_for_related_report_list_success_empty_response.md') as file:
        hr_output_for_related_reports = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["RELATED_REPORT_LIST"].format("0000000000000000000001")}?limit=5',
                      json=related_report_lists_empty_data, status_code=200)

    resp = related_report_list_command(mock_client, {'report_id': '0000000000000000000001'})

    assert resp.readable_output == hr_output_for_related_reports
    assert resp.raw_response == related_report_lists_empty_data


def test_related_report_list_command_when_report_not_found(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-related-report-list
    command when report not found.

    Given:
       - command arguments for  related_report_list_command
    When:
       - Calling ` related_report_list_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import related_report_list_command

    report_invalid_id = util_load_json('test_data/get_report_by_id_when_report_not_found.json')

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["RELATED_REPORT_LIST"].format("0000000000000000000001")}?limit=5',
                      json=report_invalid_id, status_code=404)

    with pytest.raises(DemistoException) as err:
        related_report_list_command(mock_client, {'report_id': '0000000000000000000001'})

    assert str(err.value) == MESSAGES['STATUS_CODE'].format(404, MESSAGES['NO_RECORD_FOUND'])


def test_related_report_list_command_when_invalid_argument(mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-related-report-list command
    when invalid argument provided.
    Given:
       - command arguments for related_report_list_command
    When:
       - Calling `related_report_list_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import related_report_list_command
    args = {'report_id': ' '}
    with pytest.raises(ValueError) as err:
        related_report_list_command(mock_client, remove_space_from_args(args))

    assert str(err.value) == MESSAGES['MISSING_REQUIRED_ARGS'].format('report_id')


@patch("demistomock.results")
def test_email(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of email command through main function
    when it returns reputation about given email address.

    Given:
       - mocked client
    When:
       - Calling `email_lookup_command` function
    Then:
       - Returns list of command results.
    """

    email_reputation = util_load_json('test_data/email_reputation.json')
    email_reputation_context = util_load_json('test_data/email_reputation_context.json')
    with open('test_data/hr_output_for_email_reputation.md') as file:
        hr_output_for_email_reputation = file.read()
    requests_mock.get(f'{MOCK_URL}/technical-intelligence/v1/simple?query=%2Btype%3A%28%22email-dst%22%2C%20'
                      f'%22email-src%22%2C%20%22email-src-display-name%22%2C%20%22email-subject%22%2C%20'
                      f'%22email%22%29%20%2Bvalue.%5C%2A.keyword%3A%22dummy%40dummy.com%22',
                      json=email_reputation, status_code=200)
    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}
    args = {'email': 'dummy@dummy.com'}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='email')
    mocker.patch.object(demisto, 'args', return_value=args)

    main()
    assert hr_output_for_email_reputation == mock_return.call_args.args[0].get('HumanReadable')
    assert email_reputation_context == mock_return.call_args.args[0].get('EntryContext')
    assert email_reputation == mock_return.call_args.args[0].get('Contents')


@patch("demistomock.results")
def test_email_empty_response(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of email command through main function
    when Ignite do not have data about that email address.

    Given:
       - mocked client
    When:
       - Calling `email_lookup_command` function
    Then:
       - Returns list of command results.
    """

    email_reputation = util_load_json('test_data/email_reputation_empty.json')
    email_reputation_context = util_load_json('test_data/email_reputation_context_empty.json')
    with open('test_data/hr_output_for_email_reputation_empty.md') as file:
        hr_output_for_email_reputation = file.read()

    requests_mock.get(f'{MOCK_URL}/technical-intelligence/v1/simple?query=%2Btype%3A%28%22email-dst%22%2C%20'
                      f'%22email-src%22%2C%20%22email-src-display-name%22%2C%20%22email-subject%22%2C%20'
                      f'%22email%22%29%20%2Bvalue.%5C%2A.keyword%3A%22dummy2%40dummy.com%22',
                      json=email_reputation, status_code=200)

    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}
    args = {'email': 'dummy2@dummy.com'}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='email')
    mocker.patch.object(demisto, 'args', return_value=args)

    main()
    assert hr_output_for_email_reputation == mock_return.call_args.args[0].get('HumanReadable')
    assert email_reputation_context == mock_return.call_args.args[0].get('EntryContext')
    assert email_reputation == mock_return.call_args.args[0].get('Contents')


@patch("demistomock.results")
def test_filename(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of filename command through main function
    when it returns reputation about given filename.

    Given:
       - mocked client
    When:
       - Calling `filename_lookup_command` function
    Then:
       - Returns list of command results.
    """

    filename_reputation = util_load_json('test_data/filename_reputation.json')
    filename_reputation_context = util_load_json('test_data/filename_reputation_context.json')
    with open('test_data/filename_reputation_hr.md') as file:
        filename_reputation_hr = file.read()

    requests_mock.get(f'{MOCK_URL}/technical-intelligence/v1/simple?query='
                      f'%2Btype%3A%28%22filename%22%29%20%2Bvalue.%5C%2A.keyword%3A%22dummy.log%22',
                      json=filename_reputation, status_code=200)
    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}
    args = {'filename': 'dummy.log'}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='filename')
    mocker.patch.object(demisto, 'args', return_value=args)

    main()
    assert filename_reputation_hr == mock_return.call_args.args[0].get('HumanReadable')
    assert filename_reputation_context == mock_return.call_args.args[0].get('EntryContext')
    assert filename_reputation == mock_return.call_args.args[0].get('Contents')


@patch("demistomock.results")
def test_filename_empty_response(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of filename command through main function
    when Ignite do not have data about that filename.

    Given:
       - mocked client
    When:
       - Calling `filename_lookup_command` function
    Then:
       - Returns list of command results.
    """
    filename_reputation = util_load_json('test_data/filename_reputation_empty.json')
    filename_reputation_context = util_load_json('test_data/filename_reputation_context_empty.json')
    with open('test_data/filename_reputation_empty_hr.md') as file:
        filename_reputation_empty_hr = file.read()

    requests_mock.get(f'{MOCK_URL}/technical-intelligence/v1/simple?query='
                      f'%2Btype%3A%28%22filename%22%29%20%2Bvalue.%5C%2A.keyword%3A%22dummy2.log%22',
                      json=filename_reputation, status_code=200)

    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}
    args = {'filename': 'dummy2.log'}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='filename')
    mocker.patch.object(demisto, 'args', return_value=args)

    main()
    assert filename_reputation_empty_hr == mock_return.call_args.args[0].get('HumanReadable')
    assert filename_reputation_context == mock_return.call_args.args[0].get('EntryContext')
    assert filename_reputation == mock_return.call_args.args[0].get('Contents')


@patch("demistomock.results")
def test_domain_lookup_command_success(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of domain look up command through main function
    when it returns reputation about given domain indicator.

    Given:
       - mocked client
    When:
       - Calling `domain_lookup_command` function
    Then:
       - Returns list of command results.
    """

    domain_lookup_reputation = util_load_json('test_data/domain_lookup_reputation.json')
    domain_lookup_reputation_context = util_load_json('test_data/domain_lookup_reputation_context.json')
    with open('test_data/hr_output_for_domain_lookup_reputation.md') as file:
        hr_output_for_domain_lookup_reputation = file.read()

    query = r'+type:("domain") +value.\*.keyword:"dummy.com"'
    url = f'{MOCK_URL}{URL_SUFFIX["INDICATOR_SEARCH"]}?query=' + urllib.parse.quote(query)

    requests_mock.get(url, json=domain_lookup_reputation, status_code=200)
    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}
    args = {'domain': 'dummy.com'}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='domain')
    mocker.patch.object(demisto, 'args', return_value=args)

    main()

    assert hr_output_for_domain_lookup_reputation == mock_return.call_args.args[0].get('HumanReadable')
    assert domain_lookup_reputation_context == mock_return.call_args.args[0].get('EntryContext')
    assert domain_lookup_reputation == mock_return.call_args.args[0].get('Contents')


@patch("demistomock.results")
def test_domain_lookup_command_success_when_empty_response(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of domain look up command through main function
    when it returns empty reputation about given domain indicator.

    Given:
       - mocked client
    When:
       - Calling `domain_lookup_command` function
    Then:
       - Returns list of command results.
    """

    domain_lookup_empty_reputation_context = util_load_json('test_data/domain_lookup_empty_reputation_context.json')
    with open('test_data/hr_output_for_domain_lookup_empty_reputation.md') as file:
        hr_output_for_domain_lookup_reputation = file.read()

    query = r'+type:("domain") +value.\*.keyword:"dummy.com"'
    url = f'{MOCK_URL}{URL_SUFFIX["INDICATOR_SEARCH"]}?query=' + urllib.parse.quote(query)

    requests_mock.get(url, json={}, status_code=200)
    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}
    args = {'domain': 'dummy.com'}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='domain')
    mocker.patch.object(demisto, 'args', return_value=args)

    main()

    assert hr_output_for_domain_lookup_reputation == mock_return.call_args.args[0].get('HumanReadable')
    assert domain_lookup_empty_reputation_context == mock_return.call_args.args[0].get('EntryContext')
    assert {} == mock_return.call_args.args[0].get('Contents')


def test_domain_lookup_command_when_invalid_value_is_provided(mocker):
    """
    Test case for successful execution of domain look up command through main function
    when domain indicator's value is blank.

    Given:
       - mocked client
    When:
       - Calling `domain_lookup_command` function
    Then:
       - Returns list of command results.
    """
    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}
    args = {'domain': ' '}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='domain')
    mocker.patch.object(demisto, 'args', return_value=args)

    return_error = mocker.patch.object(Ignite, "return_error")
    main()

    assert MESSAGES['MISSING_REQUIRED_ARGS'].format('domain') in return_error.call_args[0][0]


@patch("demistomock.results")
def test_ip_lookup_command_success(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of ip look up command through main function
    when it returns reputation about given ip indicator.

    Given:
       - mocked client
    When:
       - Calling `ip_lookup_command` function
    Then:
       - Returns list of command results.
    """

    ip_lookup_reputation = util_load_json('test_data/ip_lookup_reputation.json')
    ip_lookup_reputation_context = util_load_json('test_data/ip_lookup_reputation_context.json')
    with open('test_data/hr_output_for_ip_lookup_reputation.md') as file:
        hr_output_for_ip_lookup_reputation = file.read()

    query = QUERY + '0.0.0.1' + '"'
    url = f'{MOCK_URL}{URL_SUFFIX["INDICATOR_SEARCH"]}?query=' + urllib.parse.quote(query)
    requests_mock.get(url, json=ip_lookup_reputation, status_code=200)
    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}
    args = {'ip': '0.0.0.1'}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='ip')
    mocker.patch.object(demisto, 'args', return_value=args)

    main()

    assert hr_output_for_ip_lookup_reputation == mock_return.call_args.args[0].get('HumanReadable')
    assert ip_lookup_reputation_context == mock_return.call_args.args[0].get('EntryContext')
    assert ip_lookup_reputation == mock_return.call_args.args[0].get('Contents')


@patch("demistomock.results")
def test_ip_lookup_command_community_search_success(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of ip look up command through main function
    when it returns reputation about given ip indicator.

    Given:
       - mocked client
    When:
       - Calling `ip_lookup_command` function
    Then:
       - Returns list of command results.
    """

    query = QUERY + '0.0.0.1' + '"'
    url = f'{MOCK_URL}{URL_SUFFIX["INDICATOR_SEARCH"]}?query=' + urllib.parse.quote(query)
    requests_mock.get(url, json={}, status_code=200)

    ip_lookup_community_search_reputation = util_load_json('test_data/ip_lookup_community_search_reputation.json')
    ip_lookup_community_search_reputation_context = util_load_json('test_data/ip_lookup_community_search_reputation_context.json')
    with open('test_data/hr_output_for_ip_lookup_community_search_reputation.md') as file:
        hr_output_for_ip_lookup_community_search_reputation = file.read()

    community_search_url = f'{MOCK_URL}{URL_SUFFIX["COMMUNITY_SEARCH"]}'
    requests_mock.post(community_search_url, json=ip_lookup_community_search_reputation, status_code=200)

    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}
    args = {'ip': '0.0.0.1'}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='ip')
    mocker.patch.object(demisto, 'args', return_value=args)

    main()

    assert hr_output_for_ip_lookup_community_search_reputation == mock_return.call_args.args[0].get('HumanReadable')
    assert ip_lookup_community_search_reputation_context == mock_return.call_args.args[0].get('EntryContext')
    assert ip_lookup_community_search_reputation == mock_return.call_args.args[0].get('Contents')


@patch("demistomock.results")
def test_ip_lookup_command_success_when_empty_response(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of ip look up command through main function
    when it returns empty reputation about given ip indicator.

    Given:
       - mocked client
    When:
       - Calling `ip_lookup_command` function
    Then:
       - Returns list of command results.
    """

    ip_lookup_empty_reputation_context = util_load_json('test_data/ip_lookup_empty_reputation_context.json')
    with open('test_data/hr_output_for_ip_lookup_empty_reputation.md') as file:
        hr_output_for_ip_lookup_reputation = file.read()

    query = QUERY + '0.0.0.1' + '"'
    url = f'{MOCK_URL}{URL_SUFFIX["INDICATOR_SEARCH"]}?query=' + urllib.parse.quote(query)
    requests_mock.get(url, json={}, status_code=200)

    ip_lookup_community_search_empty_reputation = util_load_json('test_data/ip_lookup_community_search_empty_reputation.json')
    community_search_url = f'{MOCK_URL}{URL_SUFFIX["COMMUNITY_SEARCH"]}'
    requests_mock.post(community_search_url, json=ip_lookup_community_search_empty_reputation, status_code=200)
    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}
    args = {'ip': '0.0.0.1'}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='ip')
    mocker.patch.object(demisto, 'args', return_value=args)

    main()

    assert hr_output_for_ip_lookup_reputation == mock_return.call_args.args[0].get('HumanReadable')
    assert ip_lookup_empty_reputation_context == mock_return.call_args.args[0].get('EntryContext')
    assert {} == mock_return.call_args.args[0].get('Contents')


@pytest.mark.parametrize('args, error_msg', [
    ({'ip': 'dummy.com'}, MESSAGES['INVALID_IP_ADDRESS'].format('dummy.com')),
    ({'ip': ' '}, MESSAGES['MISSING_REQUIRED_ARGS'].format('ip')),
])
def test_ip_lookup_command_when_invalid_value_is_provided(mocker, args, error_msg, capfd):
    """
    Test case for successful execution of ip look up command through main function
    when ip indicator's value is invalid.

    Given:
       - mocked client
    When:
       - Calling `ip_lookup_command` function
    Then:
       - Returns list of command results.
    """
    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='ip')
    mocker.patch.object(demisto, 'args', return_value=args)
    return_error = mocker.patch.object(Ignite, "return_error")

    capfd.close()
    main()

    assert error_msg in return_error.call_args[0][0]


@patch("demistomock.results")
def test_common_lookup_command_success(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of common look up command through main function
    when it returns reputation about given indicator.

    Given:
       - mocked client
    When:
       - Calling `common_lookup_command` function
    Then:
       - Returns list of command results.
    """

    common_lookup_reputation = util_load_json('test_data/common_lookup_reputation.json')
    common_lookup_reputation_context = util_load_json('test_data/common_lookup_reputation_context.json')
    with open('test_data/hr_output_for_common_lookup_reputation.md') as file:
        hr_output_for_common_lookup_reputation = file.read()

    url = f'{MOCK_URL}{URL_SUFFIX["INDICATOR_SEARCH"]}?query=' + urllib.parse.quote(r'+value.\*.keyword:"dummy@dummy.com"')
    requests_mock.get(url, json=common_lookup_reputation, status_code=200)
    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}
    args = {'indicator': 'dummy@dummy.com'}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='flashpoint-ignite-common-lookup')
    mocker.patch.object(demisto, 'args', return_value=args)

    main()

    assert hr_output_for_common_lookup_reputation == mock_return.call_args.args[0].get('HumanReadable')
    assert common_lookup_reputation_context == mock_return.call_args.args[0].get('EntryContext')
    assert common_lookup_reputation == mock_return.call_args.args[0].get('Contents')


@patch("demistomock.results")
def test_common_lookup_command_success_when_indicator_type_is_ipv4(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of common look up command through main function
    when it returns reputation about given ip indicator.

    Given:
       - mocked client
    When:
       - Calling `common_lookup_command` function
    Then:
       - Returns list of command results.
    """

    common_lookup_reputation = util_load_json('test_data/common_lookup_reputation.json')
    common_lookup_reputation_context = util_load_json('test_data/common_lookup_ipv4_reputation_context.json')
    with open('test_data/hr_output_for_common_lookup_ipv4_reputation.md') as file:
        hr_output_for_common_lookup_reputation = file.read()

    query = r'+type:("ip-src","ip-dst","ip-dst|port") +value.\*:"0.0.0.0"'
    url = f'{MOCK_URL}{URL_SUFFIX["INDICATOR_SEARCH"]}?query=' + urllib.parse.quote(query)
    requests_mock.get(url, json=common_lookup_reputation, status_code=200)
    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}
    args = {'indicator': '0.0.0.0'}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='flashpoint-ignite-common-lookup')
    mocker.patch.object(demisto, 'args', return_value=args)

    main()

    assert hr_output_for_common_lookup_reputation == mock_return.call_args.args[0].get('HumanReadable')
    assert common_lookup_reputation_context == mock_return.call_args.args[0].get('EntryContext')
    assert common_lookup_reputation == mock_return.call_args.args[0].get('Contents')


@patch("demistomock.results")
def test_common_lookup_command_success_when_indicator_type_is_ipv6(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of common look up command through main function
    when it returns reputation about given ip indicator.

    Given:
       - mocked client
    When:
       - Calling `common_lookup_command` function
    Then:
       - Returns list of command results.
    """

    common_lookup_reputation = util_load_json('test_data/common_lookup_reputation.json')
    common_lookup_reputation_context = util_load_json('test_data/common_lookup_ipv6_reputation_context.json')
    with open('test_data/hr_output_for_common_lookup_ipv6_reputation.md') as file:
        hr_output_for_common_lookup_reputation = file.read()

    query = r'+type:("ip-src","ip-dst","ip-dst|port") +value.\*:"0:0:0:0:0:0:0:0"'
    url = f'{MOCK_URL}{URL_SUFFIX["INDICATOR_SEARCH"]}?query=' + urllib.parse.quote(query)
    requests_mock.get(url, json=common_lookup_reputation, status_code=200)
    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}
    args = {'indicator': '0:0:0:0:0:0:0:0'}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='flashpoint-ignite-common-lookup')
    mocker.patch.object(demisto, 'args', return_value=args)

    main()

    assert hr_output_for_common_lookup_reputation == mock_return.call_args.args[0].get('HumanReadable')
    assert common_lookup_reputation_context == mock_return.call_args.args[0].get('EntryContext')
    assert common_lookup_reputation == mock_return.call_args.args[0].get('Contents')


@patch("demistomock.results")
def test_common_lookup_command_success_when_empty_response(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of common look up command through main function
    when it returns empty reputation about given indicator.

    Given:
       - mocked client
    When:
       - Calling `common_lookup_command` function
    Then:
       - Returns list of command results.
    """

    with open('test_data/hr_output_for_common_lookup_empty_response.md') as file:
        hr_output_for_common_lookup_empty_response = file.read()

    url = f'{MOCK_URL}{URL_SUFFIX["INDICATOR_SEARCH"]}?query=' + urllib.parse.quote(r'+value.\*.keyword:"dummy@dummy.com"')
    requests_mock.get(url, json={}, status_code=200)
    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}
    args = {'indicator': 'dummy@dummy.com'}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='flashpoint-ignite-common-lookup')
    mocker.patch.object(demisto, 'args', return_value=args)

    main()

    assert hr_output_for_common_lookup_empty_response == mock_return.call_args.args[0].get('HumanReadable')
    assert {} == mock_return.call_args.args[0].get('EntryContext')
    assert {} == mock_return.call_args.args[0].get('Contents')


def test_common_lookup_command_when_invalid_value_is_provided(mocker):
    """
    Test case for successful execution of common look up command through main function
    when indicator's value is blank.

    Given:
       - mocked client
    When:
       - Calling `common_lookup_command` function
    Then:
       - Returns list of command results.
    """
    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}
    args = {'indicator': ' '}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='flashpoint-ignite-common-lookup')
    mocker.patch.object(demisto, 'args', return_value=args)

    return_error = mocker.patch.object(Ignite, "return_error")
    main()

    assert MESSAGES['MISSING_REQUIRED_ARGS'].format('indicator') in return_error.call_args[0][0]


@patch("demistomock.results")
def test_url(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of url command through main function
    when it returns reputation about given url.

    Given:
       - mocked client
    When:
       - Calling `url_lookup_command` function
    Then:
       - Returns list of command results.
    """

    url_reputation = util_load_json('test_data/url_reputation.json')
    url_reputation_context = util_load_json('test_data/url_reputation_context.json')
    with open('test_data/url_reputation_hr.md') as file:
        url_reputation_hr = file.read()
    requests_mock.get(f'{MOCK_URL}/technical-intelligence/v1/simple',
                      json=url_reputation, status_code=200)
    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}
    args = {'url': 'http://dummy.com'}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='url')
    mocker.patch.object(demisto, 'args', return_value=args)

    main()
    assert url_reputation_hr == mock_return.call_args.args[0].get('HumanReadable')
    assert url_reputation_context == mock_return.call_args.args[0].get('EntryContext')
    assert url_reputation == mock_return.call_args.args[0].get('Contents')


@patch("demistomock.results")
def test_url_empty_response(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of url command through main function
    when Ignite do not have data about that url.

    Given:
       - mocked client
    When:
       - Calling `url_lookup_command` function
    Then:
       - Returns list of command results.
    """

    url_reputation = util_load_json('test_data/url_reputation_empty.json')
    url_reputation_context = util_load_json('test_data/url_reputation_context_empty.json')
    with open('test_data/url_reputation_hr_empty.md') as file:
        url_reputation_hr = file.read()

    requests_mock.get(f'{MOCK_URL}/technical-intelligence/v1/simple',
                      json=url_reputation, status_code=200)

    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}
    args = {'url': 'http://dummy2.com'}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='url')
    mocker.patch.object(demisto, 'args', return_value=args)

    main()
    assert url_reputation_hr == mock_return.call_args.args[0].get('HumanReadable')
    assert url_reputation_context == mock_return.call_args.args[0].get('EntryContext')
    assert url_reputation == mock_return.call_args.args[0].get('Contents')


@patch("demistomock.results")
def test_file(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of file command through main function
    when it returns reputation about given file.

    Given:
       - mocked client
    When:
       - Calling `file_lookup_command` function
    Then:
       - Returns list of command results.
    """

    file_reputation = util_load_json('test_data/file_reputation.json')
    file_reputation_context = util_load_json('test_data/file_reputation_context.json')
    with open('test_data/file_reputation_hr.md') as file:
        file_reputation_hr = file.read()

    requests_mock.get(f'{MOCK_URL}/technical-intelligence/v1/simple',
                      json=file_reputation, status_code=200)
    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}
    args = {'file': '00000000000000000000000000000001'}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='file')
    mocker.patch.object(demisto, 'args', return_value=args)

    main()
    assert file_reputation_hr == mock_return.call_args.args[0].get('HumanReadable')
    assert file_reputation_context == mock_return.call_args.args[0].get('EntryContext')
    assert file_reputation == mock_return.call_args.args[0].get('Contents')


@patch("demistomock.results")
def test_file_empty_response(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of file command through main function
    when Ignite do not have data about that file.

    Given:
       - mocked client
    When:
       - Calling `file_lookup_command` function
    Then:
       - Returns list of command results.
    """
    file_reputation = util_load_json('test_data/file_reputation_empty.json')
    file_reputation_context = util_load_json('test_data/file_reputation_context_empty.json')
    with open('test_data/file_reputation_empty_hr.md') as file:
        file_reputation_empty_hr = file.read()

    requests_mock.get(f'{MOCK_URL}/technical-intelligence/v1/simple',
                      json=file_reputation, status_code=200)

    params = {**BASIC_PARAMS, 'integrationReliability': 'B - Usually reliable'}
    args = {'file': '10000000000000000000000000000000'}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='file')
    mocker.patch.object(demisto, 'args', return_value=args)

    main()
    assert file_reputation_empty_hr == mock_return.call_args.args[0].get('HumanReadable')
    assert file_reputation_context == mock_return.call_args.args[0].get('EntryContext')
    assert file_reputation == mock_return.call_args.args[0].get('Contents')


def test_fetch_incidents_alerts_success(mocker, mock_client, requests_mock):
    """
    Test case scenario for execution of fetch_incidents for fetch alerts.

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Returns a valid command output.
    """
    from Ignite import fetch_incidents

    last_run = {}

    mock_response: dict = util_load_json('test_data/fetch_alerts.json')

    incidents_response = util_load_json('test_data/incidents_alerts.json')

    params: dict = {
        'fetch_type': 'Alerts',
        'first_fetch': '2024-06-14T06:17:17Z',
        'max_fetch': 4
    }

    demisto_params = {**BASIC_PARAMS, 'severity': 'Medium'}
    mocker.patch.object(demisto, 'params', return_value=demisto_params)

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["ALERTS"]}', json=mock_response, status_code=200)

    next_run, incidents = fetch_incidents(client=mock_client, last_run=last_run, params=params)

    END_TIME = next_run.get('before_time')

    expected_next_run = {
        'after_time': '2024-06-14T06:17:17Z',
        'before_time': END_TIME,
        'cursor': '1718788282.118454',
        'alert_ids': ['00000000-0000-0000-0000-000000000001',
                      '00000000-0000-0000-0000-000000000002',
                      '00000000-0000-0000-0000-000000000003',
                      '00000000-0000-0000-0000-000000000004',
                      '00000000-0000-0000-0000-000000000005',]
    }

    assert incidents == incidents_response
    assert next_run == expected_next_run


def test_fetch_incidents_alerts_when_params_not_provided_and_last_run_provided(mocker, mock_client, requests_mock):
    """
    Test case scenario of fetch_incidents for fetch alerts when params not provided and last run is provided.

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Returns a valid command output.
    """
    from Ignite import fetch_incidents

    last_run = {
        'after_time': '2024-06-14T06:17:17Z',
        'before_time': '2024-06-17T06:17:17Z',
        'alert_ids': ['00000000-0000-0000-0000-000000000000']
    }

    mock_response: dict = util_load_json('test_data/fetch_alerts.json')

    incidents_response = util_load_json('test_data/incidents_alerts.json')

    demisto_params = {**BASIC_PARAMS, 'severity': 'Medium'}
    mocker.patch.object(demisto, 'params', return_value=demisto_params)
    mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["ALERTS"]}', json=mock_response, status_code=200)

    next_run, incidents = fetch_incidents(client=mock_client, last_run=last_run, params={
                                          'max_fetch': 201, 'fetch_type': 'Alerts'})

    END_TIME = next_run.get('before_time')

    expected_next_run = {
        'after_time': '2024-06-14T06:17:17Z',
        'before_time': END_TIME,
        'cursor': '1718788282.118454',
        'alert_ids': ['00000000-0000-0000-0000-000000000000',
                      '00000000-0000-0000-0000-000000000001',
                      '00000000-0000-0000-0000-000000000002',
                      '00000000-0000-0000-0000-000000000003',
                      '00000000-0000-0000-0000-000000000004',
                      '00000000-0000-0000-0000-000000000005',]
    }
    assert incidents == incidents_response
    assert next_run == expected_next_run


def test_fetch_incidents_alerts_to_check_duplicates_incidents(mock_client, requests_mock):
    """
    Test case scenario of fetch_incidents for fetch alerts to check duplicate records in response. .

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Returns a valid command output.
    """
    from Ignite import fetch_incidents

    last_run = {
        'after_time': '2024-06-14T06:17:17Z',
        'before_time': '2024-06-17T06:17:17Z',
        'alert_ids': ['00000000-0000-0000-0000-000000000001',
                      '00000000-0000-0000-0000-000000000002',
                      '00000000-0000-0000-0000-000000000003',
                      '00000000-0000-0000-0000-000000000004',
                      '00000000-0000-0000-0000-000000000005',]
    }

    mock_response: dict = util_load_json('test_data/fetch_alerts.json')

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["ALERTS"]}', json=mock_response, status_code=200)

    next_run, incidents = fetch_incidents(client=mock_client, last_run=last_run, params={'max_fetch': 1, 'fetch_type': 'Alerts'})

    END_TIME = next_run.get('before_time')

    expected_next_run = {
        'after_time': '2024-06-14T06:17:17Z',
        'before_time': END_TIME,
        'cursor': '1718788282.118454',
        'alert_ids': ['00000000-0000-0000-0000-000000000001',
                      '00000000-0000-0000-0000-000000000002',
                      '00000000-0000-0000-0000-000000000003',
                      '00000000-0000-0000-0000-000000000004',
                      '00000000-0000-0000-0000-000000000005',]
    }
    assert incidents == []
    assert next_run == expected_next_run


def test_fetch_incidents_alerts_when_invalid_arguments_provided(mock_client):
    """
    Test case scenario for execution of fetch_incidents for fetch alerts when invalid arguments provided.

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Raise error message.
    """
    from Ignite import fetch_incidents

    error_message = MESSAGES['INVALID_MAX_FETCH'].format('0')
    with pytest.raises(DemistoException) as error:
        fetch_incidents(client=mock_client, last_run={}, params={'max_fetch': 0, 'fetch_type': 'Alerts'})

    assert str(error.value) == error_message


def test_test_module_with_fetch_incidents_alerts(requests_mock, mock_client):
    """
    Test case scenario for execution of fetch_incident when is_test is true.

    Given:
        - mock client
    When:
        - Calling `fetch_incident` function
    Then:
        - Returns a valid output
    """
    from Ignite import fetch_incidents

    mock_response: dict = util_load_json('test_data/fetch_alerts.json')

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["ALERTS"]}', json=mock_response, status_code=200)

    next_run, incidents = fetch_incidents(client=mock_client, last_run={}, params={
                                          'max_fetch': 2, 'fetch_type': 'Alerts'}, is_test=True)

    assert next_run == {}
    assert incidents == []


def test_alert_list_command_success(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-alert-list command.

    Given:
       - command arguments for alert_list_command
    When:
       - Calling `alert_list_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import alert_list_command

    alerts = util_load_json('test_data/alert_list_success.json')
    alert_list_context = util_load_json('test_data/alert_list_success_context.json')
    with open('test_data/alert_list_success_hr.md') as file:
        hr_output_for_alerts = file.read()

    token_context = util_load_json('test_data/token_success_context.json')
    with open('test_data/token_success_hr.md') as file:
        hr_output_for_token = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["ALERTS"]}', json=alerts, status_code=200)

    args = {
        'size': '4',
        'created_at': '2024-06-11T05:54:25Z',
        'created_before': '2024-06-12T05:54:25Z'
    }
    actual_response = alert_list_command(mock_client, args)

    assert actual_response[0].outputs_prefix == OUTPUT_PREFIX['ALERT']
    assert actual_response[0].outputs_key_field == 'id'
    assert actual_response[0].readable_output == hr_output_for_alerts
    assert actual_response[0].outputs == alert_list_context
    assert actual_response[0].raw_response == alerts

    assert actual_response[1].outputs_prefix == OUTPUT_PREFIX['TOKEN']
    assert actual_response[1].outputs_key_field == 'name'
    assert actual_response[1].readable_output == hr_output_for_token
    assert actual_response[1].outputs == token_context


def test_alert_list_command_success_when_next_is_null(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-alert-list command when next is null.

    Given:
       - command arguments for alert_list_command
    When:
       - Calling `alert_list_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import alert_list_command

    alerts = util_load_json('test_data/alert_list_success_next_is_null.json')
    alert_list_context = util_load_json('test_data/alert_list_success_context_next_is_null.json')
    with open('test_data/alert_list_success_next_is_null_hr.md') as file:
        hr_output_for_alerts = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["ALERTS"]}', json=alerts, status_code=200)

    args = {
        'cursor': '0',
        'tags': 'tags1,tags2',
        'sources': 'source1,source2',
        'asset_ids': 'asset1,asset2',
        'query_ids': 'query1,query2',
        'asset_type': 'assert_type',
    }
    actual_response = alert_list_command(mock_client, args)

    assert actual_response[0].outputs_prefix == OUTPUT_PREFIX['ALERT']
    assert actual_response[0].outputs_key_field == 'id'
    assert actual_response[0].readable_output == hr_output_for_alerts
    assert actual_response[0].outputs == alert_list_context
    assert actual_response[0].raw_response == alerts


def test_alert_list_command_success_when_empty_response(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-alert-list command when empty response.

    Given:
       - command arguments for alert_list_command
    When:
       - Calling `alert_list_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import alert_list_command

    alerts = util_load_json('test_data/alert_list_success_empty_response.json')
    with open('test_data/alert_list_success_empty_response_hr.md') as file:
        hr_output_for_alerts = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["ALERTS"]}', json=alerts, status_code=200)

    actual_response = alert_list_command(mock_client, {'size': '1'})

    assert actual_response[0].readable_output == hr_output_for_alerts
    assert actual_response[0].raw_response == alerts


@pytest.mark.parametrize('args, error_msg', [
    ({'size': '0'}, MESSAGES['SIZE_ERROR'].format('0', MAX_ALERTS_LIMIT)),
    ({'size': '501'}, MESSAGES['SIZE_ERROR'].format('501', MAX_ALERTS_LIMIT)),
    ({'created_after': '2024-06-11T05:54:25Z', 'created_before': '2024-06-11T05:54:25Z'},
     MESSAGES['INVALID_TIME_INTERVAL'].format('created_after', 'created_before', '2024-06-11T05:54:25Z', '2024-06-11T05:54:25Z')),
    ({'status': 'tmpStatus'}, MESSAGES['INVALID_SINGLE_SELECT_PARAM'].format('tmpstatus', 'status', ALERT_STATUS_VALUES)),
    ({'origin': 'tmpOrigin'}, MESSAGES['INVALID_SINGLE_SELECT_PARAM'].format('tmporigin', 'origin', ALERT_ORIGIN_VALUES)),
    ({'asset_ip': 'abc.com'}, MESSAGES['INVALID_IP_ADDRESS'].format('abc.com'))
])
def test_alert_list_command_success_when_invalid_argument_provided(mock_client, args, error_msg):
    """
    Test case scenario for successful execution of flashpoint-ignite-alert-list command when invalid argument provided.

    Given:
       - command arguments for alert_list_command
    When:
       - Calling `alert_list_command` function
    Then:
       - Returns a valid error message.
    """
    from Ignite import alert_list_command

    with pytest.raises(ValueError) as err:
        alert_list_command(mock_client, args)

    assert str(err.value) == error_msg


def test_module_fetch_incidents_when_max_product_exceed_total_limit(mock_client, requests_mock):
    """
    Test case scenario for execution of fetch_incident compromised credentials when is_test is true.

    Given:
       - mocked client.
    When:
       - Calling `fetch_incidents` function
    Then:
       - Returns a valid error message.
    """
    from Ignite import fetch_incidents

    mock_response: dict = util_load_json('test_data/fetch_incidents_with_check_max_product.json')

    error_message = MESSAGES['TIME_RANGE_ERROR'].format('10005')
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response, status_code=200)

    with pytest.raises(ValueError) as error:
        fetch_incidents(client=mock_client, last_run={}, params={}, is_test=True)

    assert str(error.value) == error_message
