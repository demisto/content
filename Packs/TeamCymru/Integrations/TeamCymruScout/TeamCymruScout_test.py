'''TeamCymru for Cortex XSOAR - Unit Tests file'''

import json
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
import demistomock as demisto
import TeamCymruScout
from CommonServerPython import DemistoException, arg_to_datetime, DBotScoreReliability
from TeamCymruScout import API_KEY, BASE_URL, BASIC_AUTH, DATE_FORMAT, ENDPOINTS, Client, main, \
    MAXIMUM_INDICATOR_SEARCH_SIZE, ERROR_MESSAGES, OUTPUT_PREFIX, OUTPUT_KEY_FIELD, MAXIMUM_IP_LIST_SIZE, \
    MAXIMUM_DETAIL_IP_SIZE, scout_indicator_search_command, scout_ip_list_command


''' CONSTANTS '''


BASIC_PARAMS = {'authentication_type': API_KEY, 'api_key': {'password': API_KEY},
                'integrationReliability': 'A - Completely reliable'}
BASIC_AUTH_PARAMS = {'authentication_type': BASIC_AUTH, 'integrationReliability': 'A - Completely reliable',
                     'basic_auth': {'identifier': 'admin', 'password': API_KEY}}
IP_ARGS = {'ip': '0.0.0.1, 0.0. 0.1'}


''' UTILITY FUNCTIONS AND FIXTURES '''


def util_load_json(path: str) -> dict:
    '''Load a json to python dict.'''
    with open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def util_load_text_data(path: str) -> str:
    '''Load a text file.'''
    with open(path, mode='r', encoding='utf-8') as f:
        return f.read()


@pytest.fixture
def mock_client():
    '''Mock a client object with required data to mock.'''
    client = Client(BASE_URL, False, False, {}, None)
    return client


@pytest.mark.parametrize('params', [BASIC_PARAMS, BASIC_AUTH_PARAMS])
@patch('TeamCymruScout.return_results')
def test_test_module_using_main_function(mock_return, requests_mock, mocker, params):
    '''
    Test case scenario for successful execution of test_module through main function.

    Given:
       - mocked client.
    When:
       - Calling `test_module` function.
    Then:
       - Returns an ok message.
    '''
    response = util_load_json('test_data/scout_api_usage_response.json')

    requests_mock.get(f'{BASE_URL}{ENDPOINTS["QUERY_USAGE"]}', json=response, status_code=200)

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')

    main()
    assert 'ok' == mock_return.call_args.args[0]


@pytest.mark.parametrize('params, error_message', [
    ({'authentication_type': BASIC_AUTH}, ERROR_MESSAGES['NO_PARAM_PROVIDED'].format('Username')),
    ({'authentication_type': BASIC_AUTH, 'basic_auth': {'identifier': 'admin'}},
     ERROR_MESSAGES['NO_PARAM_PROVIDED'].format('Password')),
    ({'authentication_type': BASIC_AUTH, 'basic_auth': {'password': 'admin'}},
     ERROR_MESSAGES['NO_PARAM_PROVIDED'].format('Username')),
    ({'authentication_type': API_KEY}, ERROR_MESSAGES['NO_PARAM_PROVIDED'].format(API_KEY)),
])
def test_test_module_for_invalid_auth_using_main_function(requests_mock, mocker, params, capfd, error_message):
    '''
    Test case scenario for the execution of test_module with invalid authentication parameters.

    Given:
       - mocked client.
    When:
       - Calling `test_module` function.
    Then:
       - Returns exception.
    '''
    response = util_load_json('test_data/scout_api_usage_response.json')

    requests_mock.get(f'{BASE_URL}{ENDPOINTS["QUERY_USAGE"]}', json=response, status_code=200)

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    return_error = mocker.patch.object(TeamCymruScout, "return_error")

    capfd.close()
    main()

    assert error_message in return_error.call_args[0][0]


@patch('TeamCymruScout.return_results')
def test_scout_api_usage_command_using_main_function(mock_return, requests_mock, mocker):
    '''
    Test case scenario for successful execution of scout_api_usage_command through main function.

    Given:
       - mocked client.
    When:
       - Calling `scout_api_usage_command` function.
    Then:
       - Returns CommandResult.
    '''
    response = util_load_json('test_data/scout_api_usage_response.json')
    output = util_load_json('test_data/scout_api_usage_output.json')
    hr = util_load_text_data('test_data/scout_api_usage_hr.md')

    requests_mock.get(f'{BASE_URL}{ENDPOINTS["QUERY_USAGE"]}', json=response, status_code=200)

    mocker.patch.object(demisto, 'params', return_value=BASIC_PARAMS)
    mocker.patch.object(demisto, 'command', return_value='scout-api-usage')

    main()
    assert output == mock_return.call_args.args[0].outputs
    assert response == mock_return.call_args.args[0].raw_response
    assert hr == mock_return.call_args.args[0].readable_output
    assert 'command_name' == mock_return.call_args.args[0].outputs_key_field
    assert OUTPUT_PREFIX['QUERY_USAGE'] == mock_return.call_args.args[0].outputs_prefix


@patch('TeamCymruScout.return_results')
def test_ip_command_using_main_function(mock_return, requests_mock, capfd, mocker):
    '''
    Test case scenario for successful execution of ip_command through main function.

    Given:
       - mocked client.
    When:
       - Calling `ip_command` function.
    Then:
       - Returns CommandResult.
    '''
    response = util_load_json('test_data/ip_response.json')
    output = util_load_json('test_data/ip_output.json')
    ip_hr = util_load_text_data('test_data/ip_hr.md')
    query_usage_hr = util_load_text_data('test_data/scout_api_usage_hr.md')
    raw_response = util_load_json('test_data/ip_raw_response.json')
    ip_indicator = util_load_json('test_data/ip_indicator.json')
    ip_relationships = util_load_json('test_data/ip_relationships.json')

    requests_mock.get(f'{BASE_URL}{ENDPOINTS["IP_DETAILS"].format("0.0.0.1")}', json=response, status_code=200)

    # create_relationships parameter marked as true.
    BASIC_PARAMS['create_relationships'] = 'true'

    mocker.patch.object(demisto, 'params', return_value=BASIC_PARAMS)
    mocker.patch.object(demisto, 'args', return_value=IP_ARGS)
    mocker.patch.object(demisto, 'command', return_value='ip')

    capfd.close()
    main()

    assert output[0] == mock_return.call_args.args[0][0].outputs
    assert raw_response == mock_return.call_args.args[0][0].raw_response
    assert ip_hr == mock_return.call_args.args[0][0].readable_output
    assert OUTPUT_KEY_FIELD['IP'] == mock_return.call_args.args[0][0].outputs_key_field
    assert OUTPUT_PREFIX['IP'] == mock_return.call_args.args[0][0].outputs_prefix
    assert ip_indicator == mock_return.call_args.args[0][0].indicator.to_context()
    assert ip_relationships == [data.to_context() for data in mock_return.call_args.args[0][0].relationships]

    assert output[1] == mock_return.call_args.args[0][1].outputs
    assert raw_response == mock_return.call_args.args[0][1].raw_response
    assert query_usage_hr == mock_return.call_args.args[0][1].readable_output
    assert OUTPUT_KEY_FIELD['QUERY_USAGE'] == mock_return.call_args.args[0][1].outputs_key_field
    assert OUTPUT_PREFIX['QUERY_USAGE'] == mock_return.call_args.args[0][1].outputs_prefix


@pytest.mark.parametrize('args, error_message', [
    ({}, ERROR_MESSAGES['NO_PARAM_PROVIDED'].format('ip')),
    ({'ip': '0.0.0.1', 'start_date': '1 day', 'end_date': '2 day'}, ERROR_MESSAGES['START_DATE_GREATER_THAN_END_DATE']),
    ({'ip': '0.0.0.1', 'start_date': '2 day',
      'end_date': str((arg_to_datetime('now') + timedelta(days=2)).strftime(DATE_FORMAT))},
     ERROR_MESSAGES['END_DATE_GREATER_THAN_CURRENT_TIME']),
    ({'ip': '0.0.0.1', 'start_date': '60 day', 'end_date': '29 day'}, ERROR_MESSAGES['REACHED_MAXIMUM_DIFF_DAYS']),
    ({'ip': '0.0.0.1', 'start_date': '91 day', 'end_date': '70 day'}, ERROR_MESSAGES['REACHED_MAXIMUM_START_DAYS']),
    ({'ip': '0.0.0.1', 'days': '31'}, ERROR_MESSAGES['INVALID_DAY'].format('31')),
    ({'ip': '0.0.0.1', 'days': '0'}, ERROR_MESSAGES['INVALID_DAY'].format('0')),
    ({'ip': '0.0.0.1', 'size': '0'}, ERROR_MESSAGES['INVALID_PAGE_SIZE'].format('0', 1, MAXIMUM_DETAIL_IP_SIZE)),
    ({'ip': '0.0.0.1', 'size': MAXIMUM_DETAIL_IP_SIZE + 1},
     ERROR_MESSAGES['INVALID_PAGE_SIZE'].format(MAXIMUM_DETAIL_IP_SIZE + 1, 1, MAXIMUM_DETAIL_IP_SIZE))
])
def test_ip_command_for_invalid_arguments_using_main_function(mocker, args, capfd, error_message):
    '''
    Test case scenario for the execution of ip_command with invalid arguments.

    Given:
       - mocked client.
    When:
       - Calling `ip_command` function.
    Then:
       - Returns exception.
    '''
    mocker.patch.object(demisto, 'params', return_value=BASIC_PARAMS)
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'command', return_value='ip')
    return_error = mocker.patch.object(TeamCymruScout, "return_error")

    capfd.close()
    main()

    assert error_message in return_error.call_args[0][0]


def test_scout_indicator_search_command_success(mocker, mock_client, requests_mock):
    '''
    Test case scenario for successful execution of scout_indicator_search_command.

    Given:
       - mocked client.
    When:
       - Calling `scout_indicator_search_command` function.
    Then:
       - Assert for the output, raw response, readable output and indicator response.
    '''
    response = util_load_json('test_data/scout_indicator_search_response.json')
    output = util_load_json('test_data/scout_indicator_search_output.json')
    hr = util_load_text_data('test_data/scout_indicator_search_hr.md')
    usage_hr = util_load_text_data('test_data/scout_api_usage_hr.md')

    requests_mock.get(f'{BASE_URL}{ENDPOINTS["SEARCH_INDICATORS"]}', json=response, status_code=200)

    args = {'query': '0.0.0.1', 'limit': 1, 'start_date': '30 day', 'end_date': 'now', 'days': '1'}

    params = {'integrationReliability': DBotScoreReliability.B, 'create_relationships': True}
    mocker.patch.object(demisto, 'params', return_value=params)
    results = scout_indicator_search_command(mock_client, args)

    assert response['ips'][0] == results[0].raw_response
    assert hr == results[0].readable_output
    assert 'ip' == results[0].outputs_key_field
    assert OUTPUT_PREFIX['IP'] == results[0].outputs_prefix
    assert output['entry_context'] == results[0].to_context().get('EntryContext')

    del response['ips']
    assert response == results[1].raw_response
    usage_output = output['query_usage'].copy()
    usage_output['command_name'] = 'scout-indicator-search'
    assert usage_output == results[1].outputs
    assert usage_hr == results[1].readable_output
    assert 'command_name' == results[1].outputs_key_field
    assert OUTPUT_PREFIX['QUERY_USAGE'] == results[1].outputs_prefix


def test_scout_indicator_search_command_no_result(mock_client, requests_mock):
    '''
    Test case scenario for no result for scout_indicator_search_command.

    Given:
       - mocked client.
    When:
       - Calling `scout_indicator_search_command` function.
    Then:
       - Assert for the output, raw response, readable output and indicator response.
    '''
    response = util_load_json('test_data/scout_indicator_search_response.json')
    output = util_load_json('test_data/scout_indicator_search_output.json')
    usage_hr = util_load_text_data('test_data/scout_api_usage_hr.md')

    response['ips'] = None
    requests_mock.get(f'{BASE_URL}{ENDPOINTS["SEARCH_INDICATORS"]}', json=response, status_code=200)

    args = {'query': '0.0.0.1', 'limit': 1, 'start_date': '30 day', 'end_date': 'now', 'days': '1'}

    results = scout_indicator_search_command(mock_client, args)

    assert response['ips'] == results[0].raw_response
    assert ERROR_MESSAGES['NO_INDICATORS_FOUND'] == results[0].readable_output

    del response['ips']
    assert response == results[1].raw_response
    usage_output = output['query_usage'].copy()
    usage_output['command_name'] = 'scout-indicator-search'
    assert usage_output == results[1].outputs
    assert usage_hr == results[1].readable_output
    assert 'command_name' == results[1].outputs_key_field
    assert OUTPUT_PREFIX['QUERY_USAGE'] == results[1].outputs_prefix


@pytest.mark.parametrize('args, error_message', [
    ({}, ERROR_MESSAGES['NO_PARAM_PROVIDED'].format('query')),
    ({'query': '0.0.0.1', 'start_date': '1 day', 'end_date': '2 day'},
     ERROR_MESSAGES['START_DATE_GREATER_THAN_END_DATE']),
    ({'query': '0.0.0.1', 'start_date': '2 day',
      'end_date': (datetime.now() + timedelta(days=2)).strftime(DATE_FORMAT)},
     ERROR_MESSAGES['END_DATE_GREATER_THAN_CURRENT_TIME']),
    ({'query': '0.0.0.1', 'start_date': '60 day', 'end_date': '29 day'},
     ERROR_MESSAGES['REACHED_MAXIMUM_DIFF_DAYS']),
    ({'query': '0.0.0.1', 'start_date': '91 day', 'end_date': '70 day'},
     ERROR_MESSAGES['REACHED_MAXIMUM_START_DAYS']),
    ({'query': '0.0.0.1', 'days': '31'}, ERROR_MESSAGES['INVALID_DAY'].format('31')),
    ({'query': '0.0.0.1', 'days': '0'}, ERROR_MESSAGES['INVALID_DAY'].format('0')),
    ({'query': '0.0.0.1', 'size': '0'},
     ERROR_MESSAGES['INVALID_PAGE_SIZE'].format('0', 1, MAXIMUM_INDICATOR_SEARCH_SIZE)),
    ({'query': '0.0.0.1', 'size': MAXIMUM_INDICATOR_SEARCH_SIZE + 1},
     ERROR_MESSAGES['INVALID_PAGE_SIZE'].format(
         MAXIMUM_INDICATOR_SEARCH_SIZE + 1, 1, MAXIMUM_INDICATOR_SEARCH_SIZE)),
])
def test_scout_indicator_search_command_for_invalid_args(mock_client, args, error_message):
    '''
    Test case scenario for the execution of scout_indicator_search_command with invalid arguments.

    Given:
       - mocked client
    When:
       - Calling `scout_indicator_search_command` function.
    Then:
       - Returns exception.
    '''
    with pytest.raises(DemistoException) as err:
        scout_indicator_search_command(mock_client, args)

    assert str(err.value) == error_message


@patch('TeamCymruScout.return_warning')
def test_scout_ip_list_command_command_success(mock_return, mocker, mock_client, requests_mock):
    '''
    Test case scenario for successful execution of scout_ip_list_command_command.

    Given:
       - mocked client.
    When:
       - Calling `scout_ip_list_command_command` function.
    Then:
       - Assert for the output, raw response, readable output and indicator response.
    '''
    response = util_load_json('test_data/scout_ip_list_response.json')
    output = util_load_json('test_data/scout_ip_list_output.json')
    hr = util_load_text_data('test_data/scout_ip_list_hr.md')
    usage_hr = util_load_text_data('test_data/scout_api_usage_hr.md')

    requests_mock.get(f'{BASE_URL}{ENDPOINTS["LIST_IPS"]}', json=response, status_code=200)

    args = {'ip_addresses': '0.0.0.1,a.b.c.d,0:0:0:0:0:0:0:1'}

    params = {'integrationReliability': DBotScoreReliability.B, 'create_relationships': True}
    mocker.patch.object(demisto, 'params', return_value=params)
    results = scout_ip_list_command(mock_client, args)

    assert ERROR_MESSAGES['INVALID_IP_ADDRESSES'].format('a.b.c.d') == mock_return.call_args[0][0]

    assert response['data'][0] == results[0].raw_response
    assert hr == results[0].readable_output
    assert OUTPUT_KEY_FIELD['IP'] == results[0].outputs_key_field
    assert OUTPUT_PREFIX['IP'] == results[0].outputs_prefix
    assert output['entry_context'] == results[0].to_context().get('EntryContext')

    del response['data']
    assert response == results[1].raw_response
    usage_output = output['query_usage'].copy()
    usage_output['command_name'] = 'scout-ip-list'
    assert usage_output == results[1].outputs
    assert usage_hr == results[1].readable_output
    assert OUTPUT_KEY_FIELD['QUERY_USAGE'] == results[1].outputs_key_field
    assert OUTPUT_PREFIX['QUERY_USAGE'] == results[1].outputs_prefix


def test_scout_ip_list_command_no_result(mock_client, requests_mock):
    '''
    Test case scenario for no result for scout_ip_list_command.

    Given:
       - mocked client.
    When:
       - Calling `scout_ip_list_command` function.
    Then:
       - Assert for the output, raw response, readable output and indicator response.
    '''
    response = util_load_json('test_data/scout_ip_list_response.json')
    output = util_load_json('test_data/scout_ip_list_output.json')
    usage_hr = util_load_text_data('test_data/scout_api_usage_hr.md')

    response['data'] = None
    requests_mock.get(f'{BASE_URL}{ENDPOINTS["LIST_IPS"]}', json=response, status_code=200)

    args = {'ip_addresses': '0.0.0.1,0.0.0.2,0.0.0.3,0.0.0.4,0.0.0.5,0.0.0.6,0.0.0.7,0.0.0.8,0.0.0.9,0.0.0.10'}

    results = scout_ip_list_command(mock_client, args)

    assert response['data'] == results[0].raw_response
    assert ERROR_MESSAGES['NO_INDICATORS_FOUND'] == results[0].readable_output

    del response['data']
    assert response == results[1].raw_response
    usage_output = output['query_usage'].copy()
    usage_output['command_name'] = 'scout-ip-list'
    assert usage_output == results[1].outputs
    assert usage_hr == results[1].readable_output
    assert OUTPUT_KEY_FIELD['QUERY_USAGE'] == results[1].outputs_key_field
    assert OUTPUT_PREFIX['QUERY_USAGE'] == results[1].outputs_prefix


@pytest.mark.parametrize('reliability', [
    DBotScoreReliability.A_PLUS, DBotScoreReliability.A,
    DBotScoreReliability.B, DBotScoreReliability.C,
    DBotScoreReliability.D, DBotScoreReliability.E,
    DBotScoreReliability.F])
def test_scout_ip_list_command_with_different_reliability(mock_client, requests_mock, mocker, reliability):
    '''
    Test case scenario for the execution of scout_ip_list_command with different source reliability.

    Given:
       - mocked client
    When:
       - Calling `scout_ip_list_command` function.
    Then:
       - Assert for the output, raw response, readable output and indicator response.
    '''
    response = util_load_json('test_data/scout_ip_list_response.json')

    requests_mock.get(f'{BASE_URL}{ENDPOINTS["LIST_IPS"]}', json=response, status_code=200)

    args = {'ip_addresses': '0.0.0.1'}
    params = {'integrationReliability': reliability}
    mocker.patch.object(demisto, 'params', return_value=params)
    results = scout_ip_list_command(mock_client, args)

    assert results[0].indicator.dbot_score.reliability == reliability  # type: ignore


@pytest.mark.parametrize('args, error_message', [
    ({'ip_addresses': ', ,,, ,,,,,'}, ERROR_MESSAGES['NO_PARAM_PROVIDED'].format('ip_addresses')),
    ({'ip_addresses': ' '}, ERROR_MESSAGES['NO_PARAM_PROVIDED'].format('ip_addresses')),
    ({'ip_addresses': '0.0.0.1,0.0.0.2,0.0.0.3,0.0.0.4,0.0.0.5,0.0.0.6,0.0.0.7,0.0.0.8,0.0.0.9,0.0.0.10,0.0.0.11'},
     ERROR_MESSAGES['INVALID_IP_ADDRESS_SIZE'].format(11, MAXIMUM_IP_LIST_SIZE)),
])
def test_scout_ip_list_command_for_invalid_args(mock_client, args, error_message):
    '''
    Test case scenario for the execution of scout_ip_list_command with invalid arguments.

    Given:
       - mocked client.
    When:
       - Calling `scout_ip_list_command` function.
    Then:
       - Returns exception.
    '''
    with pytest.raises(DemistoException) as err:
        scout_ip_list_command(mock_client, args)

    assert str(err.value) == error_message


def test_scout_ip_list_command_for_all_ips_invalid(mock_client):
    '''
    Test case scenario for the execution of scout_ip_list_command with invalid ip addresses.

    Given:
       - mocked client.
    When:
       - Calling `scout_ip_list_command` function.
    Then:
       - Returns exception.
    '''
    args = {'ip_addresses': '0: 0: 85a3: 0000: asv: 8a2e: 0370: 7334,2.2.2'}
    with pytest.raises(SystemExit) as err:
        scout_ip_list_command(mock_client, args)

    assert err.value.code == 0
