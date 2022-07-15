import json
from unittest.mock import patch
import pytest

from LogsignSiem import *
from test_data.sample_data import *

import demistomock

TEST_URL = "https://example.com"


def get_client(url: str = TEST_URL, api_key: str = "apikey", verify: bool = False, proxy: bool = False):
    return Client(url=url, api_key=api_key, verify=verify, proxy=proxy)


def test_check_args():
    mock_data = CHECK_ARG_MOCK_DATA
    assert check_arg('test_int', mock_data) == 15
    assert check_arg('test_str', mock_data) == "logsign"
    assert check_arg('test_list', mock_data) == [1, 2, 3]
    assert check_arg('test_dict', mock_data) == {"str": "unix"}
    with pytest.raises(ValueError):
        check_arg('unknown', mock_data)


def test_client_general_exc():
    client = get_client(url="Logsign")
    with pytest.raises(Exception):
        client._http_request('GET', '/url_suffix', params={"args": 1})


def test_client_type_error():
    client = get_client(url="Logsign")
    with pytest.raises(TypeError):
        client._http_request()


def test_get_generic_data():
    mock_data = {
        "incidents": [1, 2, 3]
    }
    result = get_generic_data(data=mock_data, key='incidents', output_prefix='Logsign.Incidents')
    assert result.outputs_prefix == 'Logsign.Incidents'
    assert result.outputs == mock_data
    assert result.raw_response == json.dumps(mock_data)


def test_get_query_command(requests_mock):
    mock_args = {'query': '*', 'grouped_column': 'Source.IP', 'criteria': 'value', 'time_frame': '1 day'}
    mock_q_result = {"success": True, "columns": ["8.8.8.8", "8.8.4.4"]}
    requests_mock.get(
        f'{TEST_URL}/get_columns?api_key=apikey&query=*&grouped_column=Source.IP&criteria=value&time_frame=1%20day',
        json=mock_q_result)
    client = get_client()
    response = get_query_command(client=client, url_suffix='get_columns', args=mock_args)
    assert response.raw_response == json.dumps(mock_q_result)
    assert response.outputs_prefix == 'LogsignSiem.Columns'
    assert json.loads(response.raw_response)['columns'] == mock_q_result['columns']


def test_api_check_command(requests_mock):
    mock_resp = {'result': 'ok'}
    requests_mock.get(f'{TEST_URL}/test_api?api_key=apikey', json=mock_resp)
    client = get_client()
    response = api_check_command(client)
    assert response == mock_resp['result']


def test_api_check_command_fail(requests_mock):
    mock_resp = 'Authorization Error: Make sure Logsign Discovery API Key is correctly set'
    requests_mock.get(f'{TEST_URL}/test_api?api_key=apikey', exc=mock_resp)
    client = get_client()
    with pytest.raises(ValueError):
        api_check_command(client)


def test_get_query_command_count(requests_mock):
    mock_args = {'query': '*', 'grouped_column': 'Source.IP', 'criteria': 'value', 'time_frame': '1 day'}
    mock_q_result = {"success": True, "count": 783327}
    requests_mock.get(
        f'{TEST_URL}/get_count?api_key=apikey&query=*&grouped_column=Source.IP&criteria=value&time_frame=1%20day',
        json=mock_q_result)
    client = get_client()
    response = get_query_command(client=client, url_suffix='get_count', args=mock_args)
    assert response.raw_response == json.dumps(mock_q_result)
    assert response.outputs_prefix == 'LogsignSiem.Count'
    assert json.loads(response.raw_response)['count'] == mock_q_result['count']


def test_main_success(mocker):
    """
        When main function called test function should call.
    """
    import LogsignSiem

    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(LogsignSiem, 'api_check_command', return_value='ok')
    LogsignSiem.main()
    assert LogsignSiem.api_check_command.called


@patch('LogsignSiem.return_error')
def test_main_failure(mock_return_error, mocker):
    """
        When main function get some exception then valid message should be print.
    """
    import LogsignSiem
    mocker.patch.object(demisto, 'error')
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(LogsignSiem, 'api_check_command', side_effect=Exception)
    LogsignSiem.main()

    mock_return_error.assert_called_once_with('Error: ')


def test_get_columns_q_cmd(mocker):
    """
        When main function called test function should call.
    """
    import LogsignSiem

    mocker.patch.object(demisto, 'args', return_value=ARGS_Q)
    mocker.patch.object(demisto, 'command', return_value='logsign-get-columns-query')
    mocker.patch.object(LogsignSiem, 'get_query_command', return_value=RESULT_COLUMNS_HR)

    LogsignSiem.main()
    assert LogsignSiem.get_query_command.called


def test_get_count_q_cmd(mocker):
    """
        When main function called test function should call.
    """
    import LogsignSiem

    mocker.patch.object(demisto, 'args', return_value=ARGS_Q)
    mocker.patch.object(demisto, 'command', return_value='logsign-get-count-query')
    mocker.patch.object(LogsignSiem, 'get_query_command', return_value=RESULT_COUNT_HR)

    LogsignSiem.main()
    assert LogsignSiem.get_query_command.called


def test_get_incidents(requests_mock):
    last_run = '2021-05-03T13:00:00Z'
    requests_mock.get(f'{TEST_URL}/get_incidents?api_key=apikey&last_run={last_run}', json=MOCK_INCIDENTS)
    client = get_client()
    response = client.get_incidents('GET', datetime.strptime(last_run, DATE_FORMAT), '')
    assert response == MOCK_INCIDENTS


def test_fetch_incidents(requests_mock):
    last_run = "2021-04-21T00:00:00Z"
    next_run = {'last_fetch': '2021-04-21T01:00:00Z'}
    requests_mock.get(f"{TEST_URL}/get_incidents?api_key=apikey&last_run={last_run}", json=MOCK_INC)
    client = get_client()
    resp = client.get_incidents('GET', datetime.strptime(last_run, DATE_FORMAT), '')
    demistomock.setLastRun({'last_fetch': last_run})
    assert len(resp['incidents']) == 2
    assert resp['incidents'] == MOCK_INC['incidents']
    assert next_run['last_fetch'] == resp['last_fetch']
