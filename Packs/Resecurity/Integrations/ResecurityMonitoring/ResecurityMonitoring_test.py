import json
import io
import urllib.parse

import pytest

from ResecurityMonitoring import PAGINATION_HEADER_NAME, MODULE_NAME_BREACHES, DEFAULT_PAGE_SIZE, DEFAULT_MODE


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_test_module(requests_mock):
    from ResecurityMonitoring import Client, test_module, DemistoException
    url = 'https://test.com/api/monitor/check-connection'

    mock_response = util_load_json('test_data/test_module_result.json')
    requests_mock.get(url, json=mock_response)

    client = Client(
        base_url='https://test.com/api/',
        verify=False,
        auth=('some_api_key', ''),
    )

    result_message = test_module(client)
    assert result_message == mock_response["message"]

    # case when message is empty - the result is fail
    requests_mock.get(url, json={})
    with pytest.raises((DemistoException),
                       match="Failed to establish connection with provided credentials."):
        test_module(client)


def test_get_task_monitor_results_command(requests_mock):
    from ResecurityMonitoring import Client, get_task_monitor_results_command, DemistoException

    page = 1
    task_id = 1

    params = {'id': task_id,
              'module_name': MODULE_NAME_BREACHES,
              'page': page,
              'per-page': DEFAULT_PAGE_SIZE,
              'mode': DEFAULT_MODE
              }
    url = 'https://test.com/api/monitor/task-results-by-module?' + urllib.parse.urlencode(params)

    mock_response = util_load_json('test_data/get_task_monitor_results.json')

    requests_mock.get(url,
                      headers={PAGINATION_HEADER_NAME: str(page)},
                      json=mock_response)

    client = Client(
        base_url='https://test.com/api/',
        verify=False,
        auth=('some_api_key', ''),
    )

    args = {
        'monitor_task_id': task_id
    }

    command_function = get_task_monitor_results_command(MODULE_NAME_BREACHES)
    response = command_function(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == 'Resecurity.DataBreach'
    assert response.outputs_key_field == 'id'

    # case when the 'page' arg is not None
    page_arg = 2
    params = {'id': task_id,
              'module_name': MODULE_NAME_BREACHES,
              'page': page_arg,
              'per-page': DEFAULT_PAGE_SIZE,
              'mode': DEFAULT_MODE
              }
    url = 'https://test.com/api/monitor/task-results-by-module?' + urllib.parse.urlencode(params)

    mock_response = util_load_json('test_data/get_task_monitor_results.json')
    requests_mock.get(url,
                      headers={PAGINATION_HEADER_NAME: str(page)},
                      json=mock_response)

    args = {
        'monitor_task_id': task_id,
        'page': page_arg,
    }

    response = command_function(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == 'Resecurity.DataBreach'
    assert response.outputs_key_field == 'id'

    # check that 'per_page' value is not bigger that 'limit' value
    params = {'id': task_id,
              'module_name': MODULE_NAME_BREACHES,
              'page': page,
              'per-page': 1,
              'mode': DEFAULT_MODE
              }
    url = 'https://test.com/api/monitor/task-results-by-module?' + urllib.parse.urlencode(params)

    mock_response = util_load_json('test_data/get_task_monitor_results.json')
    requests_mock.get(url,
                      headers={PAGINATION_HEADER_NAME: str(page)},
                      json=mock_response)

    args = {
        'monitor_task_id': task_id,
        'per-page': 5,
        'limit': 1
    }

    response = command_function(client, args)

    assert response.outputs == mock_response[:1]
    assert response.outputs_prefix == 'Resecurity.DataBreach'
    assert response.outputs_key_field == 'id'

    # check for raising an error if header does not consist of pagination value
    requests_mock.get(url,
                      json=mock_response)
    with pytest.raises((DemistoException),
                       match="Something is wrong, header {0} is empty for API request".format(PAGINATION_HEADER_NAME)):
        command_function(client, args)
