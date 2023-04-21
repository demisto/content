import json
import io
import urllib.parse

from ResecurityMonitoring import PAGINATION_HEADER_NAME, MODULE_NAME_BREACHES, DEFAULT_PAGE_SIZE


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_task_monitor_results_command(requests_mock):
    from ResecurityMonitoring import Client, get_task_monitor_results_command

    page = 1
    task_id = 1

    params = {'id': task_id, 'module_name': MODULE_NAME_BREACHES, 'page': page, 'per-page': DEFAULT_PAGE_SIZE}
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
