import io
import json

from CommonServerPython import *
from typing import Dict, Any

MOCK_URL = 'https://nonexistent-domain.com'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_api_success(requests_mock: Any) -> None:
    '''Successful test for the test-api command'''
    from BinalyzeAIR import Client, test_connection

    mock_response: Dict[str, bool] = {
        'statusCode': 200
    }

    expected_mocked_command_result: str = 'ok'

    requests_mock.get('https://nonexistent-domain.com/api/public/endpoints?filter[organizationIds]=0', json=mock_response)

    client: Client = Client(
        base_url='https://nonexistent-domain.com',
        verify=False
    )

    mocked_command_result: str = test_connection(client)
    if mocked_command_result is expected_mocked_command_result:
        assert mocked_command_result == expected_mocked_command_result


def test_api_fail(requests_mock: Any) -> None:
    '''Authorization fail test for the test-api command.'''

    from BinalyzeAIR import Client, test_connection

    mock_response: str = 'Authorization Error'

    expected_mocked_command_result: str = 'Authorization Error: Make sure API Key is correctly set.'

    requests_mock.get('https://nonexistent-domain.com/api/public/endpoints?filter[organizationIds]=0', json=mock_response)

    client: Client = Client(
        base_url='https://nonexistent-domain.com',
        verify=False
    )

    mocked_command_result: str = test_connection(client)
    if mocked_command_result is expected_mocked_command_result:
        assert mocked_command_result == expected_mocked_command_result


def test_api_connection_fail(requests_mock: Any) -> None:
    '''Connectivity fail test for the test-api command.'''

    from BinalyzeAIR import Client, test_connection

    mock_response: str = 'Connection Error'

    expected_mocked_command_result: str = 'Connection Error: Test connection failed.'

    requests_mock.get('https://nonexistent-domain.com/api/public/endpoints?filter[organizationIds]=0', json=mock_response)

    client: Client = Client(
        base_url='https://nonexistent-domain.com',
        verify=False
    )

    mocked_command_result: str = test_connection(client)
    if mocked_command_result is expected_mocked_command_result:
        assert mocked_command_result == expected_mocked_command_result


def test_air_acquire_command(requests_mock: Any) -> None:
    from BinalyzeAIR import Client, air_acquire_command

    args: Dict[str, Any] = {
        'hostname': 'endpointhostname',
        'profile': 'quick',
        'case_id': 'case_id will be here',
        'organization_id': 0
    }

    headers: Dict[str, Any] = {
        'Authorization': 'Bearer api_key',
        'User-Agent': 'Binalyze AIR',
        'Content-type': 'application/json',
        'Accept-Charset': 'UTF-8'
    }
    mock_response = util_load_json('test_data/test_acquire_success.json')

    client: Client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers=headers
    )

    requests_mock.post('https://nonexistent-domain.com/api/public/acquisitions/acquire', json=mock_response)

    mocked_command_result: CommandResults = air_acquire_command(client, args)
    mocked_readable_output = util_load_json('test_data/test_acquire_success.json').get('results')
    mocked_command_output = {
        'Result': mock_response.get('result'),
        'Success': mock_response.get('success')
    },
    if mocked_command_result == 404:
        assert mocked_readable_output == 'No contex for queried hostname.'

    assert mocked_command_result.outputs_prefix == 'BinalyzeAIR.Acquisition'
    assert mocked_command_result.outputs_key_field == 'hostname'
    assert mocked_command_output


def test_air_isolate_command(requests_mock: Any) -> None:
    from BinalyzeAIR import Client, air_isolate_command

    args: Dict[str, Any] = {
        'hostname': 'endpointhostname',
        'organization_id': 0,
        'isolation': True
    }
    headers: Dict[str, Any] = {
        'Authorization': 'Bearer api_key',
        'User-Agent': 'Binalyze AIR',
        'Content-type': 'application/json',
        'Accept-Charset': 'UTF-8'
    }
    mock_response = util_load_json('test_data/test_isolate_success.json')

    client: Client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers=headers
    )
    requests_mock.post('https://nonexistent-domain.com/api/public/endpoints/tasks/isolation', json=mock_response)

    mocked_command_result: CommandResults = air_isolate_command(client, args)
    mocked_readable_output = util_load_json('test_data/test_isolate_success.json').get('results')
    mocked_command_output = {
        'Result': mock_response.get('result'),
        'Success': mock_response.get('success')
    },
    if mocked_command_result == 404:
        assert mocked_readable_output == 'No contex for queried hostname.'

    assert mocked_command_result.outputs_prefix == 'BinalyzeAIR.Isolate'
    assert mocked_command_result.outputs_key_field == 'hostname'
    assert mocked_command_output
