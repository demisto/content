from CommonServerPython import *
from typing import Dict, Any, List

MOCK_URL = 'https://nonexistent-domain.com/'


def test_connection_success(requests_mock: Any) -> None:
    '''Command for test-connection'''

    expected_mocked_command_result: str = 'ok'
    requests_mock.get(f'{MOCK_URL}/api/app/info')
    assert expected_mocked_command_result


def test_connection_fail(requests_mock: Any) -> None:
    '''Command for test-connection'''

    expected_mocked_command_result: str = 'test connection failed'
    requests_mock.get(f'{MOCK_URL}/api/app/info')
    assert expected_mocked_command_result


def test_air_acquire_command(requests_mock: Any) -> None:
    from BinalyzeAIR import Client, air_acquire_command

    args: Dict[str, Any] = {
        'hostname': 'endpointhostname',
        'profile': 'quick',
        'case_id': 'case_id will be here',
        'organization_id': 0
    }

    mock_response: Dict[str, Any] = {
        "success": True,
        "result": [
            {
                "_id": "12345678-90ab-cdef-1234-567890abcdef",
                "name": "Example Case Acquisition X",
                "organizationId": 0
            }
        ],
        "statusCode": 200,
        "errors": []
    }
    headers: Dict[str, Any] = {
        'Authorization': 'Bearer api_key',
        'User-Agent': 'Binalyze AIR',
        'Content-type': 'application/json',
        'Accept-Charset': 'UTF-8'
    }
    client: Client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers=headers
    )
    expected_mocked_command_result: List[Dict[str, Any]] = mock_response
    requests_mock.post('https://nonexistent-domain.com/api/public/acquisitions/acquire', json=mock_response)

    mocked_command_result: CommandResults = air_acquire_command(client, args)

    assert mocked_command_result.outputs_prefix == 'BinalyzeAIR.Acquisition'
    assert mocked_command_result.outputs_key_field == 'hostname'
    assert mocked_command_result.outputs == expected_mocked_command_result


def test_air_isolate_command_enable(requests_mock: Any) -> None:
    from BinalyzeAIR import Client, air_isolate_command

    args: Dict[str, Any] = {
        'hostname': 'endpointhostname',
        'organization_id': 0,
        'isolation': True
    }

    mock_response: Dict[str, Any] = {
        "success": True,
        "result": [
            {
                "_id": "12345678-90ab-cdef-1234-567890abcdef",
                "name": "Isolation 001",
                "organizationId": 0
            }
        ],
        "statusCode": 200,
        "errors": []
    }

    headers: Dict[str, Any] = {
        'Authorization': 'Bearer api_key',
        'User-Agent': 'Binalyze AIR',
        'Content-type': 'application/json',
        'Accept-Charset': 'UTF-8'
    }
    client: Client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers=headers
    )
    expected_mocked_command_result: List[Dict[str, Any]] = mock_response
    requests_mock.post('https://nonexistent-domain.com/api/public/endpoints/tasks/isolation', json=mock_response)

    mocked_command_result: CommandResults = air_isolate_command(client, args)

    assert mocked_command_result.outputs_prefix == 'BinalyzeAIR.Isolate'
    assert mocked_command_result.outputs_key_field == 'hostname'
    assert mocked_command_result.outputs == expected_mocked_command_result


def test_air_isolate_command_disable(requests_mock: Any) -> None:
    from BinalyzeAIR import Client, air_isolate_command

    args: Dict[str, Any] = {
        'hostname': 'endpointhostname',
        'organization_id': 0,
        'isolation': False
    }

    mock_response: Dict[str, Any] = {
        "success": True,
        "result": [
            {
                "_id": "12345678-90ab-cdef-1234-567890abcdef",
                "name": "Isolation 001",
                "organizationId": 0
            }
        ],
        "statusCode": 200,
        "errors": []
    }

    headers: Dict[str, Any] = {
        'Authorization': 'Bearer api_key',
        'User-Agent': 'Binalyze AIR',
        'Content-type': 'application/json',
        'Accept-Charset': 'UTF-8'
    }
    client: Client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers=headers
    )
    expected_mocked_command_result: List[Dict[str, Any]] = mock_response
    requests_mock.post('https://nonexistent-domain.com/api/public/endpoints/tasks/isolation', json=mock_response)

    mocked_command_result: CommandResults = air_isolate_command(client, args)

    assert mocked_command_result.outputs_prefix == 'BinalyzeAIR.Isolate'
    assert mocked_command_result.outputs_key_field == 'hostname'
    assert mocked_command_result.outputs == expected_mocked_command_result
