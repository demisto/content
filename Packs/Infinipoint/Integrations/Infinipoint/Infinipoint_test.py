import json
import io
from Infinipoint import COMMANDS_CONFIG

BASE_URL = 'https://test.com'
PAGE_SIZE = 100
INSECURE = False
ACCESS_KEY = "JX7XoBi9QRW1BMkPiaegKw"
PRIVATE_KEY = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIPFpFl9XuPtJfWmN4hVsuAkdaTYAegfJ/Q8eM"
MAX_INCIDENTS_TO_FETCH = 1000


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_programs_command(requests_mock):
    from Infinipoint import infinipoint_command, Client

    mock_response = util_load_json('test_data/get_assets_programs.json')

    requests_mock.post('http://test.com/api/assets/programs',
                       json=mock_response)

    args = {"name": "VMware"}

    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = infinipoint_command(client, args, COMMANDS_CONFIG['infinipoint-get-assets-programs'], False)
    assert response.outputs[0]['name'] == mock_response[0]['name']


def test_get_hardware_command(requests_mock):
    from Infinipoint import infinipoint_command, Client
    mock_response = util_load_json('test_data/get_assets_hardware.json')
    requests_mock.post('http://test.com/api/assets/hardware',
                       json=mock_response)
    args = {"os_type": "4"}
    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = infinipoint_command(client, args, COMMANDS_CONFIG['infinipoint-get-assets-devices'], pagination=False)
    assert response.outputs[0]['os_type'] == mock_response[0]['os_type']


def test_get_cloud_command(requests_mock):
    from Infinipoint import infinipoint_command, Client
    mock_response = util_load_json('test_data/get_assets_hardware.json')
    requests_mock.post('http://test.com/api/assets/cloud',
                       json=mock_response)
    args = {"source": "GCP API"}
    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = infinipoint_command(client, args, COMMANDS_CONFIG['infinipoint-get-assets-cloud'], pagination=False)
    assert response.outputs[0]['os_type'] == mock_response[0]['os_type']


def test_get_users_command(requests_mock):
    from Infinipoint import infinipoint_command, Client
    mock_response = util_load_json('test_data/get_assets_users.json')
    requests_mock.post('http://test.com/api/assets/users',
                       json=mock_response)
    args = {"source": "GCP API"}
    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = infinipoint_command(client, args, COMMANDS_CONFIG['infinipoint-get-assets-users'], pagination=False)
    assert response.outputs[0]['username'] == mock_response[0]['username']


def test_get_devices_command(requests_mock):
    from Infinipoint import infinipoint_command, Client
    mock_response = util_load_json('test_data/get_assets_devices.json')
    requests_mock.post('http://test.com/api/devices',
                       json=mock_response)
    args = {
        "os_type": "1"
    }
    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = infinipoint_command(client, args, COMMANDS_CONFIG['infinipoint-get-device'], pagination=False)
    assert response.outputs[0]['agentVersion'] == mock_response[0]['agentVersion']


def test_get_vulnerable_devices_command(requests_mock):
    from Infinipoint import infinipoint_command, Client
    mock_response = util_load_json('test_data/get_vulnerable_devices.json')
    requests_mock.post('http://test.com/api/vulnerability/devices',
                       json=mock_response)
    args = {
        "cve_id": "CVE-2020-1301"
    }
    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = infinipoint_command(client, args, COMMANDS_CONFIG['infinipoint-get-vulnerable-devices'], pagination=False)
    assert response.outputs[0]['os_name'] == mock_response[0]['os_name']


def test_get_tag_command(requests_mock):
    from Infinipoint import infinipoint_command, Client
    mock_response = util_load_json('test_data/get_tag.json')
    requests_mock.post('http://test.com/api/tags',
                       json=mock_response)
    args = {
        "name": "et"
    }
    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = infinipoint_command(client, args, COMMANDS_CONFIG['infinipoint-get-tag'], pagination=False)
    assert response.outputs[0]['name'] == mock_response[0]['name']


def test_get_networks_command(requests_mock):
    from Infinipoint import infinipoint_command, Client
    mock_response = util_load_json('test_data/get_networks.json')
    requests_mock.post('http://test.com/api/networks',
                       json=mock_response)
    args = {
        "alias": "GCP"
    }
    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = infinipoint_command(client, args, COMMANDS_CONFIG['infinipoint-get-networks'], pagination=False)
    assert response.outputs[0]['alias'] == mock_response[0]['alias']


def test_get_queries_command(requests_mock):
    from Infinipoint import infinipoint_command, Client
    mock_response = util_load_json('test_data/get_queries.json')
    requests_mock.post('http://test.com/api/all-scripts/search',
                       json=mock_response)
    args = {
        "name": "Kernel version"
    }
    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = infinipoint_command(client, args, COMMANDS_CONFIG['infinipoint-get-queries'], pagination=False)
    assert response.outputs[0]['name'] == mock_response[0]['name']


def test_run_queries_command(requests_mock):
    from Infinipoint import run_queries_command, Client
    mock_response = util_load_json('test_data/run-queries.json')
    requests_mock.post('http://test.com/api/all-scripts/execute',
                       json=mock_response)
    args = {
        "id": "0b5004ce-0a18-11ea-9a9f-362b9e155667"
    }
    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = run_queries_command(client, args, COMMANDS_CONFIG['infinipoint-execute-action'])
    assert response.outputs['name'] == mock_response['name']


def test_device_details_command(requests_mock):
    from Infinipoint import infinipoint_command, Client
    mock_response = util_load_json('test_data/get_devices_details.json')
    args = {
        "discoveryId": "23eb50e7ceb907975686ba5cebbd3520"
    }
    requests_mock.get(f'http://test.com/api/discover/details/{args.get("discoveryId")}',
                      json=mock_response)
    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = infinipoint_command(client, args, COMMANDS_CONFIG['infinipoint-get-device-details'], pagination=False)
    assert response.outputs['$device'] == mock_response['$device']


def test_cve_command(requests_mock):
    from Infinipoint import infinipoint_command, Client

    mock_response = util_load_json('test_data/get_cve.json')
    args = {
        "cve_id": "CVE-2020-1301"
    }
    requests_mock.get(f'http://test.com/api/vulnerability/{args.get("cve_id")}/details', json=mock_response)
    client = Client(
        base_url='http://test.com',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    response = infinipoint_command(client, args, COMMANDS_CONFIG['infinipoint-get-cve'], pagination=False)
    assert response.outputs['cve_id'] == mock_response['cve_id']
