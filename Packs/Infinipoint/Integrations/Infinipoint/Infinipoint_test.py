import json
import io


BASE_URL = 'https://test.com'
PAGE_SIZE = 100
INSECURE = False
ACCESS_KEY = "JX7XoBi9QRW1BMkPiaegKw"
PRIVATE_KEY = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIPFpFl9XuPtJfWmN4hVsuAkdaTYAegfJ/Q8eM"
MAX_INCIDENTS_TO_FETCH = 1000


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_devices_command(requests_mock):
    from Infinipoint import get_devices_client2_command, Client

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

    response = get_devices_client2_command('/api/devices', args, 'Infinipoint.Devices',
                                           'osName', client, pagination=False)

    assert response.outputs[0]['agentVersion'] == mock_response[0]['agentVersion']


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

    response = infinipoint_command(client, '/api/assets/programs', args, 'Infinipoint.Assets.Programs',
                                   'name', pagination=False)

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

    response = infinipoint_command(client, '/api/assets/hardware', args, 'Infinipoint.Assets.Hardware',
                                   '$host', pagination=False)

    assert response.outputs[0]['os_type'] == mock_response[0]['os_type']
