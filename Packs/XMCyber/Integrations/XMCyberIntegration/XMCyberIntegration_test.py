import json
import io
from XMCyberIntegration import XM, Client, entity_get_command, PAGE_SIZE, URLS


TEST_URL = 'https://test.com'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def get_xm_mock():
    client = Client(
        base_url=TEST_URL,
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    return XM(client)


def mock_request_and_get_xm_mock(json_path, requests_mock, url_to_mock):
    json = util_load_json(json_path)
    requests_mock.get(url_to_mock, json=json)
    return get_xm_mock()


def test_entity_get(requests_mock):
    """Tests entity_get_command command function.

    Configures requests_mock instance to generate the appropriate search
    API response. Checks the output of the command function with the expected output.
    """

    mock_url = f'{TEST_URL}{URLS.Entities}?search=%2FCorporateDC%2Fi&page=1&pageSize={PAGE_SIZE}'
    xm = mock_request_and_get_xm_mock('test_data/entity_get.json', requests_mock, mock_url)

    response = entity_get_command(xm, {
        'name': 'CorporateDC'
    })

    assert response.outputs_prefix == 'XMCyber'
    assert response.outputs_key_field == 'entity_id'
    assert response.outputs == [{
        'entity_id': '3110337924893579985',
        'name': 'CorporateDC',
        'is_asset': True,
        'is_choke_point': True,
        'affected_assets': {
            'value': 14,
            'level': "medium"
        }
    }]
