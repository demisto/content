import pytest
import io
from CommonServerPython import *
from StellarCyber import Client, get_alert_command, close_case_command, update_case_command
SERVER_URL = 'https://test.example.com'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return Client(dp_host='test.example.com', username='test', password='test', verify=True, proxy=None, tenantid=None)

def test_get_alert_command(client, requests_mock):
    args = {
        "alert_id": "1710883791406342b1f41b2247774d60bf035a6f98e5ff21"
    }
    mock_response_get_alert = util_load_json(
        './test_data/outputs/get_alert.json')
    mock_results = util_load_json('./test_data/outputs/get_alert_command.json')
    mock_token = {
        'data': {
            'access_token': 'example',
            'expiration_utc': time.ctime(time.time() + 10000)
        }
    }
    requests_mock.post(f'{SERVER_URL}/connect/api/v1/access_token', json=mock_token)
    requests_mock.get(f"{SERVER_URL}/connect/api/data/aella-ser-*/_search?q=_id:{args['alert_id']}", json=mock_response_get_alert)
    results = get_alert_command(client=client, args=args)
    assert results.outputs_prefix == 'StellarCyber.Alert'
    assert results.outputs_key_field == 'alert_id'
    assert results.outputs == mock_results.get('outputs')


def test_close_case_command(client, requests_mock):
    args = {
        "stellar_case_id": "65f340d9b190d36b26ad2bdc",
        "stellar_close_reason": "Example..."
    }
    mock_response_close_case = util_load_json(
        './test_data/outputs/close_case.json')
    mock_results = util_load_json('./test_data/outputs/close_case_command.json'
                                  )
    mock_token = {
        'data': {
            'access_token': 'example',
            'expiration_utc': time.ctime(time.time() + 10000)
        }
    }
    requests_mock.post(f'{SERVER_URL}/connect/api/v1/access_token', json=mock_token)
    requests_mock.post(f'{SERVER_URL}/connect/api/v1/incidents?id={args["stellar_case_id"]}', json=mock_response_close_case)
    results = close_case_command(client=client, args=args)
    assert results.outputs_prefix == 'StellarCyber.Case.Close'
    assert results.outputs_key_field == '_id'
    assert results.outputs == mock_results.get('outputs')


def test_update_case_command(client, requests_mock):
    args = {
        "stellar_case_id": "65f340d9b190d36b26ad2bdc",
        "stellar_case_status": "New"
    }
    mock_response_update_case = util_load_json(
        './test_data/outputs/update_case.json')
    mock_results = util_load_json(
        './test_data/outputs/update_case_command.json')
    mock_token = {
        'data': {
            'access_token': 'example',
            'expiration_utc': time.ctime(time.time() + 10000)
        }
    }
    requests_mock.post(f'{SERVER_URL}/connect/api/v1/access_token', json=mock_token)
    requests_mock.post(f'{SERVER_URL}/connect/api/v1/incidents?id={args["stellar_case_id"]}', json=mock_response_update_case)
    results = update_case_command(client=client, args=args)
    assert results.outputs_prefix == 'StellarCyber.Case.Update'
    assert results.outputs_key_field == '_id'
    assert results.outputs == mock_results.get('outputs')
