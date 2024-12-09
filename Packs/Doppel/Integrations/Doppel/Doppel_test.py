"""The file contains the Unit tests for the Doppel XSOAR integration
The unit tests are suppose to run to make sure that with the modification of the pack, there is not failures
Please write a new unit test for the behavior whenever the pack is modified for new features
"""

import json
import io
import requests_mock

from Doppel import Client, get_alert_command


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())

def test_get_alert_command(requests_mock):
    """Tests the get-alert command
    """

    client = Client(base_url='https://api.doppel.com', api_key='valid_api_key')
    args = {
        'id': 'TST-31222'
    }
    response_200 = util_load_json('test_data/get-alert-command-200.json')
    requests_mock.get(f'https://api.doppel.com/alert?id={args["id"]}', json=response_200)
    
    response = get_alert_command(client, args)

    mock_response = util_load_json('test_data/get-alert-command-200.json')

    assert response.outputs == mock_response

