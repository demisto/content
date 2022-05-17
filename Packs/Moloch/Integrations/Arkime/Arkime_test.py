import json
import io
from Arkime import Client, file_list_command


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_file_list_command():
    client = Client(server_url='url', verify=False, proxy=False, headers={}, auth={})
    args = {}
    response = file_list_command(client, args)

    mock_response = util_load_json('test_data/connection_list.json')

    assert response.outputs == mock_response


def test_connection_list_command():
    client = Client(server_url='https://www.example.com', verify=False, proxy=False, headers={}, auth={})
