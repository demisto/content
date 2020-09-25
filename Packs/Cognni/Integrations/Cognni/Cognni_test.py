import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_ping(requests_mock):
    """Tests the ping command
    """
    from Cognni import Client, ping_command

    mock_response = util_load_json('test_data/ping_response.json')
    requests_mock.post('https://stage-webapi.cognni.ai/intelligence/data/graphql',
                       json=mock_response)

    client = Client(
        base_url='https://stage-webapi.cognni.ai',
        verify=False,
        headers={
            'Authorization': 'Bearer some_api_key'
        }
    )

    response = ping_command(client)

    # assert response.outputs[0] == mock_response
    assert response.outputs_prefix == 'Cognni.ping'
    assert response.raw_response['ping'] == 'pong'
