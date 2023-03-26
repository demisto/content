import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_events_command(requests_mock, mocker):
    """Tests get-events command function.

    Checks the output of the command function with the expected output.

    No mock is needed here because the say_hello_command does not call
    any external API.
    """
    from WithSecureEventCollector import Client, get_events_command

    client = Client(base_url='https://test.com', verify=False, proxy=False, client_id='client_id',
                    client_secret='client_secret')
    mock_response = util_load_json('test_data/get_events.json')
    args = {
        'fetch_from': '2022-12-26T00:00:00Z',
        'limit': 2
    }
    mocker.patch.object(Client, 'get_access_token', return_value={'access_token': 'access_token'})
    requests_mock.get(
        'https://test.com/security-events/v1/security-events?limit=2&serverTimestampStart=2022-12-26T00:00:00Z',
        json=mock_response)
    events, response = get_events_command(client, args)

    assert len(events) == 2
    assert events == mock_response.get('items')
