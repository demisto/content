import json
import io

from CheckPointHEC import Client, checkpointhec_get_entity


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_checkpointhec_get_entity(mocker):
    client = Client(
        base_url='https://smart-api-example-1-us.avanan-example.net',
        client_id='****',
        client_secret='****',
        verify=False,
        proxy=False
    )

    mock_response = util_load_json('./test_data/checkpointhec-get_entity.json')
    mocker.patch.object(
        Client,
        'get_entity',
        return_value=mock_response,
    )

    result = checkpointhec_get_entity(client, '00000000000000000000000000000000')
    assert result.outputs == mock_response['responseData'][0]['entityPayload']
