from datetime import datetime, timedelta
import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_fetch_indicators(requests_mock, mocker):
    from decyfiriocs import Client, fetch_indicators_command
    date_format = '%Y-%m-%dT%H:%M:%SZ'
    mock_response = util_load_json('test_data/search_iocs.json')

    client = Client(
        base_url='test_url',
        verify=False,
    )
    mocker.patch.object(Client, 'request_decyfir_api', return_value=mock_response['iocs'])

    _, new_indicators = fetch_indicators_command(
        client=client,
        decyfir_api_key='api_key',
        tlp_color='tlp_color',
        reputation='feedReputation', feed_tags=['feedTags']
    )

    assert new_indicators == [{}]