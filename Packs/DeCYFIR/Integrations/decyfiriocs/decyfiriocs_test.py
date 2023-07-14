import json


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_fetch_indicators(mocker):
    from decyfiriocs import Client, fetch_indicators_command
    mock_response1 = util_load_json('test_data/search_iocs.json')
    mock_response2 = util_load_json('test_data/iocs.json')

    client = Client(
        base_url='test_url',
        verify=False,
    )
    mocker.patch.object(Client, 'get_decyfir_api_iocs_ti_data', return_value=mock_response1['iocs'])

    data = fetch_indicators_command(
        client=client,
        decyfir_api_key='api_key',
        tlp_color='tlp_color',
        reputation='feedReputation', feed_tags=['feedTags']
    )

    assert data == mock_response2['IN_DATA_1']


def test_decyfir_get_indicators(mocker):
    from decyfiriocs import Client, decyfir_get_indicators_command
    mock_response1 = util_load_json('test_data/search_iocs.json')
    mock_response2 = util_load_json('test_data/iocs.json')

    client = Client(
        base_url='test_url',
        verify=False,
    )
    mocker.patch.object(Client, 'get_decyfir_api_iocs_ti_data', return_value=mock_response1['iocs'])
    data = decyfir_get_indicators_command(
        client=client,
        decyfir_api_key='api_key',
        tlp_color='tlp_color',
        reputation='feedReputation', feed_tags=['feedTags']
    )
    assert data.raw_response == mock_response2['IN_DATA_2']
