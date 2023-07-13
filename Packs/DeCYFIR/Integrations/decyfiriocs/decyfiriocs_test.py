import json


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_fetch_indicators(mocker):
    from decyfiriocs import Client, fetch_indicators_command
    mock_response = util_load_json('test_data/search_iocs.json')

    client = Client(
        base_url='test_url',
        verify=False,
    )
    mocker.patch.object(Client, 'get_decyfir_api_iocs_ti_data', return_value=mock_response['iocs'])

    data = fetch_indicators_command(
        client=client,
        decyfir_api_key='api_key',
        tlp_color='tlp_color',
        reputation='feedReputation', feed_tags=['feedTags']
    )

    assert data == [
        {'Reputation': 'feedReputation',
         'fields': {'aliases': [],
                    'description': 'Sample Testing',
                    'firstseenbysource': '2023-07-11T06:21:42.110Z',
                    'geocountry': 'United States',
                    'ipv4-addr:value': '0.0.0.0',
                    'modified': '2023-07-11T06:21:42.110Z',
                    'stixid': 'indicator--e3eccca4-f0f6-4d89-90ae-85427b7894f3',
                    'tags': ['feedTags',
                             'group 83',
                             'macdownloader',
                             'parastoo',
                             'Charming Kitten'],
                    'trafficlightprotocol': 'tlp_color'},
         'rawJSON': {'created': '2023-07-11T06:21:42.110Z',
                     'description': 'Sample Testing',
                     'first_seen': '2022-06-06T00:00:00.000Z',
                     'id': 'indicator--e3eccca4-f0f6-4d89-90ae-85427b7894f3',
                     'indicator_types': ['attribution'],
                     'kill_chain_phases  ': ['Command & Control'],
                     'labels': [{'geographies': 'United States',
                                 'tags': ['group 83',
                                          'macdownloader',
                                          'parastoo',
                                          'Charming Kitten']}],
                     'last_seen': '2022-12-16T00:00:00.000Z',
                     'modified': '2023-07-11T06:21:42.110Z',
                     'name': '0.0.0.0',
                     'pattern': "[ipv4-addr:value = '0.0.0.0']",
                     'pattern_type': 'stix',
                     'spec_version': '2.1',
                     'type': 'indicator',
                     'valid_from': '2023-07-11T06:21:42.110Z'},
         'relationships': [],
         'service': 'DeCYFIR',
         'type': 'IP',
         'value': '0.0.0.0'},
        {'relationships': []}
    ]
