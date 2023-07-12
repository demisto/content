import json


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_fetch_indicators(requests_mock, mocker):
    from decyfiriocs import Client, fetch_indicators_command
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

    assert new_indicators == [{
        "iocs": [
            {
                "type": "indicator",
                "name": "192.30.255.113",
                "description": "Early Campaign - UNC054",
                "created": "2023-07-11T06:21:42.110Z",
                "modified": "2023-07-11T06:21:42.110Z",
                "indicator_types": [
                    "attribution"
                ],
                "pattern": "[ipv4-addr:value = '192.30.255.113']",
                "pattern_type": "stix",
                "valid_from": "2023-07-11T06:21:42.110Z",
                "kill_chain_phases  ": [
                    "Command & Control"
                ],
                "spec_version": "2.1",
                "labels": [
                    {
                        "geographies": "United States",
                        "tags": [
                            "group 83",
                            "macdownloader",
                            "parastoo",
                            "Charming Kitten",
                            "elfin",
                            "ikittens",
                            "charming kitten",
                            "apt33",
                            "newsbeef",
                            "apt 35",
                            "magic hound",
                            "ta453",
                            "temp.beanie",
                            "cobalt gypsy",
                            "phosphorus",
                            "TA505",
                            "ta505",
                            "atk 103",
                            "chimborazo",
                            "evil corp",
                            "gold evergreen",
                            "gold tahoe",
                            "graceful spider",
                            "hive0065",
                            "sectorj04",
                            "ta 505",
                            "ta-505",
                            "unc054",
                            "dev-0206",
                            "dev-0243",
                            "silence group"
                        ]
                    }
                ],
                "first_seen ": "2022-06-06T00:00:00.000Z",
                "last_seen ": "2022-12-16T00:00:00.000Z"
            }
        ]
    }]
