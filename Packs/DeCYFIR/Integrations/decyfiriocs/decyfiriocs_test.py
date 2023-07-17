from decyfiriocs import Client
from CommonServerPython import ThreatIntel
import json


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_convert_decyfir_ti_to_indicators_formats(mocker):
    raw_iocs_ti_data = util_load_json('test_data/iocs_ti.json')
    raw_ti_data = util_load_json('test_data/iocs.json')
    ti_data = raw_iocs_ti_data['threat_actors']

    client = Client(
        base_url='test_url',
        verify=False,
    )
    ti_data_out = client.convert_decyfir_ti_to_indicators_formats(decyfir_api_key='api_key', ti_data=ti_data,
                                                                  tlp_color='tlp_color',
                                                                  feed_tags=['feedTags'],
                                                                  threat_intel_type=ThreatIntel.ObjectsNames.THREAT_ACTOR,
                                                                  is_data_save=False)

    assert ti_data_out == raw_ti_data['IN_DATA_3']


def test_convert_decyfir_ioc_to_indicators_formats(mocker):
    raw_iocs_ti_data = util_load_json('test_data/iocs_ti.json')
    raw_ti_data = util_load_json('test_data/iocs.json')
    ti_data = raw_iocs_ti_data['iocs']

    client = Client(
        base_url='test_url',
        verify=False,
    )
    ti_data_out = client.convert_decyfir_ioc_to_indicators_formats(decyfir_api_key='api_key', decyfir_iocs=ti_data,
                                                                   tlp_color='tlp_color',
                                                                   feed_tags=['feedTags'],
                                                                   reputation='feedReputation',
                                                                   is_data_save=False)

    assert ti_data_out == raw_ti_data['IN_DATA_4']


def test_fetch_indicators(mocker):
    from decyfiriocs import Client, fetch_indicators_command
    mock_response1 = util_load_json('test_data/iocs_ti.json')
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
    mock_response1 = util_load_json('test_data/iocs_ti.json')
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
