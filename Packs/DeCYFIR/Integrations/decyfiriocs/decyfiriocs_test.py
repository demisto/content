from decyfiriocs import Client
from CommonServerPython import ThreatIntel
import json


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_indicator_or_threatintel_type(mocker):
    client = Client(
        base_url='test_url',
        verify=False,
        proxy=False,
    )
    da = client.get_indicator_or_threatintel_type("[ipv4-addr:value = '0.0.0.0']")
    assert da == "IP"


def test_build_ioc_relationship_obj(mocker):
    raw_iocs_ti_data = util_load_json('test_data/iocs.json')
    ta_data = raw_iocs_ti_data['IN_DATA_3']
    iocs_data = raw_iocs_ti_data['IN_DATA_1']

    client = Client(
        base_url='test_url',
        verify=False,
        proxy=False,
    )
    da = client.build_ioc_relationship_obj(iocs_data[0], ta_data[0])
    assert raw_iocs_ti_data["IN_DATA_5"][0] == da


def test_build_threat_actor_relationship_obj(mocker):
    raw_iocs_ti_data = util_load_json('test_data/iocs_ti.json')
    ins_data_in = raw_iocs_ti_data['intrusion_set']
    raw_iocs_data = util_load_json('test_data/iocs.json')
    ta_data = raw_iocs_data['IN_DATA_3']

    client = Client(
        base_url='test_url',
        verify=False,
        proxy=False,
    )

    ins_data_out = client.build_threat_intel_indicator_obj(data=ins_data_in[0],
                                                           tlp_color='tlp_color',
                                                           feed_tags=['feedTags'],
                                                           )

    da_re = client.build_threat_actor_relationship_obj(ta_data[0], ins_data_out)
    assert raw_iocs_data["IN_DATA_6"][0] == da_re


def test_build_threat_intel_indicator_obj(mocker):
    raw_iocs_ti_data = util_load_json('test_data/iocs_ti.json')

    raw_iocs_data = util_load_json('test_data/iocs.json')
    ta_data = raw_iocs_data['IN_DATA_3']
    ti_data = raw_iocs_ti_data['threat_actors']

    client = Client(
        base_url='test_url',
        verify=False,
        proxy=False,
    )

    ta_data_out = client.build_threat_intel_indicator_obj(data=ti_data[0],
                                                          tlp_color='tlp_color',
                                                          feed_tags=['feedTags'],
                                                          )

    assert ta_data[0] == ta_data_out


def test_build_ta_relationships_data(mocker):
    raw_iocs_ti_data = util_load_json('test_data/iocs_ti.json')

    raw_iocs_data = util_load_json('test_data/iocs.json')
    ta_data = raw_iocs_data['IN_DATA_7']
    ti_data = raw_iocs_ti_data['ta_relationships']

    client = Client(
        base_url='test_url',
        verify=False,
        proxy=False,
    )
    ta_source_obj = {}
    return_data = []

    ta_source_obj, src_ti_relationships_data, return_data = client.build_ta_relationships_data(ta_rel_data_coll=ti_data,
                                                                                               ta_source_obj=ta_source_obj,
                                                                                               return_data=return_data,
                                                                                               tlp_color='tlp_color',
                                                                                               feed_tags=['feedTags']
                                                                                               )
    ta_source_obj["relationships"] = src_ti_relationships_data
    return_data.append(ta_source_obj)
    assert ta_data == return_data


def test_add_aliases(mocker):
    raw_iocs_ti_data = util_load_json('test_data/iocs_ti.json')

    raw_iocs_data = util_load_json('test_data/iocs.json')
    ta_data = raw_iocs_data['IN_DATA_3'][0]
    ti_data = raw_iocs_ti_data['threat_actors']

    client = Client(
        base_url='test_url',
        verify=False,
        proxy=False,
    )

    ta_data_out = client.build_threat_intel_indicator_obj(data=ti_data[0],
                                                          tlp_color='tlp_color',
                                                          feed_tags=['feedTags'],
                                                          )
    al = ['sample']
    client.add_aliases(ta_data_out, al)
    ta_data["fields"]["aliases"].extend(al)
    assert ta_data["fields"]["aliases"] == ta_data_out["fields"]["aliases"]


def test_add_tags(mocker):
    raw_iocs_ti_data = util_load_json('test_data/iocs_ti.json')

    raw_iocs_data = util_load_json('test_data/iocs.json')
    ta_data = raw_iocs_data['IN_DATA_3'][0]
    ti_data = raw_iocs_ti_data['threat_actors']

    client = Client(
        base_url='test_url',
        verify=False,
        proxy=False,
    )

    ta_data_out = client.build_threat_intel_indicator_obj(data=ti_data[0],
                                                          tlp_color='tlp_color',
                                                          feed_tags=['feedTags'],
                                                          )
    al = ['sample']
    client.add_tags(ta_data_out, al)
    ta_data["fields"]["tags"].extend(al)
    assert ta_data["fields"]["tags"] == ta_data_out["fields"]["tags"]


def test_convert_decyfir_ti_to_indicator_format(mocker):
    raw_iocs_ti_data = util_load_json('test_data/iocs_ti.json')
    raw_ti_data = util_load_json('test_data/iocs.json')
    ti_data = raw_iocs_ti_data['threat_actors']

    client = Client(
        base_url='test_url',
        verify=False,
    )
    ti_data_out = client.convert_decyfir_ti_to_indicator_format(decyfir_api_key='api_key', data=ti_data[0],
                                                                tlp_color='tlp_color',
                                                                feed_tags=['feedTags'],
                                                                threat_intel_type=ThreatIntel.ObjectsNames.THREAT_ACTOR,
                                                                is_data_save=False)

    assert ti_data_out[0] == raw_ti_data['IN_DATA_3'][0]


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
