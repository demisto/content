from decyfiriocs import Client
import json


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_get_indicator_or_threatintel_type(mocker):
    client = Client(
        base_url="test_url",
        verify=False,
        proxy=False,
    )
    da = client.get_indicator_or_threatintel_type("[ipv4-addr:value = '0.0.0.0']")
    assert da == "IP"


def test_build_ioc_relationship_obj(mocker):
    raw_iocs_ti_data = util_load_json("test_data/iocs.json")
    ta_data = raw_iocs_ti_data["IN_DATA_3"]
    iocs_data = raw_iocs_ti_data["IN_DATA_1"]

    client = Client(
        base_url="test_url",
        verify=False,
        proxy=False,
    )
    da = client.build_ioc_relationship_obj(iocs_data[0], ta_data[0])
    assert raw_iocs_ti_data["IN_DATA_5"][0] == da
    assert da["entityA"] == "0.0.0.0"
    assert da["entityB"] == "Gibberish Panda"


# def test_build_ioc_relationship_obj(mocker):
#     raw_data = util_load_json("test_data/iocs_ti.json")


#     client = Client(
#         base_url="test_url",
#         verify=False,
#         proxy=False,
#     )

#     source_data = client.convert_decyfir_ioc_to_indicators_formats(
#         decyfir_api_key="api_key",
#         decyfir_iocs=raw_data["iocs"],
#         tlp_color="tlp_color",
#         feed_tags=["feedTags"],
#         reputation="feedReputation",
#         is_data_save=False,
#     )

#     target_data = client.build_threat_intel_indicator_obj(
#         data=raw_data["threat_actors"][0], tlp_color="tlp_color", feed_tags=["feedTags"]
#     )

#     da = client.build_ioc_relationship_obj(source_data[0], target_data)
#     assert da["entityA"] ==  "0.0.0.0"
#     assert da["entityB"] == "Gamaredon"


def test_build_threat_intel_indicator_obj(mocker):
    raw_ti_data = util_load_json("test_data/iocs_ti.json")

    # raw_iocs_data = util_load_json("test_data/iocs.json")
    # ta_data = raw_iocs_data["IN_DATA_3"]

    client = Client(
        base_url="test_url",
        verify=False,
        proxy=False,
    )

    da_re = client.build_threat_intel_indicator_obj(
        data=raw_ti_data["threat_actors"][0], tlp_color="tlp_color", feed_tags=["feedTags"]
    )
    assert da_re["value"] == "Gamaredon"


def test_build_ta_relationships_data(mocker):
    raw_iocs_ti_data = util_load_json("test_data/iocs_ti.json")
    raw_ti_data = raw_iocs_ti_data["ta_relationships"]

    # iocs_data = util_load_json("test_data/iocs.json")
    # ta_data = iocs_data["IN_DATA_7"]

    client = Client(
        base_url="test_url",
        verify=False,
        proxy=False,
    )
    ta_source_obj = {}
    return_data = []

    ta_source_obj, src_ti_relationships_data, return_data = client.build_ta_relationships_data(
        ta_rel_data_coll=raw_ti_data,
        ta_source_obj=ta_source_obj,
        return_data=return_data,
        tlp_color="tlp_color",
        feed_tags=["feedTags"],
    )
    assert ta_source_obj["name"] == "Gamaredon"
    # ta_source_obj["relationships"] = src_ti_relationships_data
    # return_data.append(ta_source_obj)
    # assert return_data[]["name"] == "CVE-2021-40444"
    # assert ("rawJSON" in ta_source_obj) is True


def test_build_threat_actor_relationship_obj(mocker):
    raw_iocs_ti_data = util_load_json("test_data/iocs_ti.json")
    raw_ti_data = raw_iocs_ti_data["ta_relationships"]

    client = Client(
        base_url="test_url",
        verify=False,
        proxy=False,
    )

    source_data = client.build_threat_intel_indicator_obj(data=raw_ti_data[0], tlp_color="tlp_color", feed_tags=["feedTags"])

    target_data = client.build_threat_intel_indicator_obj(data=raw_ti_data[1], tlp_color="tlp_color", feed_tags=["feedTags"])
    da_re = client.build_threat_actor_relationship_obj(source_data=source_data, target_data=target_data)

    assert da_re is not None
    assert da_re["entityA"] == "Gamaredon"
    assert da_re["entityB"] == "CVE-2021-40444"


def test_convert_decyfir_ioc_to_indicators_formats(mocker):
    raw_iocs_ti_data = util_load_json("test_data/iocs_ti.json")
    # raw_ti_data = util_load_json("test_data/iocs.json")
    ti_data = raw_iocs_ti_data["iocs"]

    client = Client(
        base_url="test_url",
        verify=False,
    )
    ti_data_out = client.convert_decyfir_ioc_to_indicators_formats(
        decyfir_api_key="api_key",
        decyfir_iocs=ti_data,
        tlp_color="tlp_color",
        feed_tags=["feedTags"],
        reputation="feedReputation",
        is_data_save=False,
    )

    assert ("rawJSON" in ti_data_out[0]) is True
    assert ti_data_out[0]["value"] == "0.0.0.0"
    # assert ti_data_out[0] == raw_ti_data["IN_DATA_4"][0]


def test_fetch_indicators(mocker):
    from decyfiriocs import Client, fetch_indicators_command

    mock_response1 = util_load_json("test_data/iocs_ti.json")
    # mock_response2 = util_load_json("test_data/iocs.json")

    client = Client(
        base_url="test_url",
        verify=False,
    )
    mocker.patch.object(Client, "get_decyfir_api_ti_data", return_value=mock_response1["iocs"])

    data = fetch_indicators_command(
        client=client, decyfir_api_key="api_key", tlp_color="tlp_color", reputation="feedReputation", feed_tags=["feedTags"]
    )
    assert ("rawJSON" in data[0]) is True
    assert data[0]["value"] == "0.0.0.0"


def test_get_indicator_type(mocker):
    from decyfiriocs import Client

    client = Client(
        base_url="test_url",
        verify=False,
    )
    da = client.get_indicator_or_threatintel_type("[ipv4-addr:value = '0.0.0.0']")
    assert da == "IP"


def test_decyfir_url_indicator_command(mocker):
    from decyfiriocs import Client, decyfir_url_indicator_command

    raw_data = util_load_json("test_data/iocs_ti.json")

    client = Client(
        base_url="test_url",
        verify=False,
    )
    mocker.patch.object(Client, "fetch_indicators_by_type", return_value=raw_data["url"])
    data = decyfir_url_indicator_command(client=client, decyfir_api_key="api_key")

    assert data[0]["value"] == "http://acme[.]xyz/"


def test_decyfir_domain_indicator_command(mocker):
    from decyfiriocs import Client, decyfir_domain_indicator_command

    raw_data = util_load_json("test_data/iocs_ti.json")

    client = Client(
        base_url="test_url",
        verify=False,
    )
    mocker.patch.object(Client, "fetch_indicators_by_type", return_value=raw_data["domain"])
    data = decyfir_domain_indicator_command(client=client, decyfir_api_key="api_key")

    assert data[0]["value"] == "mel8xo.cfd"


def test_decyfir_file_indicator_command(mocker):
    from decyfiriocs import Client, decyfir_hash_indicator_command

    raw_data = util_load_json("test_data/iocs_ti.json")

    client = Client(
        base_url="test_url",
        verify=False,
    )
    mocker.patch.object(Client, "fetch_indicators_by_type", return_value=raw_data["file"])
    data = decyfir_hash_indicator_command(client=client, decyfir_api_key="api_key")

    assert data[0]["value"] == "dbe51eabebf9d4ef9581ef99844a2944"


def test_decyfir_ip_indicator_command(mocker):
    from decyfiriocs import Client, decyfir_ip_indicator_command

    raw_data = util_load_json("test_data/iocs_ti.json")

    client = Client(
        base_url="test_url",
        verify=False,
    )
    mocker.patch.object(Client, "fetch_indicators_by_type", return_value=raw_data["iocs"])
    data = decyfir_ip_indicator_command(client=client, decyfir_api_key="api_key")

    assert data[0]["value"] == "0.0.0.0"
    assert data[0]["type"] == "IP"


def test_decyfir_get_indicators_command(mocker):
    from decyfiriocs import Client, decyfir_get_indicators_command

    raw_data = util_load_json("test_data/iocs_ti.json")

    client = Client(
        base_url="test_url",
        verify=False,
    )
    mocker.patch.object(Client, "fetch_indicators", return_value=raw_data["iocs"])
    data = decyfir_get_indicators_command(
        client=client, decyfir_api_key="api_key", reputation="feedReputation", tlp_color="tlp_color", feed_tags=["feedTags"]
    )

    assert data[0]["value"] == "0.0.0.0"


def test_command_results(mocker):
    from decyfiriocs import command_results

    raw_data = util_load_json("test_data/iocs_ti.json")

    data = command_results(raw_data["file"], "File")

    assert data[0]["value"] == "dbe51eabebf9d4ef9581ef99844a2944"
