import json
from unittest.mock import MagicMock


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def _client():
    from decyfiriocs import Client

    return Client(base_url="test_url", verify=False, proxy=False)


def _minimal_ta(confidence=85, name="TestActor", ta_type="threat-actor"):
    return {
        "type": ta_type,
        "id": f"{ta_type}--001",
        "name": name,
        "confidence": confidence,
        "description": "desc",
        "created": "2024-01-01T00:00:00Z",
        "modified": "2024-06-01T00:00:00Z",
        "extensions": {
            "extension-definition--abc": {
                "origin-of-country": "RU",
                "target-countries": ["US"],
                "target-industries": ["Finance"],
                "technologies": ["Windows"],
            }
        },
    }


def _minimal_cve(confidence=85):
    return {
        "type": "vulnerability",
        "id": "vulnerability--001",
        "name": "CVE-2024-99999",
        "confidence": confidence,
        "description": "test cve",
        "created": "2024-01-01T00:00:00Z",
        "modified": "2024-06-01T00:00:00Z",
        "extensions": {
            "extension-definition--abc": {
                "cvss_score": "9.8",
                "cvss_vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                "cvss_version": "2.0",
                "cvss_metrics_data": {
                    "availability_impact": "COMPLETE",
                    "integrity_impact": "COMPLETE",
                    "impact_score": 10.0,
                    "exploitability_score": 10.0,
                    "confidentiality_impact": "COMPLETE",
                    "access_vector": "NETWORK",
                    "access_complexity": "LOW",
                    "authentication": "NONE",
                    "vendors": ["VendorA", "VendorB"],
                    "products": ["ProdA"],
                    "technologies": ["Linux"],
                },
            }
        },
    }


def test_command_results_empty():
    from decyfiriocs import command_results

    result = command_results([], "IP")
    assert result == []


def test_extract_ioc_value():
    from decyfiriocs import extract_value

    result = extract_value("[ipv4-addr:value = '1.2.3.4']")
    assert result == "1.2.3.4"


def test_extract_value_empty_string():
    from decyfiriocs import extract_value

    result = extract_value("")
    assert result == ""


def test_get_indicator_or_threatintel_type(mocker):
    client = _client()
    da = client.get_indicator_or_threatintel_type("[ipv4-addr:value = '0.0.0.0']")
    assert da == "IP"


def test_get_indicator_or_threatintel_type_none():
    client = _client()
    result = client.get_indicator_or_threatintel_type(None)
    assert result == ""


def test_get_indicator_or_threatintel_type_unknown():
    client = _client()
    result = client.get_indicator_or_threatintel_type("something-unrecognized")
    assert result == ""


def test_get_indicator_or_threatintel_type_email():
    client = _client()
    result = client.get_indicator_or_threatintel_type("[email:value = 'foo@bar.com']")
    assert result == "Email"


def test_get_indicator_or_threatintel_type_vulnerability():
    client = _client()
    result = client.get_indicator_or_threatintel_type("vulnerability")
    assert result == "CVE"


def test_get_indicator_or_threatintel_type_threat_actor():
    client = _client()
    result = client.get_indicator_or_threatintel_type("threat-actor")
    assert result == "Threat Actor"


def test_get_indicator_or_threatintel_type_campaign():
    client = _client()
    result = client.get_indicator_or_threatintel_type("campaign")
    assert result == "Campaign"


def test_get_indicator_or_threatintel_type_malware():
    client = _client()
    result = client.get_indicator_or_threatintel_type("malware")
    assert result == "Malware"


def test_get_indicator_or_threatintel_type_attack_pattern():
    client = _client()
    result = client.get_indicator_or_threatintel_type("attack-pattern")
    assert result == "Attack Pattern"


def test_get_indicator_or_threatintel_type_intrusion_set():
    client = _client()
    result = client.get_indicator_or_threatintel_type("intrusion-set")
    assert result == "Intrusion Set"


def test_module_command_ok(mocker):
    from decyfiriocs import test_module_command

    client = _client()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mocker.patch.object(client, "_http_request", return_value=mock_resp)

    result = test_module_command(client, "test_api_key")
    assert result == "ok"


def test_module_command_unauthorized(mocker):
    from decyfiriocs import test_module_command

    client = _client()
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mocker.patch.object(client, "_http_request", return_value=mock_resp)
    result = test_module_command(client, "test_api_key")
    assert result == "Not Authorized"


def test_module_command_forbidden(mocker):
    from decyfiriocs import test_module_command

    client = _client()
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mocker.patch.object(client, "_http_request", return_value=mock_resp)
    result = test_module_command(client, "test_api_key")
    assert result == "Not Authorized"


def test_fetch_indicators_by_type_error(mocker):
    client = _client()
    mocker.patch("demistomock.error")
    mocker.patch.object(client, "_http_request", side_effect=Exception("network error"))
    result = client.fetch_indicators_by_type("api_key", "ip")
    assert result == []


def test_build_ioc_relationship_obj(mocker):
    raw_iocs_ti_data = util_load_json("test_data/iocs.json")
    ta_data = raw_iocs_ti_data["IN_DATA_3"]
    iocs_data = raw_iocs_ti_data["IN_DATA_1"]

    client = _client()
    da = client.build_ioc_relationship_obj(iocs_data[0], ta_data[0])
    assert da is not None
    assert raw_iocs_ti_data["IN_DATA_5"][0] == da
    assert da["entityA"] == "0.0.0.0"
    assert da["entityB"] == "Gibberish Panda"
    assert da["name"] == "indicator-of"


def test_build_ioc_relationship_obj_fail(mocker):
    client = _client()
    da = client.build_ioc_relationship_obj({}, {})
    assert da is None


def test_build_ioc_relationship_obj_cve_ok(mocker):
    raw_data = util_load_json("test_data/iocs_ti.json")
    raw_cve_data = raw_data["cve"]

    client = _client()
    da_re = client.build_threat_intel_indicator_obj(data=raw_cve_data[0], tlp_color="tlp_color", feed_tags=["feedTags"])
    assert da_re["type"] == "CVE"
    assert da_re["name"] == "CVE-2025-61882"
    assert ("rawJSON" in da_re) is True


def test_build_ioc_relationship_obj_malware(mocker):
    raw_data = util_load_json("test_data/iocs_ti.json")
    raw_malware_data = raw_data["malware"]

    client = _client()
    da_re = client.build_threat_intel_indicator_obj(data=raw_malware_data[0], tlp_color="tlp_color", feed_tags=["feedTags"])
    assert da_re["value"] == "Lokibot "
    assert da_re["type"] == "Malware"
    assert ("rawJSON" in da_re) is True


def test_build_threat_intel_indicator_obj(mocker):
    raw_ti_data = util_load_json("test_data/iocs_ti.json")

    client = _client()

    da_re = client.build_threat_intel_indicator_obj(
        data=raw_ti_data["threat_actors"][0], tlp_color="tlp_color", feed_tags=["feedTags"]
    )
    assert da_re["value"] == "Gamaredon"
    assert da_re["type"] == "Threat Actor"
    assert ("rawJSON" in da_re) is True


def test_build_threat_intel_indicator_obj_fail(mocker):
    raw_ti_data = util_load_json("test_data/iocs_ti.json")

    client = _client()

    da_re = client.build_threat_intel_indicator_obj(data=raw_ti_data["iocs"][0], tlp_color="tlp_color", feed_tags=["feedTags"])
    assert da_re == {}


def test_build_ta_relationships_data(mocker):
    raw_iocs_ti_data = util_load_json("test_data/iocs_ti.json")
    raw_ti_data = raw_iocs_ti_data["ta_relationships"]

    client = _client()
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
    assert ("rawJSON" in ta_source_obj) is True


def test_build_threat_actor_relationship_obj(mocker):
    raw_iocs_ti_data = util_load_json("test_data/iocs_ti.json")
    raw_ti_data = raw_iocs_ti_data["ta_relationships"]

    client = _client()

    source_data = client.build_threat_intel_indicator_obj(data=raw_ti_data[0], tlp_color="tlp_color", feed_tags=["feedTags"])
    target_data = client.build_threat_intel_indicator_obj(data=raw_ti_data[1], tlp_color="tlp_color", feed_tags=["feedTags"])
    da_re = client.build_threat_actor_relationship_obj(source_data=source_data, target_data=target_data)

    assert da_re is not None
    assert da_re["entityA"] == "Gamaredon"
    assert da_re["entityAType"] == "Threat Actor"
    assert da_re["entityB"] == "CVE-2021-40444"
    assert da_re["entityBType"] == "CVE"
    assert da_re["name"] == "targets"


def test_convert_decyfir_ioc_to_indicators_formats(mocker):
    raw_iocs_ti_data = util_load_json("test_data/iocs_ti.json")
    ti_data = raw_iocs_ti_data["iocs"]

    client = _client()
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
    assert ti_data_out[0]["type"] == "IP"
    assert ti_data_out[0]["fields"] is not None
    fields = ti_data_out[0]["fields"]
    assert fields["verdict"] == "Malicious"


def test_convert_decyfir_ioc_to_indicators_formats_different_value(mocker):
    raw_iocs_ti_data = util_load_json("test_data/iocs_ti.json")

    ti_data = raw_iocs_ti_data["iocs"]

    client = _client()
    ti_data_out = client.convert_decyfir_ioc_to_indicators_formats(
        decyfir_api_key="api_key",
        decyfir_iocs=ti_data,
        tlp_color="tlp_color",
        feed_tags=["feedTags"],
        reputation="feedReputation",
        is_data_save=False,
    )

    assert ("rawJSON" in ti_data_out[0]) is True
    assert ti_data_out[0]["value"] != "acme.com"
    assert ti_data_out[0]["type"] != "Domain"


def _make_ta_obj(confidence, name="Test Actor"):
    return {
        "type": "threat-actor",
        "id": "threat-actor--001",
        "name": name,
        "confidence": confidence,
        "description": "desc",
        "created": "2024-01-01T00:00:00Z",
        "modified": "2024-06-01T00:00:00Z",
        "extensions": {
            "extension-definition--abc": {
                "origin-of-country": "RU",
                "target-countries": ["US"],
                "target-industries": ["Finance"],
            }
        },
    }


def test_build_threat_intel_indicator_obj_suspicious():
    client = _client()
    result = client.build_threat_intel_indicator_obj(data=_make_ta_obj(60), tlp_color="GREEN", feed_tags=[])
    assert result["value"] == "Test Actor"
    assert result["fields"]["confidence"] == 60


def test_build_threat_intel_indicator_obj_benign():
    client = _client()
    result = client.build_threat_intel_indicator_obj(data=_make_ta_obj(20), tlp_color="GREEN", feed_tags=[])
    assert result["value"] == "Test Actor"
    assert result["fields"]["confidence"] == 20


def test_build_threat_intel_indicator_obj_no_extensions():
    obj = {
        "type": "threat-actor",
        "id": "threat-actor--002",
        "name": "Ghost",
        "confidence": 90,
        "description": "",
        "created": "2024-01-01T00:00:00Z",
        "modified": "2024-06-01T00:00:00Z",
        "extensions": {},
    }
    client = _client()

    result = client.build_threat_intel_indicator_obj(data=obj, tlp_color=None, feed_tags=[])
    assert result != {}


def test_build_threat_intel_indicator_obj_with_aliases_and_labels():
    obj = _make_ta_obj(85)
    obj["aliases"] = ["AKA1", "AKA2"]
    obj["labels"] = ["apt", "espionage"]
    client = _client()
    result = client.build_threat_intel_indicator_obj(data=obj, tlp_color="RED", feed_tags=["tag1"])

    assert "apt" in result["fields"]["tags"]


def test_fetch_indicators(mocker):
    from decyfiriocs import Client, fetch_indicators_command

    raw_data = util_load_json("test_data/iocs_ti.json")

    client = Client(
        base_url="test_url",
        verify=False,
    )
    mocker.patch.object(Client, "get_decyfir_api_ti_data", return_value=raw_data["iocs"])

    data = fetch_indicators_command(
        client=client, decyfir_api_key="api_key", tlp_color="tlp_color", reputation="feedReputation", feed_tags=["feedTags"]
    )
    assert ("rawJSON" in data[0]) is True
    assert data[0]["value"] == "0.0.0.0"
    assert data[0]["type"] == "IP"


def test_get_indicator_type(mocker):
    from decyfiriocs import Client

    client = Client(
        base_url="test_url",
        verify=False,
    )
    da = client.get_indicator_or_threatintel_type("[ipv4-addr:value = '0.0.0.0']")
    assert da == "IP"
    da = client.get_indicator_or_threatintel_type("[domain-name:value = 'mel8xo.cfd']")
    assert da == "Domain"
    da = client.get_indicator_or_threatintel_type("[url:value = 'http://acme[.]xyz/']")
    assert da == "URL"
    da = client.get_indicator_or_threatintel_type("[file:hashes.'SHA-256' = 'dbe51eabebf9d4ef9581ef99844a2944']")
    assert da == "File"


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


def test_get_decyfir_api_ti_data_non_200(mocker):
    client = _client()
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.content = b""
    mocker.patch.object(client, "_http_request", return_value=mock_resp)
    result = client.get_decyfir_api_ti_data("/some/path")
    assert result == []


def test_get_decyfir_api_ti_data_200_empty_body(mocker):
    client = _client()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b""
    mocker.patch.object(client, "_http_request", return_value=mock_resp)
    result = client.get_decyfir_api_ti_data("/some/path")
    assert result == []


def test_convert_ioc_with_is_data_save_true_cached_ta(mocker):
    raw_data = util_load_json("test_data/iocs_ti.json")
    ioc = raw_data["iocs"][0].copy()

    ioc["extensions"] = {
        list(ioc["extensions"].keys())[0]: {
            **list(ioc["extensions"].values())[0],
            "threat_actors": "Gamaredon",
        }
    }

    ta_bundle = raw_data["ta_relationships"]

    client = _client()
    mocker.patch.object(client, "get_decyfir_api_ti_data", return_value=ta_bundle)

    result = client.convert_decyfir_ioc_to_indicators_formats(
        decyfir_api_key="api_key",
        decyfir_iocs=[ioc, ioc],
        tlp_color="GREEN",
        feed_tags=["tag1"],
        reputation="Good",
        is_data_save=True,
    )

    assert any(r.get("value") == "0.0.0.0" for r in result)


def test_convert_ioc_with_is_data_save_true_no_ta(mocker):
    raw_data = util_load_json("test_data/iocs_ti.json")
    ioc = raw_data["iocs"][0].copy()
    ext_key = list(ioc["extensions"].keys())[0]
    ioc["extensions"] = {ext_key: {**list(ioc["extensions"].values())[0], "threat_actors": ""}}

    client = _client()
    mock_get = mocker.patch.object(client, "get_decyfir_api_ti_data", return_value=[])

    result = client.convert_decyfir_ioc_to_indicators_formats(
        decyfir_api_key="api_key",
        decyfir_iocs=[ioc],
        tlp_color="GREEN",
        feed_tags=[],
        reputation="Good",
        is_data_save=True,
    )

    mock_get.assert_not_called()
    assert len(result) == 1


def test_convert_ioc_with_is_data_save_true_unknown_ta(mocker):
    raw_data = util_load_json("test_data/iocs_ti.json")
    ioc = raw_data["iocs"][0].copy()
    ext_key = list(ioc["extensions"].keys())[0]
    ioc["extensions"] = {ext_key: {**list(ioc["extensions"].values())[0], "threat_actors": "Unknown"}}

    client = _client()
    mock_get = mocker.patch.object(client, "get_decyfir_api_ti_data", return_value=[])

    result = client.convert_decyfir_ioc_to_indicators_formats(
        decyfir_api_key="api_key",
        decyfir_iocs=[ioc],
        tlp_color=None,
        feed_tags=None,
        reputation=None,
        is_data_save=True,
    )

    mock_get.assert_not_called()
    assert len(result) == 1


def test_fetch_indicators_is_data_save_true(mocker):
    from decyfiriocs import fetch_indicators_command

    raw_data = util_load_json("test_data/iocs_ti.json")
    client = _client()
    mocker.patch.object(client, "get_decyfir_api_ti_data", return_value=raw_data["iocs"])

    result = fetch_indicators_command(
        client=client,
        decyfir_api_key="api_key",
        tlp_color="GREEN",
        reputation="Good",
        feed_tags=["tag1"],
    )

    assert len(result) > 0
    assert result[0]["value"] == "0.0.0.0"


def test_fetch_indicators_exception(mocker):
    client = _client()
    mocker.patch("demistomock.error")
    mocker.patch.object(client, "get_decyfir_api_ti_data", side_effect=Exception("API error"))

    result = client.fetch_indicators(
        decyfir_api_key="api_key",
        reputation="Good",
        tlp_color=None,
        feed_tags=[],
        is_data_save=True,
    )

    assert result == []


def test_build_ioc_relationship_obj_none_ioc():
    client = _client()
    result = client.build_ioc_relationship_obj({}, {"type": "Threat Actor", "value": "X"})
    assert result is None


def test_build_ioc_relationship_obj_none_ta():
    client = _client()
    result = client.build_ioc_relationship_obj({"type": "IP", "value": "1.2.3.4"}, {})
    assert result is None


def test_build_threat_actor_relationship_obj_source_fallback():
    client = _client()
    source = {"type": "Intrusion Set", "value": "APT28"}
    target = {"type": "some-unknown-type", "value": "unknown_target"}
    result = client.build_threat_actor_relationship_obj(source, target)
    assert result is not None
    assert result["name"] == "attributed-to"


def test_build_threat_actor_relationship_obj_no_mapping():
    client = _client()
    source = {"type": "unknown-src", "value": "src_val"}
    target = {"type": "unknown-tgt", "value": "tgt_val"}
    result = client.build_threat_actor_relationship_obj(source, target)
    assert result is None


def _base_params():
    return {
        "url": "test_url",
        "api_key": {"password": "test_api_key"},
        "insecure": False,
        "proxy": False,
        "feedTags": [],
        "tlp_color": "GREEN",
        "feedReputation": "Good",
    }


def test_main_decyfir_get_indicators(mocker):
    from decyfiriocs import main

    client = _client()
    raw_data = util_load_json("test_data/iocs_ti.json")
    mocker.patch("demistomock.params", return_value=_base_params())
    mocker.patch("demistomock.command", return_value="decyfir-get-indicators")
    mocker.patch("demistomock.info")
    mocker.patch("demistomock.error")
    mocker.patch.object(client, "fetch_indicators", return_value=raw_data["iocs"])
    mock_return = mocker.patch("decyfiriocs.return_results")

    main()
    assert mock_return.called


def test_main_ip_command(mocker):
    from decyfiriocs import main

    client = _client()

    raw_data = util_load_json("test_data/iocs_ti.json")
    mocker.patch("demistomock.params", return_value=_base_params())
    mocker.patch("demistomock.command", return_value="decyfir-ip-get")
    mocker.patch("demistomock.info")
    mocker.patch("demistomock.error")
    mocker.patch.object(client, "fetch_indicators_by_type", return_value=raw_data["iocs"])
    mock_return = mocker.patch("decyfiriocs.return_results")

    main()
    assert mock_return.called


def test_main_domain_command(mocker):
    from decyfiriocs import main

    client = _client()

    raw_data = util_load_json("test_data/iocs_ti.json")
    mocker.patch("demistomock.params", return_value=_base_params())
    mocker.patch("demistomock.command", return_value="decyfir-domain-get")
    mocker.patch("demistomock.info")
    mocker.patch("demistomock.error")
    mocker.patch.object(client, "fetch_indicators_by_type", return_value=raw_data["domain"])
    mock_return = mocker.patch("decyfiriocs.return_results")

    main()
    assert mock_return.called


def test_main_url_command(mocker):
    from decyfiriocs import main

    client = _client()
    raw_data = util_load_json("test_data/iocs_ti.json")
    mocker.patch("demistomock.params", return_value=_base_params())
    mocker.patch("demistomock.command", return_value="decyfir-url-get")
    mocker.patch("demistomock.info")
    mocker.patch("demistomock.error")
    mocker.patch.object(client, "fetch_indicators_by_type", return_value=raw_data["url"])
    mock_return = mocker.patch("decyfiriocs.return_results")

    main()
    assert mock_return.called


def test_main_file_command(mocker):
    from decyfiriocs import main

    client = _client()
    raw_data = util_load_json("test_data/iocs_ti.json")
    mocker.patch("demistomock.params", return_value=_base_params())
    mocker.patch("demistomock.command", return_value="decyfir-file-get")
    mocker.patch("demistomock.info")
    mocker.patch("demistomock.error")
    mocker.patch.object(client, "fetch_indicators_by_type", return_value=raw_data["file"])
    mock_return = mocker.patch("decyfiriocs.return_results")

    main()
    assert mock_return.called


def test_main_unknown_command(mocker):
    from decyfiriocs import main

    mocker.patch("demistomock.params", return_value=_base_params())
    mocker.patch("demistomock.command", return_value="not-a-real-command")
    mocker.patch("demistomock.info")
    mocker.patch("demistomock.error")
    mock_error = mocker.patch("decyfiriocs.return_error")

    main()
    assert mock_error.called


def test_main_exception_in_setup(mocker):
    from decyfiriocs import main

    mocker.patch("demistomock.params", side_effect=Exception("bad params"))
    mocker.patch("demistomock.command", return_value="test-module")
    mocker.patch("demistomock.error")
    mock_error = mocker.patch("decyfiriocs.return_error")

    main()
    assert mock_error.called


def test_convert_ioc_file_hash_sha256(mocker):
    client = _client()

    ioc = {
        "type": "indicator",
        "id": "indicator--sha256",
        "name": "File SHA-256 hash 'abc123'",
        "confidence": 90,
        "description": "",
        "created": "2024-01-01T00:00:00Z",
        "modified": "2024-06-01T00:00:00Z",
        "pattern": "[file:hashes.'SHA-256' = 'abc123']",
        "labels": [],
        "extensions": {
            "ext-1": {
                "threat_actors": "",
                "recommended_actions": "",
                "roles": "",
                "asn": "",
                "country_code": "",
            }
        },
    }
    result = client.convert_decyfir_ioc_to_indicators_formats(
        decyfir_api_key="key",
        decyfir_iocs=[ioc],
        reputation=None,
        tlp_color=None,
        feed_tags=None,
        is_data_save=False,
    )
    assert any(r.get("type") == "File" for r in result)


def test_convert_ioc_file_hash_sha1(mocker):
    client = _client()

    ioc = {
        "type": "indicator",
        "id": "indicator--sha1",
        "name": "File SHA-1 hash 'deadbeef'",
        "confidence": 55,
        "description": "",
        "created": "2024-01-01T00:00:00Z",
        "modified": "2024-06-01T00:00:00Z",
        "pattern": "[file:hashes.'SHA-1' = 'deadbeef']",
        "labels": [],
        "extensions": {
            "ext-1": {
                "threat_actors": "",
                "recommended_actions": "monitor",
                "roles": "",
                "asn": "",
                "country_code": "",
            }
        },
    }
    result = client.convert_decyfir_ioc_to_indicators_formats(
        decyfir_api_key="key",
        decyfir_iocs=[ioc],
        reputation=None,
        tlp_color=None,
        feed_tags=None,
        is_data_save=False,
    )
    assert any(r.get("type") == "File" for r in result)


def test_convert_ioc_file_hash_md5_fail(mocker):
    client = _client()

    ioc = {
        "type": "indicator",
        "id": "indicator--md5",
        "name": "File MD5 hash 'cafebabe'",
        "confidence": 30,
        "description": "",
        "created": "2024-01-01T00:00:00Z",
        "modified": "2024-06-01T00:00:00Z",
        "pattern": "[file:hashes.MD5 = 'cafebabe']",
        "labels": [],
        "extensions": {
            "ext-1": {
                "threat_actors": "",
                "recommended_actions": "",
                "roles": "",
                "asn": "",
                "country_code": "",
            }
        },
    }
    result = client.convert_decyfir_ioc_to_indicators_formats(
        decyfir_api_key="key",
        decyfir_iocs=[ioc],
        reputation=None,
        tlp_color=None,
        feed_tags=None,
        is_data_save=False,
    )
    assert any(r.get("type") != "File" for r in result)


def test_main_top_level_exception(mocker):
    from decyfiriocs import main

    mocker.patch("demistomock.params", side_effect=Exception("bad config"))
    mocker.patch("demistomock.command", return_value="test-module")
    mock_err = mocker.patch("decyfiriocs.return_error")
    main()
    assert mock_err.called


def _ioc_dict(threat_actors="", confidence=90):
    return {
        "type": "indicator",
        "id": "indicator--001",
        "name": "0.0.0.0",
        "confidence": confidence,
        "description": "test ioc",
        "created": "2024-01-01T00:00:00Z",
        "modified": "2024-06-01T00:00:00Z",
        "pattern": "[ipv4-addr:value = '0.0.0.0']",
        "labels": ["malicious"],
        "extensions": {
            "extension-definition--abc": {
                "threat_actors": threat_actors,
                "recommended_actions": "block",
                "roles": "botnet",
                "asn": "AS1234",
                "country_code": "RU",
            }
        },
    }


def test_fetch_indicators_is_data_save_false_slices(mocker):
    client = _client()

    iocs = [_ioc_dict() for _ in range(5)]
    for i, ioc in enumerate(iocs):
        ioc["id"] = f"indicator--{i:03}"
    mocker.patch.object(client, "get_decyfir_api_ti_data", return_value=iocs)

    result = client.fetch_indicators(
        decyfir_api_key="key",
        reputation=None,
        tlp_color=None,
        feed_tags=[],
        is_data_save=False,
    )
    assert len(result) == 2


def test_convert_ioc_is_data_save_true_empty_ta(mocker):
    client = _client()

    ioc = _ioc_dict(threat_actors="")
    mock_get = mocker.patch.object(client, "get_decyfir_api_ti_data", return_value=[])

    result = client.convert_decyfir_ioc_to_indicators_formats(
        decyfir_api_key="key",
        decyfir_iocs=[ioc],
        reputation="Good",
        tlp_color=None,
        feed_tags=None,
        is_data_save=True,
    )
    mock_get.assert_not_called()
    assert len(result) == 1


def test_build_ta_relationships_data_alternate_ref_keys():
    client = _client()
    ta = _minimal_ta(name="GhostActor")
    cve = _minimal_cve()
    rel = {
        "type": "relationship",
        "id": "relationship--001",
        "sourceRef": ta["id"],
        "targetRef": cve["id"],
    }
    bundle = [ta, cve, rel]

    ta_source_obj, rels, return_data = client.build_ta_relationships_data(
        ta_rel_data_coll=bundle,
        ta_source_obj={},
        return_data=[],
        tlp_color="GREEN",
        feed_tags=[],
    )
    assert ta_source_obj.get("name") == "GhostActor"
