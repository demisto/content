"""Unit tests for the CYFIRMA Threat Intelligence feed integration."""

import CyfirmaThreatIntelligence as cf
import demistomock as demisto
import pytest
from CommonServerPython import DemistoException, FeedIndicatorType

BASE_URL = "https://api.cyfirma.test/api/ex/v3/da"


@pytest.fixture
def client():
    return cf.Client(base_url=BASE_URL, verify=False, headers={"X-Api-Key": "key"})


# ----------------------------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [(None, []), ("", []), ([1, 2], [1, 2]), ("a", ["a"]), (5, [5])],
)
def test_as_list(value, expected):
    assert cf.as_list(value) == expected


def test_first_of():
    data = {"a": None, "b": "", "c": [], "d": {}, "e": "found", "f": "later"}
    assert cf.first_of(data, "a", "b", "c", "d", "e", "f") == "found"
    assert cf.first_of(data, "a", "missing") is None
    assert cf.first_of(data, "a", default="dflt") == "dflt"


@pytest.mark.parametrize(
    "confidence, expected",
    [
        (95, (3, "Malicious")),
        (80, (3, "Malicious")),
        (60, (2, "Suspicious")),
        (50, (2, "Suspicious")),
        (10, (1, "Benign")),
        (0, (0, "Unknown")),
        ("abc", (1, "Benign")),
        ({}, (1, "Benign")),
    ],
)
def test_confidence_to_score(confidence, expected):
    assert cf.confidence_to_score(confidence) == expected


@pytest.mark.parametrize("pattern", ["", None, "not a pattern", "   garbage"])
def test_parse_pattern_empty_or_malformed(pattern):
    assert cf.parse_pattern(pattern) == ("", "", {})


def test_parse_pattern_unsupported_observable():
    assert cf.parse_pattern("[process:name = 'x']") == ("", "", {})


def test_parse_pattern_simple_values():
    assert cf.parse_pattern("[ipv4-addr:value = '1.2.3.4']") == (FeedIndicatorType.IP, "1.2.3.4", {})
    assert cf.parse_pattern("[domain-name:value = 'evil.com']") == (FeedIndicatorType.Domain, "evil.com", {})
    assert cf.parse_pattern("[url:value = 'http://a.com/b']") == (FeedIndicatorType.URL, "http://a.com/b", {})
    assert cf.parse_pattern("[ipv6-addr:value = '::1']")[0] == FeedIndicatorType.IPv6


def test_parse_pattern_cidr():
    assert cf.parse_pattern("[ipv4-addr:value = '1.2.3.0/24']") == (FeedIndicatorType.CIDR, "1.2.3.0/24", {})
    assert cf.parse_pattern("[ipv6-addr:value = '2001:db8::/32']") == (
        FeedIndicatorType.IPv6CIDR,
        "2001:db8::/32",
        {},
    )


def test_parse_pattern_escaped_quote():
    _, value, _ = cf.parse_pattern("[domain-name:value = 'a\\'b']")
    assert value == "a'b"


def test_parse_pattern_file_hash_preference():
    pattern = "[file:hashes.MD5 = 'md5v' OR file:hashes.\"SHA-1\" = 'sha1v' OR file:hashes.'SHA-256' = 'sha256v']"
    ioc_type, value, hashes = cf.parse_pattern(pattern)
    assert ioc_type == FeedIndicatorType.File
    assert value == "sha256v"
    assert hashes == {"md5": "md5v", "sha1": "sha1v", "sha256": "sha256v"}


def test_parse_pattern_file_only_md5_and_duplicate():
    _, value, hashes = cf.parse_pattern("[file:hashes.MD5 = 'aaa' OR file:hashes.MD5 = 'bbb']")
    assert value == "aaa"
    assert hashes == {"md5": "aaa"}


def test_parse_pattern_file_unknown_hash_algo_falls_back_to_value():
    ioc_type, value, hashes = cf.parse_pattern("[file:hashes.'FOO' = 'xyz']")
    assert ioc_type == FeedIndicatorType.File
    assert value == "xyz"
    assert hashes == {}


def test_parse_pattern_no_value():
    assert cf.parse_pattern("[domain-name:value]") == (FeedIndicatorType.Domain, "", {})


def test_location_value():
    assert cf.location_value({"name": "India"}) == "India"
    assert cf.location_value({"city": "BLR", "region": "KA", "country": "IN"}) == "BLR, KA, IN"
    assert cf.location_value({"latitude": 1.5, "longitude": 2.5}) == "1.5,2.5"
    assert cf.location_value({"latitude": 1.5}) == ""
    assert cf.location_value({}) == ""


def test_get_ti_ext_id():
    assert cf.get_ti_ext_id(cf.LABEL_VULNERABILITY) == cf.VUL_EXTENSION_ID
    assert cf.get_ti_ext_id(cf.LABEL_THREAT_ACTOR) == cf.TA_EXTENSION_ID
    assert cf.get_ti_ext_id(cf.LABEL_MALWARE) == cf.MALWARE_EXTENSION_ID
    assert cf.get_ti_ext_id("unknown") == cf.INDICATOR_EXTENSION_ID


@pytest.mark.parametrize(
    "value, expected",
    [
        ("30 days", 30),
        ("7", 7),
        (15, 15),
        (None, cf.DEFAULT_FIRST_FETCH_DAYS),
        ("", cf.DEFAULT_FIRST_FETCH_DAYS),
        ("abc", cf.DEFAULT_FIRST_FETCH_DAYS),
    ],
)
def test_parse_days(value, expected):
    assert cf._parse_days(value) == expected


# ----------------------------------------------------------------------------------------------
# Client.identify_feed_type
# ----------------------------------------------------------------------------------------------


def test_identify_indicator_with_pattern(client):
    obj = {"type": "indicator", "pattern": "[ipv4-addr:value = '1.1.1.1']"}
    assert client.identify_feed_type(obj) == ("1.1.1.1", FeedIndicatorType.IP)


def test_identify_indicator_name_fallback(client, mocker):
    mocker.patch.object(cf, "auto_detect_indicator_type", return_value=FeedIndicatorType.IP)
    assert client.identify_feed_type({"type": "indicator", "pattern": "", "name": "8.8.8.8"}) == (
        "8.8.8.8",
        FeedIndicatorType.IP,
    )


def test_identify_indicator_name_not_detected(client, mocker):
    mocker.patch.object(cf, "auto_detect_indicator_type", return_value=None)
    assert client.identify_feed_type({"type": "indicator", "name": "zzz"}) == ("", "")


def test_identify_indicator_no_name(client):
    assert client.identify_feed_type({"type": "indicator"}) == ("", "")


def test_identify_location(client):
    assert client.identify_feed_type({"type": "location", "name": "India"}) == ("India", cf._LOCATION_TYPE)


def test_identify_sdo(client):
    assert client.identify_feed_type({"type": "vulnerability", "name": "CVE-2024-1"}) == (
        "CVE-2024-1",
        FeedIndicatorType.CVE,
    )
    assert client.identify_feed_type({"type": "Malware", "name": "Evil"}) == ("Evil", cf.SDO_TYPES["malware"])


def test_identify_bare_observable(client):
    assert client.identify_feed_type({"type": "ipv4-addr", "value": "1.2.3.4"}) == ("1.2.3.4", FeedIndicatorType.IP)
    assert client.identify_feed_type({"type": "domain-name", "name": "a.com"}) == ("a.com", FeedIndicatorType.Domain)


def test_identify_unknown_type(client):
    assert client.identify_feed_type({"type": "weird"}) == ("", "")
    assert client.identify_feed_type({}) == ("", "")


# ----------------------------------------------------------------------------------------------
# Client.build_relationships
# ----------------------------------------------------------------------------------------------

IND_ID = "indicator--1"
TA_ID = "threat-actor--1"
MAL_ID = "malware--1"
FEED_OBJS = {
    IND_ID: {"type": "indicator", "id": IND_ID, "pattern": "[ipv4-addr:value = '1.1.1.1']"},
    TA_ID: {"type": "threat-actor", "id": TA_ID, "name": "APT1"},
    MAL_ID: {"type": "malware", "id": MAL_ID, "name": "Evil"},
    "bad--1": {"type": "weird", "id": "bad--1"},
    "empty--1": {"type": "malware", "id": "empty--1", "name": ""},
}


def _rel(source, target, rel_type="uses"):
    return {"type": "relationship", "relationship_type": rel_type, "source_ref": source, "target_ref": target}


def test_build_relationship_regular(client):
    res = client.build_relationships(_rel(TA_ID, MAL_ID), FEED_OBJS)
    assert res["name"] == "uses"
    assert res["entityA"] == "APT1"
    assert res["entityB"] == "Evil"
    assert res["entityBType"] == cf.SDO_TYPES["malware"]


def test_build_relationship_from_indicator(client):
    res = client.build_relationships(_rel(IND_ID, MAL_ID, "indicates"), FEED_OBJS)
    assert res["name"] == "indicator-of"
    assert res["entityA"] == "1.1.1.1"


def test_build_relationship_alias(client):
    res = client.build_relationships(_rel(MAL_ID, TA_ID, "indicates"), FEED_OBJS)
    assert res["name"] == "indicator-of"


@pytest.mark.parametrize(
    "rel",
    [
        _rel("missing", MAL_ID),
        _rel(TA_ID, "missing"),
        _rel("bad--1", MAL_ID),
        _rel(TA_ID, "bad--1"),
        _rel(TA_ID, "empty--1"),
        _rel(TA_ID, MAL_ID, ""),
        {"type": "relationship", "source_ref": TA_ID, "target_ref": MAL_ID},
    ],
)
def test_build_relationship_unbuildable(client, rel):
    assert client.build_relationships(rel, FEED_OBJS) == {}


# ----------------------------------------------------------------------------------------------
# Client.convert_threat_intel_obj
# ----------------------------------------------------------------------------------------------


def test_convert_unsupported(client):
    assert client.convert_threat_intel_obj({"type": "weird"}, "RED", "Good", []) == {}


def test_convert_indicator_block(client):
    obj = {
        "type": "indicator",
        "id": "indicator--9",
        "pattern": "[file:hashes.MD5 = 'aaa' OR file:hashes.'SHA-256' = 'bbb']",
        "created": "c",
        "modified": "m",
        "confidence": 90,
        "description": "desc",
        "labels": ["l1", "t1"],
        "aliases": "al",
        "extensions": {cf.INDICATOR_EXTENSION_ID: {"country": "IN", "recommended_actions": "block"}},
    }
    res = client.convert_threat_intel_obj(obj, "AMBER", "Bad", ["t1", "t2"])
    assert res["value"] == "bbb"
    assert res["type"] == FeedIndicatorType.File
    assert res["score"] == 3
    assert res["service"] == cf.INTEGRATION_NAME
    assert res["rawJSON"] is obj
    fields = res["fields"]
    assert fields["tags"] == ["t1", "t2", "l1"]
    assert fields["md5"] == "aaa"
    assert fields["sha256"] == "bbb"
    assert fields["geocountry"] == "IN"
    assert fields["blocked"] is True
    assert fields["reputation"] == "Bad"
    assert fields["trafficlightprotocol"] == "AMBER"
    assert fields["aliases"] == ["al"]


def test_convert_indicator_monitor_no_extension_no_reputation(client):
    obj = {"type": "indicator", "pattern": "[ipv4-addr:value = '1.1.1.1']"}
    res = client.convert_threat_intel_obj(obj, "", "", None)
    fields = res["fields"]
    assert "blocked" not in fields
    assert "reputation" not in fields
    assert fields["geocountry"] == ""
    assert fields["trafficlightprotocol"] == ""
    assert fields["confidence"] == 0
    assert res["score"] == 0


def _vuln(version, **ext):
    return {
        "type": "vulnerability",
        "id": "vulnerability--1",
        "name": "CVE-2024-0001",
        "description": "d",
        "modified": "m",
        "confidence": 85,
        "extensions": {cf.VUL_EXTENSION_ID: {"cvss_version": version, "cvss_base_score": 9.8, "cvss_vector": "vec", **ext}},
    }


def test_convert_vulnerability_v3(client):
    obj = _vuln("3.1", attack_vector="NETWORK", kev=True, vendors=["a", "b"], products="p", technologies=["t"])
    res = client.convert_threat_intel_obj(obj, "RED", "", [])
    fields = res["fields"]
    assert res["type"] == FeedIndicatorType.CVE
    assert fields["verdict"] == "Malicious"
    assert fields["cvssversion"] == "3.1"
    assert fields["cvssscore"] == 9.8
    table = {m["metrics"]: m["value"] for m in fields["cvsstable"]}
    assert table["Attack vector"] == "NETWORK"
    assert table["KEV"] == "True"
    assert table["Vendors"] == "a, b"
    assert table["Products"] == "p"
    assert table["Technologies"] == "t"
    assert "Access vector" not in table


def test_convert_vulnerability_v2(client):
    table = {m["metrics"] for m in client.convert_threat_intel_obj(_vuln("2.0"), "", "", [])["fields"]["cvsstable"]}
    assert "Access vector" in table
    assert "Authentication" in table
    assert "Attack vector" not in table


def test_convert_vulnerability_unknown_version(client):
    obj = _vuln(None)
    table = {m["metrics"] for m in client.convert_threat_intel_obj(obj, "", "", [])["fields"]["cvsstable"]}
    assert "Impact score" in table
    assert "Access vector" not in table
    assert "Attack vector" not in table


def test_convert_vulnerability_no_extension(client):
    obj = {"type": "vulnerability", "name": "CVE-1"}
    res = client.convert_threat_intel_obj(obj, "", "", [])
    assert res["fields"]["cvssversion"] == ""


def test_convert_location_full(client):
    obj = {
        "type": "location",
        "name": "India",
        "country": "IN",
        "region": "Asia",
        "city": "BLR",
        "latitude": 1.0,
        "longitude": 2.0,
    }
    res = client.convert_threat_intel_obj(obj, "", "", [])
    assert res["score"] == 0
    assert res["fields"]["geolocation"] == "1.0,2.0"
    assert res["fields"]["countryname"] == "IN"
    assert res["fields"]["region"] == "Asia"
    assert res["fields"]["city"] == "BLR"


def test_convert_location_minimal(client):
    res = client.convert_threat_intel_obj({"type": "location", "country": "IN"}, "", "", [])
    assert "geolocation" not in res["fields"]
    assert "region" not in res["fields"]
    assert "city" not in res["fields"]
    assert res["fields"]["countryname"] == "IN"


def test_convert_threat_actor_uses_static_score(client):
    res = client.convert_threat_intel_obj({"type": "threat-actor", "name": "APT1", "confidence": 10}, "", "", [])
    assert res["score"] == cf.TI_SCORES[cf.SDO_TYPES["threat-actor"]]


# ----------------------------------------------------------------------------------------------
# Client.fetch_all_pages / fetch_threat_actors_data / get_feeds
# (the client now issues requests through ``Client.get`` instead of the old ``call_api``)
# ----------------------------------------------------------------------------------------------


def test_fetch_all_pages(client, mocker):
    get = mocker.patch.object(client, "get", side_effect=[{"objects": [1, 2]}, {"objects": [3]}, {"objects": []}])
    feeds: list = []
    params = {"a": 1}
    client.fetch_all_pages(params, "/p", feeds)
    assert feeds == [1, 2, 3]
    assert get.call_count == 3
    assert all(c.args == ("/p",) for c in get.call_args_list)
    assert all("X-Request-ID" in c.kwargs["headers"] for c in get.call_args_list)
    assert params == {"a": 1}  # caller's dict untouched


def test_fetch_all_pages_none_response(client, mocker):
    mocker.patch.object(client, "get", return_value=None)
    feeds: list = []
    client.fetch_all_pages({}, "/p", feeds)
    assert feeds == []


def test_fetch_threat_actors_data(client, mocker):
    err = mocker.patch.object(demisto, "error")
    names = [f"ta{i}" for i in range(cf.TA_SEARCH_CHUNK_SIZE + 1)]
    get = mocker.patch.object(
        client,
        "get",
        side_effect=[
            {"objects": [{"type": "threat-actor", "name": "ta0"}, {"type": "malware", "name": "m"}]},
            Exception("boom"),
        ],
    )
    feeds: list = []
    client.fetch_threat_actors_data(names, feeds)
    assert feeds == [{"type": "malware", "name": "m"}]
    assert get.call_count == 2
    assert get.call_args_list[0].args == (cf._TA_SEARCH_API_PATHS,)
    assert get.call_args_list[0].kwargs["params"] == {"values": names[: cf.TA_SEARCH_CHUNK_SIZE]}
    err.assert_called_once()


def test_fetch_threat_actors_data_none_response(client, mocker):
    mocker.patch.object(client, "get", return_value=None)
    feeds: list = []
    client.fetch_threat_actors_data(["x"], feeds)
    assert feeds == []


@pytest.mark.parametrize("tailored", [True, False])
def test_get_feeds(client, mocker, tailored):
    suffix = cf._TAILORED_PATHS if tailored else cf._ALL_PATHS
    ioc_path = f"{cf._IOC_API_PATHS}{suffix}"
    vul_path = f"{cf._VUL_API_PATHS}{suffix}"

    indicator = {"type": "indicator", "id": IND_ID, "pattern": "[ipv4-addr:value = '1.1.1.1']"}
    ta = {"type": "threat-actor", "id": TA_ID, "name": "APT1"}
    malware = {"type": "malware", "id": MAL_ID, "name": "Evil"}
    vuln = {"type": "vulnerability", "id": "vulnerability--1", "name": "CVE-2024-1"}
    unknown = {"type": "weird", "id": "weird--1", "name": "x"}
    rel_ok = _rel(TA_ID, MAL_ID)
    rel_bad = _rel(TA_ID, "missing")

    calls: list = []

    def fake_get(path, params=None, headers=None, **kwargs):
        calls.append((path, dict(params or {})))
        if path == ioc_path and (params or {}).get("page") == 0:
            return {"objects": [indicator, dict(indicator), ta, rel_ok, rel_bad, unknown]}
        if path == vul_path and (params or {}).get("page") == 0:
            return {"objects": [vuln]}
        if path == cf._TA_SEARCH_API_PATHS:
            return {"objects": [ta, malware]}
        return {}

    mocker.patch.object(client, "get", side_effect=fake_get)

    res = client.get_feeds(
        first_fetch=5,
        tlp_color="RED",
        feed_reputation="",
        feed_tags=["tag"],
        fetch_tailored_indicators=tailored,
        fetch_tailored_vulnerabilities=tailored,
    )

    paths = [c[0] for c in calls]
    assert ioc_path in paths
    assert vul_path in paths
    assert (cf._TA_SEARCH_API_PATHS, {"values": ["APT1"]}) in calls

    # 4 unique convertible objects (indicator, TA, vuln, malware) + 1 relationship
    assert len(res) == 5
    assert sum(1 for r in res if r.get("type") == FeedIndicatorType.IP) == 1
    assert sum(1 for r in res if "entityA" in r) == 1


# ----------------------------------------------------------------------------------------------
# test_module
# ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("ti, vul", [(False, True), (True, False), (False, False)])
def test_test_module_lookback_too_long(client, ti, vul):
    res = cf.test_module(client, ti, vul, cf.MAX_DAYS_WITHOUT_TAILORING + 1)
    assert "look-back period" in res


@pytest.mark.parametrize("exc_msg", ["Forbidden", "Unauthorized"])
def test_test_module_auth_error(client, mocker, exc_msg):
    mocker.patch.object(client, "get", side_effect=DemistoException(exc_msg))
    assert cf.test_module(client, True, True, 60).startswith("Authorization Error")


def test_test_module_other_error_reraised(client, mocker):
    mocker.patch.object(client, "get", side_effect=DemistoException("Server exploded"))
    with pytest.raises(DemistoException):
        cf.test_module(client, True, True, 60)


@pytest.mark.parametrize(
    "response",
    [{}, {"isOrgActive": False}, {"isOrgActive": True, "isCompanyActive": False}],
)
def test_test_module_inactive_org(client, mocker, response):
    mocker.patch.object(client, "get", return_value=response)
    with pytest.raises(DemistoException, match="Not Authorized"):
        cf.test_module(client, True, True, 60)


@pytest.mark.parametrize("response", [{"isOrgActive": True, "isCompanyActive": True}, {"isOrgActive": True}])
def test_test_module_active_org(client, mocker, response):
    mocker.patch.object(client, "get", return_value=response)
    assert cf.test_module(client, True, True, 60) == "ok"


def test_test_module_pings_test_path(client, mocker):
    get = mocker.patch.object(client, "get", return_value={"isOrgActive": True})
    cf.test_module(client, True, True, 60)
    get.assert_called_once_with(cf._TEST_PATH)


def test_test_module_short_lookback_without_tailoring(client, mocker):
    mocker.patch.object(client, "get", return_value={"isOrgActive": True})
    assert cf.test_module(client, False, False, cf.MAX_DAYS_WITHOUT_TAILORING) == "ok"


# ----------------------------------------------------------------------------------------------
# fetch_feeds
# ----------------------------------------------------------------------------------------------


def test_fetch_feeds_batches(client, mocker, monkeypatch):
    monkeypatch.setattr(cf, "INDICATOR_BATCH_SIZE", 2)
    mocker.patch.object(client, "get_feeds", return_value=[{"v": 1}, {"v": 2}, {"v": 3}])
    create = mocker.patch.object(demisto, "createIndicators")
    cf.fetch_feeds(client, 5, "RED", "Good", ["t"], True, False)
    assert create.call_count == 2
    client.get_feeds.assert_called_once_with(
        first_fetch=5,
        tlp_color="RED",
        feed_reputation="Good",
        feed_tags=["t"],
        fetch_tailored_indicators=True,
        fetch_tailored_vulnerabilities=False,
    )


def test_fetch_feeds_error(client, mocker):
    mocker.patch.object(client, "get_feeds", side_effect=RuntimeError("boom"))
    err = mocker.patch.object(demisto, "error")
    with pytest.raises(RuntimeError):
        cf.fetch_feeds(client, 5, "", "", [], True, True)
    err.assert_called_once()


# ----------------------------------------------------------------------------------------------
# build_result
# ----------------------------------------------------------------------------------------------


def test_build_result_empty():
    assert cf.build_result([], cf.LABEL_INDICATOR, "t").readable_output == "For current request no data found."


def test_build_result_invalid_type():
    with pytest.raises(ValueError):
        cf.build_result([{"a": 1}], "Bogus", "t")


def test_build_result_indicator():
    data = [
        {
            "type": "indicator",
            "pattern": "[ipv4-addr:value = '1.1.1.1']",
            "confidence": 90,
            "description": "d",
            "extensions": {
                cf.INDICATOR_EXTENSION_ID: {
                    "country": "IN",
                    "threat_actors": ["APT1"],
                    "recommended_actions": "BLOCK",
                    "roles": ["C2"],
                    "security_vendors": {"x": 1},
                }
            },
        },
        {"type": "indicator", "pattern": "", "confidence": None},  # unknown type, no extensions
    ]
    res = cf.build_result(data, cf.LABEL_INDICATOR, "Title")
    assert res.outputs_prefix == "Cyfirma.Indicator"
    assert res.outputs_key_field == "value"
    assert res.raw_response == data
    assert isinstance(res.outputs, list)
    first, second = res.outputs
    assert first["value"] == "1.1.1.1"
    assert first["type"] == FeedIndicatorType.IP
    assert first["score"] == 3
    assert first["threat_actor"] == ["APT1"]
    assert first["vendors"] == {"x": 1}
    assert first["action"] == "BLOCK"
    assert second["type"] == "Unknown"
    assert second["score"] == 0
    assert "Title" in res.readable_output


def test_build_result_vulnerability():
    data = [
        {
            "name": "CVE-2024-1",
            "description": "d",
            "confidence": 55,
            "extensions": {cf.VUL_EXTENSION_ID: {"country": "US", "cvss_version": "3.1", "vendors": ["v"]}},
        },
        {"name": "CVE-2024-2"},
    ]
    res = cf.build_result(data, cf.LABEL_VULNERABILITY, "T")
    assert res.outputs_prefix == "Cyfirma.Vulnerability"
    assert isinstance(res.outputs, list)
    assert res.outputs[0]["value"] == "CVE-2024-1"
    assert res.outputs[0]["type"] == "CVE"
    assert res.outputs[0]["score"] == 2
    assert res.outputs[0]["cvss_version"] == "3.1"
    assert res.outputs[0]["vendors"] == ["v"]
    assert res.outputs[1]["cvss_version"] == "0.0"  # default
    assert res.outputs[1]["vendors"] == []


def test_build_result_threat_actor():
    data = [{"name": "APT1", "confidence": 80, "extensions": {cf.TA_EXTENSION_ID: {"motivation": "money"}}}]
    res = cf.build_result(data, cf.LABEL_THREAT_ACTOR, "T")
    assert res.outputs_prefix == "Cyfirma.ThreatActor"
    assert isinstance(res.outputs, list)
    output = res.outputs[0]
    assert isinstance(output, dict)
    assert output["motivation"] == "money"
    assert output["origin_of_country"] == ""
    assert output["type"] == cf.LABEL_THREAT_ACTOR


def test_build_result_malware():
    data = [
        {
            "name": "Evil",
            "extensions": {cf.MALWARE_EXTENSION_ID: {"target_industries": ["x"], "country": "IN", "threat_actors": ["A"]}},
        }
    ]
    res = cf.build_result(data, cf.LABEL_MALWARE, "T")
    assert res.outputs_prefix == "Cyfirma.Malware"
    assert isinstance(res.outputs, list)
    out = res.outputs[0]
    assert isinstance(out, dict)
    assert out["target_industries"] == ["x"]
    assert out["country"] == "IN"
    assert out["threat_actors"] == ["A"]
    assert out["target_technologies"] == ""


# ----------------------------------------------------------------------------------------------
# fetch_feeds_by_type / feed_search
# ----------------------------------------------------------------------------------------------


def test_fetch_feeds_by_type(client, mocker):
    get = mocker.patch.object(
        client,
        "get",
        return_value={"objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '1.1.1.1']", "confidence": 90}]},
    )
    res = cf.fetch_feeds_by_type(client, "ip")
    get.assert_called_once_with(cf._IOC_API_PATHS, params={"types": ["ip"]})
    assert isinstance(res.outputs, list)
    assert res.outputs[0]["value"] == "1.1.1.1"
    assert "Type: ip" in res.readable_output


def test_fetch_feeds_by_type_no_objects(client, mocker):
    mocker.patch.object(client, "get", return_value={})
    assert cf.fetch_feeds_by_type(client, "ip").readable_output == "For current request no data found."


def test_fetch_feeds_by_type_error(client, mocker):
    mocker.patch.object(client, "get", side_effect=RuntimeError("boom"))
    err = mocker.patch.object(demisto, "error")
    with pytest.raises(RuntimeError):
        cf.fetch_feeds_by_type(client, "ip")
    err.assert_called_once()


def test_feed_search_missing_value(client):
    with pytest.raises(ValueError, match="value"):
        cf.feed_search(client, cf.LABEL_INDICATOR, {})


def test_feed_search_invalid_type(client):
    with pytest.raises(ValueError, match="Invalid search type"):
        cf.feed_search(client, "Bogus", {"value": "x"})


@pytest.mark.parametrize("response", [{}, None, {"other": 1}])
def test_feed_search_no_objects_key(client, mocker, response):
    mocker.patch.object(client, "get", return_value=response)
    res = cf.feed_search(client, cf.LABEL_INDICATOR, {"value": "x"})
    assert res.readable_output == "No results found for the given search criteria."


@pytest.mark.parametrize(
    "search_type, param_name, path",
    [
        (cf.LABEL_INDICATOR, "value", cf._IOC_SEARCH_API_PATHS),
        (cf.LABEL_THREAT_ACTOR, "values", cf._TA_SEARCH_API_PATHS),
        (cf.LABEL_MALWARE, "value", cf._MALWARE_SEARCH_API_PATHS),
        (cf.LABEL_VULNERABILITY, "value", cf._VUL_SEARCH_API_PATHS),
    ],
)
def test_feed_search_success(client, mocker, search_type, param_name, path):
    get = mocker.patch.object(client, "get", return_value={"objects": [{"name": "n", "confidence": 90}]})
    res = cf.feed_search(client, search_type, {"value": "needle"})
    get.assert_called_once_with(path, params={param_name: ["needle"]})
    assert res.outputs_prefix == cf._OUTPUT_PREFIXES[search_type]
    assert "needle" in res.readable_output


# ----------------------------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------------------------

BASE_PARAMS = {"url": "https://api.cyfirma.test/", "api_key": {"password": "k"}}


@pytest.fixture
def main_env(mocker):
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    return {
        "return_results": mocker.patch.object(cf, "return_results"),
        "return_error": mocker.patch.object(cf, "return_error", side_effect=SystemExit),
        "client_cls": mocker.patch.object(cf, "Client"),
        "auth_handler": mocker.patch.object(cf, "APIKeyAuthHandler"),
    }


def _setup(mocker, params, command, args=None):
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value=command)
    mocker.patch.object(demisto, "args", return_value=args or {})


@pytest.mark.parametrize(
    "params", [{}, {"url": "https://x"}, {"api_key": {"password": "k"}}, {"url": "https://x", "api_key": {}}]
)
def test_main_missing_credentials(mocker, main_env, params):
    _setup(mocker, params, "test-module")
    with pytest.raises(SystemExit):
        cf.main()
    main_env["return_error"].assert_called_once_with("Server URL and API Key are required.")


def test_main_builds_client(mocker, main_env):
    _setup(mocker, BASE_PARAMS, "test-module")
    mocker.patch.object(cf, "test_module", return_value="ok")
    cf.main()
    main_env["auth_handler"].assert_called_once_with(key="k", header_name="X-Api-Key")
    kwargs = main_env["client_cls"].call_args.kwargs
    assert kwargs["base_url"].rstrip("/") == BASE_URL
    assert kwargs["verify"] is True
    assert kwargs["proxy"] is False
    assert kwargs["auth_handler"] is main_env["auth_handler"].return_value


def test_main_test_module(mocker, main_env):
    _setup(mocker, BASE_PARAMS, "test-module")
    tm = mocker.patch.object(cf, "test_module", return_value="ok")
    cf.main()
    main_env["return_results"].assert_called_once_with("ok")
    assert tm.call_args.kwargs == {
        "fetch_tailored_indicators": True,
        "fetch_tailored_vulnerabilities": True,
        "first_fetch": cf.DEFAULT_FIRST_FETCH_DAYS,
    }


def test_main_fetch_indicators(mocker, main_env):
    params = {
        **BASE_PARAMS,
        "first_fetch": "30 days",
        "feedTags": "a,b",
        "tlp_color": "AMBER",
        "feedReputation": "Good",
        "insecure": True,
        "proxy": True,
        "fetchTailoredIndicators": False,
        "fetchTailoredVulnerability": False,
    }
    _setup(mocker, params, "fetch-indicators")
    ff = mocker.patch.object(cf, "fetch_feeds")
    cf.main()
    kwargs = ff.call_args.kwargs
    assert kwargs["first_fetch"] == 30
    assert kwargs["feed_tags"] == ["a", "b"]
    assert kwargs["tlp_color"] == "AMBER"
    assert kwargs["feed_reputation"] == "Good"
    assert kwargs["fetch_tailored_indicators"] is False
    assert kwargs["fetch_tailored_vulnerabilities"] is False
    client_kwargs = main_env["client_cls"].call_args.kwargs
    assert client_kwargs["verify"] is False
    assert client_kwargs["proxy"] is True


@pytest.mark.parametrize("command, feed_type", list(cf._TYPE_COMMANDS.items()))
def test_main_type_commands(mocker, main_env, command, feed_type):
    _setup(mocker, BASE_PARAMS, command)
    fbt = mocker.patch.object(cf, "fetch_feeds_by_type", return_value="RES")
    cf.main()
    assert fbt.call_args.args[1] == feed_type
    main_env["return_results"].assert_called_once_with("RES")


@pytest.mark.parametrize("command, search_type", list(cf._SEARCH_COMMANDS.items()))
def test_main_search_commands(mocker, main_env, command, search_type):
    _setup(mocker, BASE_PARAMS, command, {"value": "v"})
    fs = mocker.patch.object(cf, "feed_search", return_value="RES")
    cf.main()
    assert fs.call_args.args[1] == search_type
    assert fs.call_args.args[2] == {"value": "v"}
    main_env["return_results"].assert_called_once_with("RES")


def test_main_forbidden_error(mocker, main_env):
    _setup(mocker, BASE_PARAMS, "test-module")
    mocker.patch.object(cf, "test_module", side_effect=Exception("403 Forbidden"))
    with pytest.raises(SystemExit):
        cf.main()
    main_env["return_error"].assert_called_once_with("Authorization Error: make sure API Key is correctly set")


def test_main_unknown_command(mocker, main_env):
    main_env["return_error"].side_effect = None
    _setup(mocker, BASE_PARAMS, "bogus-command")
    cf.main()
    main_env["return_error"].assert_called_once()
    message = main_env["return_error"].call_args.args[0]
    assert "bogus-command" in message
    assert "not implemented" in message
