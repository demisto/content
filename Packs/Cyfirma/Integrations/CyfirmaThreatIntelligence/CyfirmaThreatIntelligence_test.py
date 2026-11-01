"""Unit tests for the CYFIRMA Threat Intelligence feed integration."""

from unittest.mock import ANY, MagicMock

import CyfirmaThreatIntelligence as mod  # <-- change to your module name
import demistomock as demisto
import pytest
from CommonServerPython import DemistoException, FeedIndicatorType, ThreatIntel

BASE_URL = "https://api.test/api/ex/v3/da"

IND_EXT = mod._INDICATOR_EXTENSION_ID
VUL_EXT = mod._VUL_EXTENSION_ID
TA_EXT = mod._TA_EXTENSION_ID
MAL_EXT = mod._MALWARE_EXTENSION_ID

IND = {
    "type": "indicator",
    "id": "indicator--1",
    "pattern": "[ipv4-addr:value = '1.1.1.1']",
    "created": "2026-10-01T00:00:00Z",
    "modified": "2026-10-02T00:00:00Z",
    "confidence": 90,
    "labels": ["botnet", "c2"],
    "description": "bad ip",
    "extensions": {
        IND_EXT: {
            "country": "IN",
            "recommended_action": "BLOCK",
            "security_vendors": {"a": 1},
            "threat_actors": "APT1",
        }
    },
}
VUL = {
    "type": "vulnerability",
    "id": "vulnerability--1",
    "name": "CVE-2026-1",
    "confidence": 85,
    "description": "desc",
    "modified": "2026-10-03T00:00:00Z",
    "extensions": {
        VUL_EXT: {
            "cvss_base_score": 9.8,
            "cvss_vector": "AV:N",
            "cvss_version": "3.1",
            "attack_vector": "NETWORK",
            "kev": True,
            "vendors": ["v1", "v2"],
            "products": ["p"],
        }
    },
}
TA = {"type": "threat-actor", "id": "threat-actor--1", "name": "APT1", "confidence": 70}
MAL = {"type": "malware", "id": "malware--1", "name": "Zeus", "confidence": 60}
LOC = {
    "type": "location",
    "id": "location--1",
    "name": "India",
    "latitude": 1.5,
    "longitude": 2.5,
    "country": "IN",
    "city": "Delhi",
    "region": "asia",
}
REL = {
    "type": "relationship",
    "id": "relationship--1",
    "relationship_type": "uses",
    "source_ref": TA["id"],
    "target_ref": MAL["id"],
}


@pytest.fixture
def client():
    return mod.Client(base_url=BASE_URL, verify=False, headers={"X-Api-Key": "k"})


# ------------------------------------------------------------------ helpers
class TestHelpers:
    @pytest.mark.parametrize(
        "value, expected",
        [(None, []), ("", []), ([1], [1]), ("a", ["a"]), (5, [5]), ([], [])],
    )
    def test_as_list(self, value, expected):
        assert mod._as_list(value) == expected

    def test_first_of(self):
        data = {"a": "", "b": None, "c": [], "d": {}, "e": "found", "f": "later"}
        assert mod.first_of(data, "a", "b", "c", "d", "e", "f") == "found"

    def test_first_of_default(self):
        assert mod.first_of({"a": ""}, "a", "zz", default="dflt") == "dflt"
        assert mod.first_of({}, "a") is None

    def test_first_of_keeps_falsy_zero(self):
        assert mod.first_of({"a": 0}, "a", default=5) == 0

    @pytest.mark.parametrize(
        "confidence, expected",
        [
            (100, (3, "Malicious")),
            (80, (3, "Malicious")),
            (79, (2, "Suspicious")),
            (50, (2, "Suspicious")),
            (49, (1, "Benign")),
            (0, (1, "Benign")),
            (None, (1, "Benign")),
            ("abc", (1, "Benign")),
            ("85", (3, "Malicious")),
        ],
    )
    def test_confidence_to_score(self, confidence, expected):
        assert mod.confidence_to_score(confidence) == expected

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("60 days", 60),
            ("30", 30),
            (7, 7),
            (None, mod.DEFAULT_FIRST_FETCH_DAYS),
            ("", mod.DEFAULT_FIRST_FETCH_DAYS),
            ("abc", mod.DEFAULT_FIRST_FETCH_DAYS),
        ],
    )
    def test_parse_days(self, value, expected):
        assert mod._parse_days(value) == expected

    def test_get_ti_ext_id(self):
        assert mod.get_ti_ext_id(mod.LABEL_VULNERABILITY) == VUL_EXT
        assert mod.get_ti_ext_id(mod.LABEL_THREAT_ACTOR) == TA_EXT
        assert mod.get_ti_ext_id(mod.LABEL_MALWARE) == MAL_EXT
        assert mod.get_ti_ext_id(mod.LABEL_INDICATOR) == IND_EXT
        assert mod.get_ti_ext_id("unknown") == IND_EXT

    @pytest.mark.parametrize(
        "obj, expected",
        [
            ({"name": "HQ", "city": "x"}, "HQ"),
            ({"city": "Delhi", "region": "N", "country": "IN"}, "Delhi, N, IN"),
            ({"country": "IN"}, "IN"),
            ({"latitude": 1, "longitude": 2}, "1,2"),
            ({"latitude": 1}, ""),
            ({}, ""),
        ],
    )
    def test_location_value(self, obj, expected):
        assert mod.location_value(obj) == expected


class TestParsePattern:
    @pytest.mark.parametrize(
        "pattern, expected_type, expected_value",
        [
            ("[ipv4-addr:value = '1.1.1.1']", FeedIndicatorType.IP, "1.1.1.1"),
            ("[ipv4-addr:value = '10.0.0.0/8']", FeedIndicatorType.CIDR, "10.0.0.0/8"),
            ("[ipv6-addr:value = '2001:db8::1']", FeedIndicatorType.IPv6, "2001:db8::1"),
            ("[ipv6-addr:value = '2001:db8::/32']", FeedIndicatorType.IPv6CIDR, "2001:db8::/32"),
            ("[domain-name:value = 'evil.com']", FeedIndicatorType.Domain, "evil.com"),
            ("[email-addr:value = 'a@b.com']", FeedIndicatorType.Email, "a@b.com"),
            ("[url:value = 'http://a.com/x']", FeedIndicatorType.URL, "http://a.com/x"),
            (r"[url:value = 'http://a.com/it\'s']", FeedIndicatorType.URL, "http://a.com/it's"),
            ("  [DOMAIN-NAME:value = 'upper.com']", FeedIndicatorType.Domain, "upper.com"),
        ],
    )
    def test_supported(self, pattern, expected_type, expected_value):
        ioc_type, value, hashes = mod.parse_pattern(pattern)
        assert (ioc_type, value) == (expected_type, expected_value)
        assert hashes == {}

    def test_file_prefers_sha256(self):
        pattern = "[file:hashes.'SHA-256' = 'abc' AND file:hashes.MD5 = 'def']"
        ioc_type, value, hashes = mod.parse_pattern(pattern)
        assert ioc_type == FeedIndicatorType.File
        assert value == "abc"
        assert hashes == {"sha256": "abc", "md5": "def"}

    def test_file_only_md5(self):
        _, value, hashes = mod.parse_pattern("[file:hashes.MD5 = 'def']")
        assert value == "def"
        assert hashes == {"md5": "def"}

    def test_file_double_quoted_algo_and_sha1(self):
        _, value, hashes = mod.parse_pattern("[file:hashes.\"SHA-1\" = 'aaa']")
        assert value == "aaa"
        assert hashes == {"sha1": "aaa"}

    def test_file_unknown_algo_falls_back_to_first_value(self):
        ioc_type, value, hashes = mod.parse_pattern("[file:hashes.'FOO' = 'zzz']")
        assert ioc_type == FeedIndicatorType.File
        assert value == "zzz"
        assert hashes == {}

    def test_file_duplicate_algo_keeps_first(self):
        _, _, hashes = mod.parse_pattern("[file:hashes.MD5 = 'one' OR file:hashes.MD5 = 'two']")
        assert hashes == {"md5": "one"}

    @pytest.mark.parametrize("pattern", ["", None, "garbage", "[mutex:name = 'x']", "[ipv4-addr:value = ]"])
    def test_invalid(self, pattern):
        ioc_type, value, hashes = mod.parse_pattern(pattern)  # type: ignore[arg-type]
        assert hashes == {}
        assert not (ioc_type and value)


# ------------------------------------------------------------------ call_api
class TestCallApi:
    def test_json(self, client, requests_mock):
        requests_mock.get(f"{BASE_URL}/x", json={"a": 1})
        assert client.call_api("/x") == {"a": 1}

    def test_empty_body(self, client, requests_mock):
        requests_mock.get(f"{BASE_URL}/x", status_code=200, content=b"")
        assert client.call_api("/x") == {}

    def test_error(self, client, requests_mock):
        requests_mock.get(f"{BASE_URL}/x", status_code=401, text="Unauthorized")
        with pytest.raises(DemistoException):
            client.call_api("/x")

    def test_headers_and_params(self, client, requests_mock):
        m = requests_mock.get(f"{BASE_URL}/x", json={})
        client.call_api("/x", params={"page": 1})
        assert m.last_request.headers["X-Api-Key"] == "k"
        assert m.last_request.qs == {"page": ["1"]}


# ------------------------------------------------------------------ _identify_feed_type
class TestIdentifyFeedType:
    def test_indicator_from_pattern(self, client):
        assert client._identify_feed_type(IND) == ("1.1.1.1", FeedIndicatorType.IP)

    def test_indicator_falls_back_to_name(self, client):
        obj = {"type": "indicator", "pattern": "garbage", "name": "8.8.8.8"}
        assert client._identify_feed_type(obj) == ("8.8.8.8", FeedIndicatorType.IP)

    def test_indicator_name_undetectable(self, client):
        obj = {"type": "indicator", "pattern": "garbage", "name": "!!not an ioc!!"}
        assert client._identify_feed_type(obj) == ("", "")

    def test_indicator_no_pattern_no_name(self, client):
        assert client._identify_feed_type({"type": "indicator"}) == ("", "")

    def test_vulnerability(self, client):
        assert client._identify_feed_type(VUL) == ("CVE-2026-1", FeedIndicatorType.CVE)

    def test_threat_actor_and_malware(self, client):
        assert client._identify_feed_type(TA) == ("APT1", ThreatIntel.ObjectsNames.THREAT_ACTOR)
        assert client._identify_feed_type(MAL) == ("Zeus", ThreatIntel.ObjectsNames.MALWARE)

    def test_location(self, client):
        assert client._identify_feed_type(LOC) == ("India", mod._LOCATION_TYPE)

    def test_bare_observable(self, client):
        obj = {"type": "ipv4-addr", "value": "2.2.2.2"}
        assert client._identify_feed_type(obj) == ("2.2.2.2", FeedIndicatorType.IP)
        obj = {"type": "domain-name", "name": "x.com"}
        assert client._identify_feed_type(obj) == ("x.com", FeedIndicatorType.Domain)

    @pytest.mark.parametrize("obj", [{"type": "something-else"}, {}, {"type": None}])
    def test_unsupported(self, client, obj):
        assert client._identify_feed_type(obj) == ("", "")

    def test_type_is_case_insensitive(self, client):
        assert client._identify_feed_type({"type": "MALWARE", "name": "Z"})[0] == "Z"


# ------------------------------------------------------------------ relationships
class TestBuildRelationships:
    def test_non_indicator_source(self, client):
        objs = {TA["id"]: TA, MAL["id"]: MAL}
        rel = client._build_relationships(REL, objs)
        assert rel["name"] == "uses"
        assert rel["entityA"] == "APT1"
        assert rel["entityB"] == "Zeus"
        assert rel["entityAType"] == ThreatIntel.ObjectsNames.THREAT_ACTOR
        # Regression: target type must come from the TARGET object
        assert rel["entityBType"] == ThreatIntel.ObjectsNames.MALWARE

    def test_indicator_source_forces_indicator_of(self, client):
        rel_obj = {**REL, "source_ref": IND["id"], "target_ref": TA["id"]}
        rel = client._build_relationships(rel_obj, {IND["id"]: IND, TA["id"]: TA})
        assert rel["name"] == "indicator-of"
        assert rel["entityA"] == "1.1.1.1"
        assert rel["entityAType"] == FeedIndicatorType.IP
        assert rel["entityB"] == "APT1"

    def test_alias_applied(self, client):
        rel_obj = {**REL, "relationship_type": "indicates"}
        rel = client._build_relationships(rel_obj, {TA["id"]: TA, MAL["id"]: MAL})
        assert rel["name"] == "indicator-of"

    @pytest.mark.parametrize("missing", ["source_ref", "target_ref"])
    def test_missing_referenced_object(self, client, missing):
        objs = {TA["id"]: TA, MAL["id"]: MAL}
        rel_obj = {**REL, missing: "does-not-exist"}
        assert client._build_relationships(rel_obj, objs) == {}

    def test_unsupported_entity(self, client):
        odd = {"type": "weird", "id": "weird--1"}
        rel_obj = {**REL, "target_ref": odd["id"]}
        assert client._build_relationships(rel_obj, {TA["id"]: TA, odd["id"]: odd}) == {}

    def test_missing_relationship_type(self, client):
        rel_obj = {**REL, "relationship_type": ""}
        assert client._build_relationships(rel_obj, {TA["id"]: TA, MAL["id"]: MAL}) == {}


# ------------------------------------------------------------------ _convert_threat_intel_obj
class TestConvert:
    def test_indicator(self, client):
        res = client._convert_threat_intel_obj(IND, "AMBER", "Bad", ["t1", "botnet"])
        assert res["value"] == "1.1.1.1"
        assert res["type"] == FeedIndicatorType.IP
        assert res["score"] == 3
        assert res["service"] == "CYFIRMA"
        assert res["rawJSON"] == IND
        f = res["fields"]
        assert f["tags"] == ["t1", "botnet", "c2"]  # merged + de-duplicated, order kept
        assert f["trafficlightprotocol"] == "AMBER"
        assert f["reputation"] == "Bad"
        assert f["geocountry"] == "IN"
        assert f["blocked"] is True
        assert f["confidence"] == 90
        assert f["stixid"] == "indicator--1"
        assert f["firstseenbysource"] == "2026-10-01T00:00:00Z"
        assert f["lastseenbysource"] == "2026-10-02T00:00:00Z"

    def test_indicator_monitor_not_blocked(self, client):
        obj = {**IND, "extensions": {IND_EXT: {"recommended_action": "MONITOR"}}}
        res = client._convert_threat_intel_obj(obj, "", "", [])
        assert "blocked" not in res["fields"]
        assert "reputation" not in res["fields"]

    def test_indicator_none_recommended_action_does_not_crash(self, client):
        obj = {**IND, "extensions": {IND_EXT: {"recommended_action": None}}}
        res = client._convert_threat_intel_obj(obj, "", "", [])
        assert "blocked" not in res["fields"]

    def test_indicator_plural_recommended_actions_key(self, client):
        obj = {**IND, "extensions": {IND_EXT: {"recommended_actions": "block"}}}
        assert client._convert_threat_intel_obj(obj, "", "", [])["fields"]["blocked"] is True

    def test_indicator_without_extensions(self, client):
        obj = {k: v for k, v in IND.items() if k != "extensions"}
        res = client._convert_threat_intel_obj(obj, "", "", [])
        assert res["fields"]["geocountry"] == ""

    def test_file_indicator_hash_fields(self, client):
        obj = {
            **IND,
            "pattern": "[file:hashes.'SHA-256' = 'abc' AND file:hashes.MD5 = 'def']",
        }
        res = client._convert_threat_intel_obj(obj, "", "", [])
        assert res["type"] == FeedIndicatorType.File
        assert res["value"] == "abc"
        assert res["fields"]["sha256"] == "abc"
        assert res["fields"]["md5"] == "def"

    def test_null_confidence(self, client):
        res = client._convert_threat_intel_obj({**IND, "confidence": None}, "", "", [])
        assert res["score"] == 1
        assert res["fields"]["confidence"] == 0

    def test_vulnerability_v3(self, client):
        res = client._convert_threat_intel_obj(VUL, "", "", [])
        f = res["fields"]
        assert res["type"] == FeedIndicatorType.CVE
        assert f["verdict"] == "Malicious"
        assert f["score"] == 3
        assert f["cvssscore"] == 9.8
        assert f["cvssvector"] == "AV:N"
        assert f["cvssversion"] == "3.1"
        assert f["cvedescription"] == "desc"
        assert f["cvemodified"] == "2026-10-03T00:00:00Z"

        metrics = {m["metrics"]: m["value"] for m in f["cvsstable"]}
        assert metrics["Attack vector"] == "NETWORK"
        assert "Privileges required" in metrics  # v3-only metric
        assert "Access vector" not in metrics  # v2-only metric
        assert metrics["KEV"] == "True"
        assert metrics["Vendors"] == "v1, v2"
        assert metrics["Products"] == "p"
        assert "Technologies" not in metrics
        assert len(f["cvsstable"]) == 5 + 5 + 3

    def test_vulnerability_v2_metrics(self, client):
        obj = {**VUL, "extensions": {VUL_EXT: {"cvss_version": "2.0", "access_vector": "N"}}}
        metrics = {m["metrics"]: m["value"] for m in client._convert_threat_intel_obj(obj, "", "", [])["fields"]["cvsstable"]}
        assert metrics["Access vector"] == "N"
        assert "Attack vector" not in metrics
        assert len(metrics) == 5 + 3

    def test_vulnerability_without_version_or_extension(self, client):
        obj = {"type": "vulnerability", "id": "v", "name": "CVE-1"}
        f = client._convert_threat_intel_obj(obj, "", "", [])["fields"]
        assert len(f["cvsstable"]) == 5
        assert f["cvssversion"] == ""

    def test_vulnerability_non_string_version(self, client):
        obj = {**VUL, "extensions": {VUL_EXT: {"cvss_version": 3.1}}}
        f = client._convert_threat_intel_obj(obj, "", "", [])["fields"]
        assert len(f["cvsstable"]) == 10

    def test_threat_actor_and_malware_scores(self, client):
        ta = client._convert_threat_intel_obj({**TA, "aliases": ["x"]}, "", "", [])
        assert ta["type"] == ThreatIntel.ObjectsNames.THREAT_ACTOR
        assert ta["score"] == mod._TI_SCORES[ThreatIntel.ObjectsNames.THREAT_ACTOR]
        assert ta["fields"]["aliases"] == ["x"]
        mal = client._convert_threat_intel_obj(MAL, "", "", [])
        assert mal["score"] == mod._TI_SCORES[ThreatIntel.ObjectsNames.MALWARE]

    def test_location(self, client):
        res = client._convert_threat_intel_obj(LOC, "", "", [])
        assert res["score"] == 0
        f = res["fields"]
        assert f["geolocation"] == "1.5,2.5"
        assert f["countryname"] == "IN"
        assert f["city"] == "Delhi"
        assert f["region"] == "asia"

    def test_location_without_coordinates(self, client):
        res = client._convert_threat_intel_obj({"type": "location", "name": "X"}, "", "", [])
        assert "geolocation" not in res["fields"]

    def test_unsupported_object(self, client):
        assert client._convert_threat_intel_obj({"type": "weird"}, "", "", []) == {}

    def test_none_feed_tags(self, client):
        res = client._convert_threat_intel_obj(IND, "", "", None)  # type: ignore[arg-type]
        assert res["fields"]["tags"] == ["botnet", "c2"]


# ------------------------------------------------------------------ paging / enrichment
class TestFetchAllPages:
    def test_pages_until_empty(self, client, mocker):
        seen_pages = []
        responses = iter([{"objects": [1]}, {"objects": [2, 3]}, {"objects": []}])

        def fake(path, params=None):
            seen_pages.append((path, params["page"]))
            return next(responses)

        mocker.patch.object(client, "call_api", side_effect=fake)
        feeds: list = []
        original = {"lookBackDays": 5}
        client._fetch_all_pages(original, "/p", feeds)

        assert feeds == [1, 2, 3]
        assert seen_pages == [("/p", 0), ("/p", 1), ("/p", 2)]
        assert original == {"lookBackDays": 5}  # not mutated

    @pytest.mark.parametrize("response", [{}, None, {"objects": None}])
    def test_handles_empty_responses(self, client, mocker, response):
        mocker.patch.object(client, "call_api", return_value=response)
        feeds: list = []
        client._fetch_all_pages({}, "/p", feeds)
        assert feeds == []


class TestFetchThreatActorsData:
    def test_chunking_and_filtering(self, client, mocker):
        names = [f"TA{i}" for i in range(12)]
        m = mocker.patch.object(
            client,
            "call_api",
            return_value={"objects": [TA, MAL, REL]},
        )
        feeds: list = []
        client._fetch_threat_actors_data(names, feeds)

        assert m.call_count == 2
        assert m.call_args_list[0].kwargs["params"]["values"] == names[:10]
        assert m.call_args_list[1].kwargs["params"]["values"] == names[10:]
        # threat-actor objects are not re-added, others are
        assert TA not in feeds
        assert feeds.count(MAL) == 2
        assert feeds.count(REL) == 2

    def test_failed_chunk_is_skipped(self, client, mocker):
        err = mocker.patch.object(demisto, "error")
        m = mocker.patch.object(client, "call_api", side_effect=[Exception("boom"), {"objects": [MAL]}])
        feeds: list = []
        client._fetch_threat_actors_data([f"T{i}" for i in range(11)], feeds)
        assert m.call_count == 2
        assert feeds == [MAL]
        err.assert_called_once()

    def test_no_names_no_calls(self, client, mocker):
        m = mocker.patch.object(client, "call_api")
        client._fetch_threat_actors_data([], [])
        m.assert_not_called()

    def test_none_response(self, client, mocker):
        mocker.patch.object(client, "call_api", return_value=None)
        feeds: list = []
        client._fetch_threat_actors_data(["a"], feeds)
        assert feeds == []


# ------------------------------------------------------------------ get_feeds
class TestGetFeeds:
    def _patch(self, client, mocker, ind_objs=None, vul_objs=None):
        paths, params_seen = [], []
        ind_objs = ind_objs if ind_objs is not None else [IND, IND, TA, REL_IND_TA]
        vul_objs = vul_objs if vul_objs is not None else [VUL, {"type": "weird", "id": "w"}]

        def fake(params, path, feeds):
            paths.append(path)
            params_seen.append(params)
            feeds.extend(ind_objs if "indicators" in path else vul_objs)

        mocker.patch.object(client, "_fetch_all_pages", side_effect=fake)
        ta_mock = mocker.patch.object(client, "_fetch_threat_actors_data")
        return paths, params_seen, ta_mock

    def test_full_flow(self, client, mocker):
        paths, params_seen, ta_mock = self._patch(client, mocker)
        res = client.get_feeds(7, "RED", "Bad", ["tag"], True, True)

        assert paths == [
            f"{mod._IOC_API_PATHS}{mod._TAILORED_PATHS}",
            f"{mod._VUL_API_PATHS}{mod._TAILORED_PATHS}",
        ]
        assert params_seen[0]["lookBackDays"] == 7
        assert params_seen[0]["withRelationships"] is True
        assert params_seen[0]["delta"] is True
        assert "X-Request-ID" in client._headers
        ta_mock.assert_called_once_with(ta_names=["APT1"], feeds=ANY)

        indicators = [r for r in res if "entityA" not in r]
        rels = [r for r in res if "entityA" in r]
        # IND (duplicate removed), TA, VUL; the unsupported object is dropped
        assert [i["value"] for i in indicators] == ["1.1.1.1", "APT1", "CVE-2026-1"]
        assert len(rels) == 1
        assert rels[0]["name"] == "indicator-of"
        assert res[-1] is rels[0]  # relationships come last

    def test_non_tailored_paths(self, client, mocker):
        paths, _, _ = self._patch(client, mocker, ind_objs=[], vul_objs=[])
        assert client.get_feeds(1, "", "", [], False, False) == []
        assert paths == [
            f"{mod._IOC_API_PATHS}{mod._ALL_PATHS}",
            f"{mod._VUL_API_PATHS}{mod._ALL_PATHS}",
        ]

    def test_mixed_tailoring(self, client, mocker):
        paths, _, _ = self._patch(client, mocker, ind_objs=[], vul_objs=[])
        client.get_feeds(1, "", "", [], True, False)
        assert paths[0].endswith(mod._TAILORED_PATHS)
        assert paths[1].endswith(mod._ALL_PATHS)

    def test_relationship_to_unknown_object_is_skipped(self, client, mocker):
        orphan = {**REL, "source_ref": "gone", "target_ref": "also-gone"}
        self._patch(client, mocker, ind_objs=[TA, orphan], vul_objs=[])
        res = client.get_feeds(1, "", "", [], True, True)
        assert [r["value"] for r in res] == ["APT1"]

    def test_unique_threat_actor_names_only(self, client, mocker):
        _, _, ta_mock = self._patch(client, mocker, ind_objs=[TA, {**TA, "id": "threat-actor--2"}], vul_objs=[])
        client.get_feeds(1, "", "", [], True, True)
        assert ta_mock.call_args.kwargs["ta_names"] == ["APT1"]


REL_IND_TA = {
    "type": "relationship",
    "id": "relationship--2",
    "relationship_type": "indicates",
    "source_ref": IND["id"],
    "target_ref": TA["id"],
}


# ------------------------------------------------------------------ test_module
class TestTestModule:
    def test_ok(self, client, mocker):
        mocker.patch.object(client, "call_api", return_value={"isOrgActive": True})
        assert mod.test_module(client, True, True, 60) == "ok"

    def test_ok_with_company(self, client, mocker):
        mocker.patch.object(client, "call_api", return_value={"isOrgActive": True, "isCompanyActive": True})
        assert mod.test_module(client, True, True, 60) == "ok"

    @pytest.mark.parametrize("tailored_ind, tailored_vul", [(False, True), (True, False), (False, False)])
    def test_lookback_too_large_without_tailoring(self, client, mocker, tailored_ind, tailored_vul):
        m = mocker.patch.object(client, "call_api")
        res = mod.test_module(client, tailored_ind, tailored_vul, mod.MAX_DAYS_WITHOUT_TAILORING + 1)
        assert "must not be greater" in res
        m.assert_not_called()

    def test_lookback_at_limit_without_tailoring_is_ok(self, client, mocker):
        mocker.patch.object(client, "call_api", return_value={"isOrgActive": True})
        assert mod.test_module(client, False, False, mod.MAX_DAYS_WITHOUT_TAILORING) == "ok"

    @pytest.mark.parametrize(
        "response",
        [{}, None, {"isOrgActive": False}, {"isOrgActive": True, "isCompanyActive": False}],
    )
    def test_not_authorized(self, client, mocker, response):
        mocker.patch.object(client, "call_api", return_value=response)
        assert mod.test_module(client, True, True, 1) == "Not Authorized"

    @pytest.mark.parametrize("msg", ["Forbidden", "Unauthorized"])
    def test_auth_error(self, client, mocker, msg):
        mocker.patch.object(client, "call_api", side_effect=DemistoException(msg))
        assert "Authorization Error" in mod.test_module(client, True, True, 1)

    def test_other_error_reraised(self, client, mocker):
        mocker.patch.object(client, "call_api", side_effect=DemistoException("boom"))
        with pytest.raises(DemistoException, match="boom"):
            mod.test_module(client, True, True, 1)


# ------------------------------------------------------------------ fetch_feeds
class TestFetchFeeds:
    def _kwargs(self):
        return {
            "first_fetch": 5,
            "tlp_color": "RED",
            "feed_reputation": "Bad",
            "feed_tags": ["t"],
            "fetch_tailored_indicators": True,
            "fetch_tailored_vulnerabilities": False,
        }

    def test_creates_indicators_in_one_batch(self, mocker):
        fake_client = MagicMock()
        fake_client.get_feeds.return_value = [{"v": 1}, {"v": 2}, {"v": 3}]
        create = mocker.patch.object(demisto, "createIndicators")
        mod.fetch_feeds(fake_client, **self._kwargs())
        fake_client.get_feeds.assert_called_once_with(**self._kwargs())
        create.assert_called_once_with([{"v": 1}, {"v": 2}, {"v": 3}])

    def test_batches(self, mocker):
        mocker.patch.object(mod, "INDICATOR_BATCH_SIZE", 2)
        fake_client = MagicMock()
        fake_client.get_feeds.return_value = [{"v": i} for i in range(5)]
        create = mocker.patch.object(demisto, "createIndicators")
        mod.fetch_feeds(fake_client, **self._kwargs())
        assert [len(c.args[0]) for c in create.call_args_list] == [2, 2, 1]

    def test_no_indicators(self, mocker):
        fake_client = MagicMock()
        fake_client.get_feeds.return_value = []
        create = mocker.patch.object(demisto, "createIndicators")
        mod.fetch_feeds(fake_client, **self._kwargs())
        create.assert_not_called()

    def test_error_logged_and_reraised(self, mocker):
        fake_client = MagicMock()
        fake_client.get_feeds.side_effect = ValueError("bad")
        err = mocker.patch.object(demisto, "error")
        with pytest.raises(ValueError, match="bad"):
            mod.fetch_feeds(fake_client, **self._kwargs())
        err.assert_called_once()


# ------------------------------------------------------------------ build_result
class TestBuildResult:
    def test_empty(self):
        res = mod.build_result([], mod.LABEL_INDICATOR, "t")
        assert res.readable_output == "For current request no data found."

    def test_invalid_type(self):
        with pytest.raises(ValueError, match="Invalid data type"):
            mod.build_result([IND], "Nope", "t")

    def test_indicator(self):
        res = mod.build_result([IND], mod.LABEL_INDICATOR, "My Title")
        assert res.outputs_prefix == "CYFIRMA.Indicators"
        assert res.outputs_key_field == "value"
        out = res.outputs[0]
        assert out == {
            "value": "1.1.1.1",
            "type": FeedIndicatorType.IP,
            "score": 3,
            "country": "IN",
            "threat_actor": "APT1",
            "vendors": {"a": 1},
        }
        assert "My Title" in res.readable_output
        assert "1.1.1.1" in res.readable_output
        assert res.raw_response == [IND]

    def test_indicator_unparsable_pattern(self):
        res = mod.build_result([{"type": "indicator", "pattern": "x"}], mod.LABEL_INDICATOR, "t")
        assert res.outputs[0]["type"] == "Unknown"
        assert res.outputs[0]["value"] == ""

    def test_indicator_null_confidence_and_missing_extensions(self):
        res = mod.build_result(
            [{"pattern": "[domain-name:value = 'a.com']", "confidence": None}],
            mod.LABEL_INDICATOR,
            "t",
        )
        assert res.outputs[0]["score"] == 1
        assert res.outputs[0]["country"] == ""

    def test_vulnerability(self):
        res = mod.build_result([VUL], mod.LABEL_VULNERABILITY, "t")
        assert res.outputs_prefix == "CYFIRMA.Vulnerability"
        out = res.outputs[0]
        assert out["value"] == "CVE-2026-1"
        assert out["type"] == "CVE"
        assert out["score"] == 3
        assert out["confidence"] == 85
        assert out["cvss_base_score"] == 9.8
        assert out["cvss_version"] == "3.1"
        assert out["attack_vector"] == "NETWORK"
        assert out["vendors"] == ["v1", "v2"]
        assert out["scope"] == ""
        assert out["cvss_vector"] == "AV:N"

    def test_vulnerability_defaults(self):
        res = mod.build_result([{"name": "CVE-X"}], mod.LABEL_VULNERABILITY, "t")
        out = res.outputs[0]
        assert out["cvss_version"] == "0.0"
        assert out["cvss_base_score"] == "0.0"
        assert out["cvss_vector"] is None
        assert out["vendors"] == []

    def test_threat_actor(self):
        ta = {
            **TA,
            "extensions": {
                TA_EXT: {
                    "origin_of_country": "RU",
                    "target_countries": ["US"],
                    "motivation": "money",
                }
            },
        }
        res = mod.build_result([ta], mod.LABEL_THREAT_ACTOR, "t")
        assert res.outputs_prefix == "CYFIRMA.ThreatActor"
        out = res.outputs[0]
        assert out["value"] == "APT1"
        assert out["type"] == mod.LABEL_THREAT_ACTOR
        assert out["score"] == 2
        assert out["origin_of_country"] == "RU"
        assert out["target_countries"] == ["US"]
        assert out["motivation"] == "money"
        assert out["associated_malware"] == ""
        assert "RU" in res.readable_output

    def test_malware(self):
        mal = {**MAL, "extensions": {MAL_EXT: {"target_industries": ["Banks"], "country": "US"}}}
        res = mod.build_result([mal], mod.LABEL_MALWARE, "t")
        assert res.outputs_prefix == "CYFIRMA.Malware"
        out = res.outputs[0]
        assert out["value"] == "Zeus"
        assert out["target_industries"] == ["Banks"]
        assert out["country"] == "US"  # read from the malware extension
        assert out["threat_actors"] == ""  # key absent in the extension -> default
        assert out["score"] == 2

    def test_multiple_rows(self):
        res = mod.build_result([VUL, {**VUL, "name": "CVE-2"}], mod.LABEL_VULNERABILITY, "t")
        assert [o["value"] for o in res.outputs] == ["CVE-2026-1", "CVE-2"]


# ------------------------------------------------------------------ fetch_feeds_by_type / feed_search
class TestFetchFeedsByType:
    def test_success(self, client, mocker):
        m = mocker.patch.object(client, "call_api", return_value={"objects": [IND]})
        res = mod.fetch_feeds_by_type(client, "ip")
        m.assert_called_once_with(mod._IOC_API_PATHS, params={"types": ["ip"]})
        assert res.outputs[0]["value"] == "1.1.1.1"
        assert "Type: ip" in res.readable_output

    def test_no_objects(self, client, mocker):
        mocker.patch.object(client, "call_api", return_value={})
        res = mod.fetch_feeds_by_type(client, "domain")
        assert "no data found" in res.readable_output

    def test_error_logged_and_reraised(self, client, mocker):
        mocker.patch.object(client, "call_api", side_effect=DemistoException("down"))
        err = mocker.patch.object(demisto, "error")
        with pytest.raises(DemistoException):
            mod.fetch_feeds_by_type(client, "url")
        err.assert_called_once()


class TestFeedSearch:
    def test_missing_value(self, client):
        with pytest.raises(ValueError, match="Missing required argument"):
            mod.feed_search(client, mod.LABEL_INDICATOR, {})

    def test_invalid_search_type(self, client):
        with pytest.raises(ValueError, match="Invalid search type"):
            mod.feed_search(client, "Nope", {"value": "x"})

    @pytest.mark.parametrize(
        "search_type, objects, expected_prefix",
        [
            (mod.LABEL_INDICATOR, [IND], "CYFIRMA.Indicators"),
            (mod.LABEL_THREAT_ACTOR, [TA], "CYFIRMA.ThreatActor"),
            (mod.LABEL_MALWARE, [MAL], "CYFIRMA.Malware"),
            (mod.LABEL_VULNERABILITY, [VUL], "CYFIRMA.Vulnerability"),
        ],
    )
    def test_each_type_uses_config(self, client, mocker, search_type, objects, expected_prefix):
        path, param_name = mod._SEARCH_CONFIG[search_type]
        m = mocker.patch.object(client, "call_api", return_value={"objects": objects})
        res = mod.feed_search(client, search_type, {"value": "needle"})
        m.assert_called_once_with(end_point=path, params={param_name: ["needle"]})
        assert res.outputs_prefix == expected_prefix
        assert "needle" in res.readable_output

    def test_threat_actor_uses_values_param(self, client, mocker):
        m = mocker.patch.object(client, "call_api", return_value={"objects": [TA]})
        mod.feed_search(client, mod.LABEL_THREAT_ACTOR, {"value": "APT1"})
        assert m.call_args.kwargs["params"] == {"values": ["APT1"]}

    @pytest.mark.parametrize("response", [{}, None, {"other": 1}])
    def test_no_results(self, client, mocker, response):
        mocker.patch.object(client, "call_api", return_value=response)
        res = mod.feed_search(client, mod.LABEL_INDICATOR, {"value": "x"})
        assert "No results found" in res.readable_output

    def test_empty_objects_list(self, client, mocker):
        mocker.patch.object(client, "call_api", return_value={"objects": []})
        res = mod.feed_search(client, mod.LABEL_INDICATOR, {"value": "x"})
        assert "no data found" in res.readable_output


# ------------------------------------------------------------------ main
class TestMain:
    BASE_PARAMS = {
        "url": "https://api.test/",
        "api_key": {"password": "k"},
        "first_fetch": "30 days",
        "feedTags": "a,b",
        "tlp_color": "RED",
        "feedReputation": "Bad",
    }

    def _setup(self, mocker, command, params=None, args=None):
        mocker.patch.object(demisto, "params", return_value=params or self.BASE_PARAMS)
        mocker.patch.object(demisto, "command", return_value=command)
        mocker.patch.object(demisto, "args", return_value=args or {})
        mocker.patch.object(demisto, "info")
        rr = mocker.patch.object(mod, "return_results")
        err = mocker.patch.object(mod, "return_error", side_effect=SystemExit)
        return rr, err

    def test_test_module(self, mocker):
        rr, _ = self._setup(mocker, "test-module")
        m = mocker.patch.object(mod, "test_module", return_value="ok")
        legacy = mocker.patch.object(demisto, "results")
        mod.main()
        m.assert_called_once_with(
            ANY,
            fetch_tailored_indicators=True,
            fetch_tailored_vulnerabilities=True,
            first_fetch=30,
        )
        rr.assert_called_once_with("ok")
        legacy.assert_not_called()  # regression: output was previously duplicated

    def test_test_module_tailoring_disabled(self, mocker):
        self._setup(
            mocker,
            "test-module",
            {**self.BASE_PARAMS, "fetchTailoredIndicators": False, "fetchTailoredVulnerability": "false"},
        )
        m = mocker.patch.object(mod, "test_module", return_value="ok")
        mod.main()
        assert m.call_args.kwargs["fetch_tailored_indicators"] is False
        assert m.call_args.kwargs["fetch_tailored_vulnerabilities"] is False

    def test_fetch_indicators(self, mocker):
        self._setup(mocker, "fetch-indicators")
        m = mocker.patch.object(mod, "fetch_feeds")
        mod.main()
        m.assert_called_once_with(
            client=ANY,
            first_fetch=30,
            tlp_color="RED",
            feed_reputation="Bad",
            feed_tags=["a", "b"],
            fetch_tailored_indicators=True,
            fetch_tailored_vulnerabilities=True,
        )

    def test_fetch_indicators_defaults(self, mocker):
        self._setup(mocker, "fetch-indicators", {"url": "https://x.com", "api_key": {"password": "k"}})
        m = mocker.patch.object(mod, "fetch_feeds")
        mod.main()
        kwargs = m.call_args.kwargs
        assert kwargs["first_fetch"] == mod.DEFAULT_FIRST_FETCH_DAYS
        assert kwargs["tlp_color"] == ""
        assert kwargs["feed_reputation"] == ""
        assert kwargs["feed_tags"] == []

    @pytest.mark.parametrize(
        "command, feed_type",
        [
            ("cyfirma-ip-get", "ip"),
            ("cyfirma-domain-get", "domain"),
            ("cyfirma-url-get", "url"),
            ("cyfirma-file-get", "file"),
        ],
    )
    def test_type_commands(self, mocker, command, feed_type):
        rr, _ = self._setup(mocker, command)
        m = mocker.patch.object(mod, "fetch_feeds_by_type", return_value="RES")
        mod.main()
        m.assert_called_once_with(ANY, feed_type)
        rr.assert_called_once_with("RES")

    @pytest.mark.parametrize(
        "command, label",
        [
            ("cyfirma-ioc-search-get", mod.LABEL_INDICATOR),
            ("cyfirma-threat-actor-search-get", mod.LABEL_THREAT_ACTOR),
            ("cyfirma-malware-search-get", mod.LABEL_MALWARE),
            ("cyfirma-vulnerability-search-get", mod.LABEL_VULNERABILITY),
        ],
    )
    def test_search_commands(self, mocker, command, label):
        rr, _ = self._setup(mocker, command, args={"value": "needle"})
        m = mocker.patch.object(mod, "feed_search", return_value="RES")
        mod.main()
        m.assert_called_once_with(ANY, label, {"value": "needle"})
        rr.assert_called_once_with("RES")

    def test_unknown_command(self, mocker):
        _, err = self._setup(mocker, "nope")
        with pytest.raises(SystemExit):
            mod.main()
        assert "not implemented" in err.call_args.args[0]

    @pytest.mark.parametrize(
        "params",
        [
            {"api_key": {"password": "k"}},
            {"url": "https://x.com"},
            {"url": "https://x.com", "api_key": None},
        ],
    )
    def test_missing_credentials(self, mocker, params):
        _, err = self._setup(mocker, "test-module", params)
        with pytest.raises(SystemExit):
            mod.main()
        assert "required" in err.call_args.args[0]

    def test_command_failure_message(self, mocker):
        _, err = self._setup(mocker, "fetch-indicators")
        mocker.patch.object(mod, "fetch_feeds", side_effect=Exception("kaboom"))
        with pytest.raises(SystemExit):
            mod.main()
        msg = err.call_args.args[0]
        assert "Failed to execute fetch-indicators command" in msg
        assert "kaboom" in msg

    def test_client_built_with_expected_config(self, mocker):
        self._setup(mocker, "test-module", {**self.BASE_PARAMS, "insecure": True, "proxy": True})
        mocker.patch.object(mod, "test_module", return_value="ok")
        client_cls = mocker.patch.object(mod, "Client")
        mod.main()
        kwargs = client_cls.call_args.kwargs
        assert kwargs["base_url"] == "https://api.test/api/ex/v3/da"
        assert kwargs["verify"] is False
        assert kwargs["proxy"] is True
        assert kwargs["headers"] == {"X-Api-Key": "k", "X-App-Name": "PALO_ALTO_XSOAR_V2_TI"}
