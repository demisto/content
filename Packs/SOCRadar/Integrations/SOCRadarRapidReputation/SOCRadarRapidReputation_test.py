import json

import pytest
from CommonServerPython import CommandResults, DemistoException

SOCRADAR_API_ENDPOINT = "https://platform.socradar.com/api"
REPUTATION_SUFFIX = f"{SOCRADAR_API_ENDPOINT}/threatfeed/rapid/reputation"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def make_client(api_key="TestAPIKey"):
    from SOCRadarRapidReputation import Client

    return Client(base_url=SOCRADAR_API_ENDPOINT, api_key=api_key, verify=False, proxy=False)


# ---------- calculate_dbot_score ----------


def test_calculate_dbot_score_unknown():
    from SOCRadarRapidReputation import calculate_dbot_score

    assert calculate_dbot_score(0) == 0
    assert calculate_dbot_score(None) == 0


def test_calculate_dbot_score_suspicious():
    from SOCRadarRapidReputation import calculate_dbot_score

    assert calculate_dbot_score(1) == 2
    assert calculate_dbot_score(49) == 2


def test_calculate_dbot_score_malicious():
    from SOCRadarRapidReputation import calculate_dbot_score

    assert calculate_dbot_score(50) == 3
    assert calculate_dbot_score(100) == 3


# ---------- build_entry_context ----------


def test_build_entry_context():
    from SOCRadarRapidReputation import build_entry_context

    raw = util_load_json("test_data/ip_reputation_response.json")
    result = build_entry_context(raw, "1.2.3.4", "ip")

    assert result["Entity"] == "1.2.3.4"
    assert result["EntityType"] == "ip"
    assert result["Score"] == 85.5
    assert result["IsWhitelisted"] is False
    assert len(result["FindingSources"]) == 1
    assert result["FindingSources"][0]["SourceName"] == "MalwareList"
    assert result["FindingSources"][0]["SeenCount"] == 12


def test_build_entry_context_no_finding_sources():
    from SOCRadarRapidReputation import build_entry_context

    raw = {"is_success": True, "data": {"score": 0.0, "is_whitelisted": True, "finding_sources": []}}
    result = build_entry_context(raw, "8.8.8.8", "ip")

    assert result["IsWhitelisted"] is True
    assert result["FindingSources"] == []


# ---------- ip_command ----------


def test_ip_command(requests_mock):
    from SOCRadarRapidReputation import ip_command

    requests_mock.get(REPUTATION_SUFFIX, json=util_load_json("test_data/ip_reputation_response.json"))

    results = ip_command(make_client(), {"ip": "1.2.3.4"}, reliability="B - Usually reliable")

    assert len(results) == 1
    assert isinstance(results[0], CommandResults)
    assert results[0].outputs["Entity"] == "1.2.3.4"
    assert results[0].outputs["Score"] == 85.5
    assert "1.2.3.4" in results[0].readable_output


def test_ip_command_invalid_ip():
    from SOCRadarRapidReputation import ip_command

    results = ip_command(make_client(), {"ip": "not-an-ip"}, reliability=None)

    assert len(results) == 1
    assert "not a type of IPv4 or IPv6" in results[0].readable_output


def test_ip_command_api_failure(requests_mock):
    from SOCRadarRapidReputation import ip_command

    requests_mock.get(REPUTATION_SUFFIX, json={"is_success": False, "message": "Service unavailable"})

    results = ip_command(make_client(), {"ip": "1.2.3.4"}, reliability=None)

    assert len(results) == 1
    assert "Error" in results[0].readable_output


# ---------- domain_command ----------


def test_domain_command(requests_mock):
    from SOCRadarRapidReputation import domain_command

    requests_mock.get(REPUTATION_SUFFIX, json=util_load_json("test_data/domain_reputation_response.json"))

    results = domain_command(make_client(), {"domain": "example.com"}, reliability="B - Usually reliable")

    assert len(results) == 1
    assert results[0].outputs["Entity"] == "example.com"
    assert results[0].outputs["Score"] == 45.0


def test_domain_command_invalid_domain():
    from SOCRadarRapidReputation import domain_command

    results = domain_command(make_client(), {"domain": "not a domain!!"}, reliability=None)

    assert len(results) == 1
    assert "not a valid domain" in results[0].readable_output


# ---------- url_command ----------


def test_url_command(requests_mock):
    from SOCRadarRapidReputation import url_command

    requests_mock.get(REPUTATION_SUFFIX, json=util_load_json("test_data/ip_reputation_response.json"))

    results = url_command(make_client(), {"url": "https://example.com/path"}, reliability=None)

    assert len(results) == 1
    assert results[0].outputs["Entity"] == "https://example.com/path"


def test_url_command_invalid_url():
    from SOCRadarRapidReputation import url_command

    results = url_command(make_client(), {"url": "not-a-url"}, reliability=None)

    assert len(results) == 1
    assert "not a valid URL" in results[0].readable_output


# ---------- file_command ----------


def test_file_command_md5(requests_mock):
    from SOCRadarRapidReputation import file_command

    requests_mock.get(REPUTATION_SUFFIX, json=util_load_json("test_data/ip_reputation_response.json"))

    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    results = file_command(make_client(), {"file": md5}, reliability=None)

    assert len(results) == 1
    assert results[0].outputs["Entity"] == md5


def test_file_command_invalid_hash():
    from SOCRadarRapidReputation import file_command

    results = file_command(make_client(), {"file": "notahash"}, reliability=None)

    assert len(results) == 1
    assert "not a valid hash" in results[0].readable_output


# ---------- handle_error_response ----------


def test_handle_error_response_401(requests_mock):
    from SOCRadarRapidReputation import MESSAGES

    requests_mock.get(REPUTATION_SUFFIX, json={"message": "Unauthorized"}, status_code=401)

    with pytest.raises(DemistoException, match=MESSAGES["AUTHORIZATION_ERROR"]):
        make_client(api_key="WrongKey").get_entity_reputation("1.2.3.4", "ip")


def test_handle_error_response_429(requests_mock):
    from SOCRadarRapidReputation import MESSAGES

    requests_mock.get(REPUTATION_SUFFIX, json={}, status_code=429)

    with pytest.raises(DemistoException, match=MESSAGES["RATE_LIMIT_EXCEED_ERROR"]):
        make_client().get_entity_reputation("1.2.3.4", "ip")


# ---------- detect_entity_type ----------


def test_detect_entity_type_ip():
    from SOCRadarRapidReputation import detect_entity_type

    assert detect_entity_type("1.2.3.4") == "ip"
    assert detect_entity_type("2001:db8::1") == "ip"


def test_detect_entity_type_url():
    from SOCRadarRapidReputation import detect_entity_type

    assert detect_entity_type("https://example.com") == "url"
    assert detect_entity_type("http://test.org/path") == "url"


def test_detect_entity_type_hash():
    from SOCRadarRapidReputation import detect_entity_type

    assert detect_entity_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"


def test_detect_entity_type_domain():
    from SOCRadarRapidReputation import detect_entity_type

    assert detect_entity_type("example.com") == "hostname"


def test_detect_entity_type_unknown():
    from SOCRadarRapidReputation import detect_entity_type

    with pytest.raises(ValueError, match="Unable to determine entity type"):
        detect_entity_type("???not-valid???")
