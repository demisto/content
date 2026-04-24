import json

import pytest
from CommonServerPython import CommandResults, DemistoException

SOCRADAR_API_ENDPOINT = "https://platform.socradar.com/api"
ENRICHMENT_SUFFIX = f"{SOCRADAR_API_ENDPOINT}/ioc_enrichment/get/indicator_details"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def make_client(api_key="TestAPIKey", include_ai_insights=False):
    from SOCRadarIoCEnrichment import Client

    return Client(
        base_url=SOCRADAR_API_ENDPOINT,
        api_key=api_key,
        verify=False,
        proxy=False,
        include_ai_insights=include_ai_insights,
    )


# ---------- calculate_dbot_score ----------


def test_calculate_dbot_score_unknown():
    from SOCRadarIoCEnrichment import calculate_dbot_score

    assert calculate_dbot_score(0) == 0
    assert calculate_dbot_score(None) == 0


def test_calculate_dbot_score_suspicious():
    from SOCRadarIoCEnrichment import calculate_dbot_score

    assert calculate_dbot_score(1) == 2
    assert calculate_dbot_score(50) == 2


def test_calculate_dbot_score_malicious():
    from SOCRadarIoCEnrichment import calculate_dbot_score

    assert calculate_dbot_score(51) == 3
    assert calculate_dbot_score(100) == 3


def test_calculate_dbot_score_list_input():
    from SOCRadarIoCEnrichment import calculate_dbot_score

    assert calculate_dbot_score([85.0]) == 3
    assert calculate_dbot_score([0]) == 0
    assert calculate_dbot_score([]) == 0


# ---------- build_entry_context ----------


def test_build_entry_context():
    from SOCRadarIoCEnrichment import build_entry_context

    raw = util_load_json("test_data/ip_enrichment_response.json")
    result = build_entry_context(raw, "1.2.3.4")

    assert result["Indicator"] == "1.2.3.4"
    assert result["Score"] == 85.0
    assert result["Country"] == "United States"
    assert result["ASN"] == "TestASN Inc"
    assert result["IsWhitelisted"] is False
    assert result["Categorization"]["Malware"] is True
    assert result["Classifications"]["Malwares"] == ["TestMalware"]
    assert len(result["History"]) == 1
    assert result["History"][0]["Event"] == "first_seen"


def test_build_entry_context_ai_insight():
    from SOCRadarIoCEnrichment import build_entry_context

    raw = util_load_json("test_data/ip_enrichment_response.json")
    raw["socradar_copilot:ioc_agent"] = "This IP is associated with botnet activity."
    result = build_entry_context(raw, "1.2.3.4")

    assert result["AIInsight"] == "This IP is associated with botnet activity."


# ---------- detect_indicator_type ----------


def test_detect_indicator_type_ip():
    from SOCRadarIoCEnrichment import detect_indicator_type

    assert detect_indicator_type("1.2.3.4") == "ip"
    assert detect_indicator_type("2001:db8::1") == "ip"


def test_detect_indicator_type_url():
    from SOCRadarIoCEnrichment import detect_indicator_type

    assert detect_indicator_type("https://example.com") == "url"


def test_detect_indicator_type_hash():
    from SOCRadarIoCEnrichment import detect_indicator_type

    assert detect_indicator_type("d41d8cd98f00b204e9800998ecf8427e") == "file"


def test_detect_indicator_type_domain():
    from SOCRadarIoCEnrichment import detect_indicator_type

    assert detect_indicator_type("example.com") == "domain"


def test_detect_indicator_type_unknown():
    from SOCRadarIoCEnrichment import detect_indicator_type

    with pytest.raises(ValueError, match="Unable to determine indicator type"):
        detect_indicator_type("???not-valid???")


# ---------- ip_command ----------


def test_ip_command(requests_mock):
    from SOCRadarIoCEnrichment import ip_command

    requests_mock.post(ENRICHMENT_SUFFIX, json=util_load_json("test_data/ip_enrichment_response.json"))

    results = ip_command(make_client(), {"ip": "1.2.3.4"}, reliability="B - Usually reliable")

    assert len(results) == 1
    assert isinstance(results[0], CommandResults)
    assert results[0].outputs["Indicator"] == "1.2.3.4"
    assert results[0].outputs["Score"] == 85.0
    assert "1.2.3.4" in results[0].readable_output


def test_ip_command_invalid_ip():
    from SOCRadarIoCEnrichment import ip_command

    results = ip_command(make_client(), {"ip": "not-an-ip"}, reliability=None)

    assert len(results) == 1
    assert "not a valid IPv4 or IPv6" in results[0].readable_output


# ---------- domain_command ----------


def test_domain_command(requests_mock):
    from SOCRadarIoCEnrichment import domain_command

    requests_mock.post(ENRICHMENT_SUFFIX, json=util_load_json("test_data/ip_enrichment_response.json"))

    results = domain_command(make_client(), {"domain": "example.com"}, reliability=None)

    assert len(results) == 1
    assert results[0].outputs["Indicator"] == "example.com"


def test_domain_command_invalid_domain():
    from SOCRadarIoCEnrichment import domain_command

    results = domain_command(make_client(), {"domain": "not a domain!!"}, reliability=None)

    assert len(results) == 1
    assert "not a valid domain" in results[0].readable_output


# ---------- url_command ----------


def test_url_command(requests_mock):
    from SOCRadarIoCEnrichment import url_command

    requests_mock.post(ENRICHMENT_SUFFIX, json=util_load_json("test_data/ip_enrichment_response.json"))

    results = url_command(make_client(), {"url": "https://example.com/path"}, reliability=None)

    assert len(results) == 1
    assert results[0].outputs["Indicator"] == "https://example.com/path"


def test_url_command_invalid_url():
    from SOCRadarIoCEnrichment import url_command

    results = url_command(make_client(), {"url": "not-a-url"}, reliability=None)

    assert len(results) == 1
    assert "not a valid URL" in results[0].readable_output


# ---------- file_command ----------


def test_file_command_sha256(requests_mock):
    from SOCRadarIoCEnrichment import file_command

    requests_mock.post(ENRICHMENT_SUFFIX, json=util_load_json("test_data/ip_enrichment_response.json"))

    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    results = file_command(make_client(), {"file": sha256}, reliability=None)

    assert len(results) == 1
    assert results[0].outputs["Indicator"] == sha256


def test_file_command_invalid_hash():
    from SOCRadarIoCEnrichment import file_command

    results = file_command(make_client(), {"file": "notahash"}, reliability=None)

    assert len(results) == 1
    assert "not a valid hash" in results[0].readable_output


# ---------- handle_error_response ----------


def test_handle_error_response_401(requests_mock):
    from SOCRadarIoCEnrichment import MESSAGES

    requests_mock.post(
        ENRICHMENT_SUFFIX,
        json=util_load_json("test_data/auth_error_response.json"),
        status_code=401,
    )

    with pytest.raises(DemistoException, match=MESSAGES["AUTHORIZATION_ERROR"]):
        make_client(api_key="WrongKey").get_indicator_enrichment("1.2.3.4")


def test_handle_error_response_429(requests_mock):
    from SOCRadarIoCEnrichment import MESSAGES

    requests_mock.post(ENRICHMENT_SUFFIX, json={}, status_code=429)

    with pytest.raises(DemistoException, match=MESSAGES["RATE_LIMIT_EXCEED_ERROR"]):
        make_client().get_indicator_enrichment("1.2.3.4")
