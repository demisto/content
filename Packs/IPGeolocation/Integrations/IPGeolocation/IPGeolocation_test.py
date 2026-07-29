"""Unit tests for the IPGeolocation.io Cortex XSOAR integration.

Every API interaction is mocked. No test performs a real network call.
"""

import json
import os

import pytest
import requests
from CommonServerPython import Common, DBotScoreReliability, DemistoException, EntryType

from IPGeolocation import (
    Client,
    ReputationConfig,
    abuse_contact_command,
    asn_command,
    build_client,
    ip_lookup_command,
    ip_reputation_command,
    ip_security_command,
    normalize_asn,
    prune_empty,
    remap_keys,
    score_security,
    run_test_module,
    validate_choices,
    validate_ip,
    validate_ip_or_domain,
    IPGEO_MAPPING,
)

BASE_URL = "https://api.ipgeolocation.io"
API_KEY = "test-api-key"
TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_data")


def load_test_data(name: str) -> dict:
    """Load a JSON fixture captured from the official documentation.

    :param name: Fixture file name, without the extension.
    :return: Parsed fixture.
    """
    with open(os.path.join(TEST_DATA_DIR, f"{name}.json"), encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture()
def client() -> Client:
    """Build a client pointed at the mocked base URL.

    :return: Configured client.
    """
    return Client(base_url=BASE_URL, api_key=API_KEY, verify=False, proxy=False, timeout=5)


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["8.8.8.8", "2607:fb91:16c6:8860:e531:2d1d:4944:6c7c", " 1.1.1.1 "])
def test_validate_ip_accepts_valid_addresses(value):
    """Valid IPv4 and IPv6 addresses are accepted and trimmed."""
    assert validate_ip(value) == value.strip()


@pytest.mark.parametrize("value", ["", "  ", "not-an-ip", "8.8.8.256", "ipgeolocation.io", "8.8.8.8/24"])
def test_validate_ip_rejects_invalid_addresses(value):
    """Malformed values, CIDR blocks and domains are rejected for IP only endpoints."""
    with pytest.raises(DemistoException):
        validate_ip(value)


@pytest.mark.parametrize("value", ["8.8.8.8", "ipgeolocation.io", "sub.example.co.uk"])
def test_validate_ip_or_domain_accepts_documented_inputs(value):
    """GET /v3/ipgeo accepts IP addresses and domain names."""
    assert validate_ip_or_domain(value) == value


@pytest.mark.parametrize("value", ["", "not a domain", "-bad.example.com", "example"])
def test_validate_ip_or_domain_rejects_invalid_inputs(value):
    """Values that are neither an IP address nor a domain name are rejected."""
    with pytest.raises(DemistoException):
        validate_ip_or_domain(value)


@pytest.mark.parametrize(("value", "expected"), [("24940", "24940"), ("AS24940", "24940"), ("as12", "12")])
def test_normalize_asn_accepts_both_notations(value, expected):
    """ASN arguments are accepted with and without the AS prefix."""
    assert normalize_asn(value) == expected


@pytest.mark.parametrize("value", ["", "ASN24940", "AS", "12abc", "-1"])
def test_normalize_asn_rejects_invalid_values(value):
    """Malformed ASN arguments are rejected before a request is made."""
    with pytest.raises(DemistoException):
        normalize_asn(value)


def test_validate_choices_rejects_undocumented_values():
    """Only documented include values are forwarded to the API."""
    with pytest.raises(DemistoException) as error:
        validate_choices(["security", "not_a_module"], {"security", "abuse"}, "include")
    assert "not_a_module" in str(error.value)


def test_validate_choices_joins_documented_values():
    """Documented values are joined into the comma separated API format."""
    assert validate_choices(["security", "abuse"], {"security", "abuse"}, "include") == "security,abuse"


def test_asn_command_requires_one_identifier(client):
    """The ASN command requires exactly one of the ip or asn arguments."""
    with pytest.raises(DemistoException):
        asn_command(client, {})
    with pytest.raises(DemistoException):
        asn_command(client, {"ip": "8.8.8.8", "asn": "24940"})


def test_build_client_requires_api_key():
    """A missing API key produces a configuration error rather than a 401."""
    with pytest.raises(DemistoException) as error:
        build_client({"url": BASE_URL, "credentials": {"password": ""}})
    assert "API key is required" in str(error.value)


@pytest.mark.parametrize("timeout", ["0", "1000", "abc"])
def test_build_client_rejects_invalid_timeout(timeout):
    """The HTTP timeout is validated against the supported range."""
    with pytest.raises(DemistoException):
        build_client({"credentials": {"password": API_KEY}, "timeout": timeout})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_prune_empty_preserves_false_and_zero():
    """Negative detections and zero confidence scores must survive pruning."""
    pruned = prune_empty({"IsVPN": False, "ThreatScore": 0, "RelayProviderName": "", "Names": [], "Nested": {"A": None}})
    assert pruned == {"IsVPN": False, "ThreatScore": 0}


def test_remap_keys_omits_absent_fields():
    """Fields absent from the API response are not invented in the context."""
    remapped = remap_keys({"ip": "8.8.8.8"}, IPGEO_MAPPING)
    assert remapped == {"IP": "8.8.8.8"}


def test_remap_keys_maps_nested_documented_objects():
    """Nested objects and arrays are remapped to PascalCase context keys."""
    remapped = remap_keys(load_test_data("ipgeo_full"), IPGEO_MAPPING)
    assert remapped["Location"]["CountryCode2"] == "US"
    assert remapped["ASN"]["ASNumber"] == "AS62240"
    assert remapped["Security"]["VPNProviderNames"] == ["Nord VPN"]
    assert remapped["TimeZone"]["DSTStart"]["Duration"] == "+1.00H"


# ---------------------------------------------------------------------------
# test-module
# ---------------------------------------------------------------------------


def test_run_test_module_returns_ok(requests_mock, client):
    """test-module performs exactly one documented lookup and returns ok."""
    matcher = requests_mock.get(f"{BASE_URL}/v3/ipgeo", json=load_test_data("ipgeo_free"))
    assert run_test_module(client) == "ok"
    assert matcher.call_count == 1
    assert matcher.last_request.qs["ip"] == ["8.8.8.8"]
    assert matcher.last_request.qs["apikey"] == [API_KEY]


def test_run_test_module_surfaces_invalid_api_key(requests_mock, client):
    """An invalid API key produces an actionable 401 message."""
    requests_mock.get(f"{BASE_URL}/v3/ipgeo", status_code=401, json={"message": "Invalid API key."})
    with pytest.raises(DemistoException) as error:
        run_test_module(client)
    assert "HTTP 401" in str(error.value)
    assert "Invalid API key." in str(error.value)


# ---------------------------------------------------------------------------
# HTTP error handling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status_code", "expected_fragment"),
    [
        (400, "Bad Request"),
        (401, "Unauthorized"),
        (403, "Forbidden"),
        (404, "Not Found"),
        (423, "Locked"),
        (429, "Too Many Requests"),
        (499, "Client Closed Request"),
        (500, "server side error"),
        (503, "server side error"),
    ],
)
def test_error_handler_maps_documented_status_codes(requests_mock, client, status_code, expected_fragment):
    """Every documented status code is translated into a meaningful error."""
    requests_mock.get(f"{BASE_URL}/v3/security", status_code=status_code, json={"message": "provider detail"})
    with pytest.raises(DemistoException) as error:
        client.get_ip_security(ip="8.8.8.8")
    message = str(error.value)
    assert f"HTTP {status_code}" in message
    assert expected_fragment in message
    assert "provider detail" in message


def test_error_handler_tolerates_non_json_error_body(requests_mock, client):
    """An HTML or plain text error body still yields a usable error."""
    requests_mock.get(f"{BASE_URL}/v3/abuse", status_code=502, text="<html>Bad Gateway</html>")
    with pytest.raises(DemistoException) as error:
        client.get_abuse_contact(ip="1.0.0.0")
    assert "HTTP 502" in str(error.value)


def test_invalid_json_success_body_is_rejected(requests_mock, client):
    """A 200 response that is not valid JSON is reported clearly."""
    requests_mock.get(f"{BASE_URL}/v3/ipgeo", status_code=200, text="<html>proxy interstitial</html>")
    with pytest.raises(DemistoException) as error:
        client.get_ip_geolocation(ip="8.8.8.8")
    assert "not valid JSON" in str(error.value)


def test_empty_response_body_is_rejected(requests_mock, client):
    """An empty 200 response is reported instead of producing empty context."""
    requests_mock.get(f"{BASE_URL}/v3/ipgeo", status_code=200, text="")
    with pytest.raises(DemistoException) as error:
        client.get_ip_geolocation(ip="8.8.8.8")
    assert "empty response" in str(error.value)


def test_non_object_json_is_rejected(requests_mock, client):
    """A JSON array where an object is documented is reported clearly."""
    requests_mock.get(f"{BASE_URL}/v3/asn", status_code=200, json=[{"asn": {}}])
    with pytest.raises(DemistoException) as error:
        client.get_asn(asn="24940")
    assert "unexpected JSON structure" in str(error.value)


def test_message_only_payload_is_rejected(requests_mock, client):
    """A payload carrying only a message field is surfaced as an error."""
    requests_mock.get(f"{BASE_URL}/v3/security", status_code=200, json={"message": "'10.0.0.0' is a bogon IP address."})
    with pytest.raises(DemistoException) as error:
        client.get_ip_security(ip="10.0.0.0")
    assert "bogon" in str(error.value)


def test_read_timeout_is_reported_with_the_setting(requests_mock, client):
    """A read timeout points the analyst at the configurable HTTP timeout."""
    requests_mock.get(f"{BASE_URL}/v3/ipgeo", exc=requests.exceptions.ReadTimeout)
    with pytest.raises(DemistoException) as error:
        client.get_ip_geolocation(ip="8.8.8.8")
    assert "timed out after 5 seconds" in str(error.value)


def test_connection_error_is_reported(requests_mock, client):
    """A connection failure is converted into a Cortex XSOAR error."""
    requests_mock.get(f"{BASE_URL}/v3/ipgeo", exc=requests.exceptions.ConnectionError)
    with pytest.raises(DemistoException):
        client.get_ip_geolocation(ip="8.8.8.8")


# ---------------------------------------------------------------------------
# ipgeolocation-ip-lookup
# ---------------------------------------------------------------------------


def test_ip_lookup_success(requests_mock, client):
    """A successful lookup populates context, readable output and raw response."""
    raw = load_test_data("ipgeo_full")
    requests_mock.get(f"{BASE_URL}/v3/ipgeo", json=raw)
    results = ip_lookup_command(client, {"ip": "2.56.188.34", "include": "security"})

    assert len(results) == 1
    result = results[0]
    assert result.outputs_prefix == "IPGeolocation.IP"
    assert result.outputs_key_field == "IP"
    assert result.outputs["IP"] == "2.56.188.34"
    assert result.outputs["Location"]["City"] == "Dallas"
    assert result.outputs["Security"]["ThreatScore"] == 80
    assert result.raw_response == raw
    assert "IPGeolocation.io IP Geolocation for 2.56.188.34" in result.readable_output
    assert "IPGeolocation.io IP Security for 2.56.188.34" in result.readable_output


def test_ip_lookup_free_plan_response(requests_mock, client):
    """A Free plan response yields context without inventing paid only fields."""
    requests_mock.get(f"{BASE_URL}/v3/ipgeo", json=load_test_data("ipgeo_free"))
    result = ip_lookup_command(client, {"ip": "8.8.8.8"})[0]
    assert "Security" not in result.outputs
    assert "Company" not in result.outputs
    assert result.outputs["ASN"] == {"ASNumber": "AS15169", "Organization": "Google LLC", "Country": "US"}


def test_ip_lookup_forwards_documented_parameters(requests_mock, client):
    """include, fields, excludes and lang are forwarded as documented."""
    matcher = requests_mock.get(f"{BASE_URL}/v3/ipgeo", json=load_test_data("ipgeo_full"))
    ip_lookup_command(
        client,
        {"ip": "2.56.188.34", "include": "security,abuse", "fields": "location.city", "excludes": "currency", "lang": "de"},
    )
    query = matcher.last_request.qs
    assert query["include"] == ["security,abuse"]
    assert query["fields"] == ["location.city"]
    assert query["excludes"] == ["currency"]
    assert query["lang"] == ["de"]


def test_ip_lookup_rejects_undocumented_language(client):
    """An unsupported language is rejected before a credit is spent."""
    with pytest.raises(DemistoException):
        ip_lookup_command(client, {"ip": "8.8.8.8", "lang": "xx"})


def test_ip_lookup_continues_after_a_single_failure(requests_mock, client):
    """One failing address does not abort the enrichment of the others."""
    requests_mock.get(
        f"{BASE_URL}/v3/ipgeo",
        [
            {"status_code": 423, "json": {"message": "bogon"}},
            {"status_code": 200, "json": load_test_data("ipgeo_free")},
        ],
    )
    results = ip_lookup_command(client, {"ip": "10.0.0.1,8.8.8.8"})
    assert len(results) == 2
    assert results[0].entry_type == EntryType.WARNING
    assert "Could not retrieve" in results[0].readable_output
    assert results[1].outputs["IP"] == "8.8.8.8"


# ---------------------------------------------------------------------------
# ipgeolocation-ip-security
# ---------------------------------------------------------------------------


def test_ip_security_success(requests_mock, client):
    """Security signals are mapped and rendered without losing false flags."""
    requests_mock.get(f"{BASE_URL}/v3/security", json=load_test_data("security_malicious"))
    result = ip_security_command(client, {"ip": "2.56.188.34"})[0]
    assert result.outputs["Security"]["IsVPN"] is True
    assert result.outputs["Security"]["IsTor"] is False
    assert result.outputs["Security"]["ProxyConfidenceScore"] == 80
    assert "Threat Score" in result.readable_output


def test_ip_security_clean_ip_keeps_zero_scores(requests_mock, client):
    """A clean IP keeps its zero threat score in context."""
    requests_mock.get(f"{BASE_URL}/v3/security", json=load_test_data("security_clean"))
    result = ip_security_command(client, {"ip": "91.128.103.196"})[0]
    assert result.outputs["Security"]["ThreatScore"] == 0
    assert result.outputs["Security"]["IsAnonymous"] is False
    assert "RelayProviderName" not in result.outputs["Security"]


# ---------------------------------------------------------------------------
# ipgeolocation-abuse-contact
# ---------------------------------------------------------------------------


def test_abuse_contact_success(requests_mock, client, mocker):
    """Abuse contacts populate both the branded context and the IP indicator."""
    mocker.patch.object(__import__("IPGeolocation").demisto, "params", return_value={})
    requests_mock.get(f"{BASE_URL}/v3/abuse", json=load_test_data("abuse"))
    result = abuse_contact_command(client, {"ip": "1.0.0.0"})[0]

    assert result.outputs["Abuse"]["Emails"] == ["helpdesk@apnic.net"]
    assert result.outputs["Abuse"]["Route"] == "1.0.0.0/24"
    assert "Organization" not in result.outputs["Abuse"]

    indicator_context = result.indicator.to_context()
    ip_context = indicator_context[Common.IP.CONTEXT_PATH]
    assert ip_context["Address"] == "1.0.0.0"
    assert ip_context["Registrar"]["Abuse"]["Email"] == "helpdesk@apnic.net"
    assert result.indicator.dbot_score.score == Common.DBotScore.NONE


# ---------------------------------------------------------------------------
# ipgeolocation-asn
# ---------------------------------------------------------------------------


def test_asn_lookup_by_asn(requests_mock, client):
    """A lookup by ASN sends the normalized ASN and omits the ip parameter."""
    matcher = requests_mock.get(f"{BASE_URL}/v3/asn", json=load_test_data("asn_basic"))
    result = asn_command(client, {"asn": "AS24940"})[0]

    assert matcher.last_request.qs["asn"] == ["24940"]
    assert "ip" not in matcher.last_request.qs
    assert result.outputs_prefix == "IPGeolocation.ASN"
    assert result.outputs_key_field == "ASNumber"
    assert result.outputs["ASNumber"] == "AS24940"
    assert result.outputs["NumOfIPv4Routes"] == "84"
    assert "IPGeolocation.io ASN Details for AS24940" in result.readable_output


def test_asn_lookup_by_ip_with_relations(requests_mock, client):
    """Routing relations and the WHOIS record are mapped and rendered."""
    matcher = requests_mock.get(f"{BASE_URL}/v3/asn", json=load_test_data("asn_full"))
    result = asn_command(client, {"ip": "49.12.0.0", "include": "peers,upstreams,downstreams,routes,whois_response"})[0]

    assert matcher.last_request.qs["ip"] == ["49.12.0.0"]
    assert result.outputs["IP"] == "49.12.0.0"
    assert result.outputs["Peers"] == [{"ASNumber": "AS3356", "Description": "Level 3 Parent, LLC", "Country": "US"}]
    assert result.outputs["Routes"] == ["192.76.177.0/24", "216.165.96.0/20", "2607:f600::/32"]
    assert "AllocationStatus" not in result.outputs
    for section in ("Peers", "Upstreams", "Downstreams", "Announced Routes", "WHOIS Record"):
        assert section in result.readable_output


def test_asn_rejects_undocumented_include(client):
    """Only the five documented ASN include objects are accepted."""
    with pytest.raises(DemistoException):
        asn_command(client, {"asn": "12", "include": "security"})


# ---------------------------------------------------------------------------
# Reputation scoring
# ---------------------------------------------------------------------------


def config(**overrides) -> ReputationConfig:
    """Build a reputation configuration with the documented defaults.

    :param overrides: Parameters to override.
    :return: Reputation configuration.
    """
    params = {"integrationReliability": DBotScoreReliability.B}
    params.update(overrides)
    return ReputationConfig(params)


def test_score_security_bad_on_threshold():
    """A threat score at or above the malicious threshold scores Bad."""
    score, message = score_security({"threat_score": 80}, config())
    assert score == Common.DBotScore.BAD
    assert "malicious threshold 70" in message


def test_score_security_bad_on_known_attacker():
    """A known attacker scores Bad even with a low threat score."""
    score, message = score_security({"threat_score": 5, "is_known_attacker": True}, config())
    assert score == Common.DBotScore.BAD
    assert "known attacker" in message


def test_score_security_known_attacker_can_be_disabled():
    """Disabling the known attacker rule leaves a low threat score Good."""
    score, _ = score_security({"threat_score": 5, "is_known_attacker": True}, config(malicious_on_known_attacker=False))
    assert score == Common.DBotScore.GOOD


def test_score_security_suspicious_on_anonymizer():
    """An anonymizing network scores Suspicious by default."""
    score, message = score_security({"threat_score": 0, "is_vpn": True, "is_tor": True}, config())
    assert score == Common.DBotScore.SUSPICIOUS
    assert "Tor exit node" in message
    assert "VPN network" in message


def test_score_security_suspicious_on_bot_or_spam():
    """Bot and spam activity score Suspicious by default."""
    score, message = score_security({"threat_score": 0, "is_spam": True}, config())
    assert score == Common.DBotScore.SUSPICIOUS
    assert "spam" in message


def test_score_security_good_for_clean_ip():
    """A clean IP with no adverse signals scores Good."""
    score, message = score_security(load_test_data("security_clean")["security"], config())
    assert score == Common.DBotScore.GOOD
    assert "No adverse security signals" in message


def test_score_security_unknown_without_security_object():
    """A response with no security object yields an Unknown reputation."""
    score, message = score_security(None, config())
    assert score == Common.DBotScore.NONE
    assert "paid IPGeolocation.io subscription" in message


def test_reputation_config_rejects_inverted_thresholds():
    """The suspicious threshold cannot exceed the malicious threshold."""
    with pytest.raises(DemistoException):
        config(malicious_threshold=30, suspicious_threshold=90)


@pytest.mark.parametrize("value", ["-1", "101", "high"])
def test_reputation_config_rejects_out_of_range_thresholds(value):
    """Thresholds outside 0 to 100 are rejected."""
    with pytest.raises(DemistoException):
        config(malicious_threshold=value)


# ---------------------------------------------------------------------------
# ip reputation command
# ---------------------------------------------------------------------------


def test_ip_reputation_with_geolocation(requests_mock, client):
    """The default mode enriches with geolocation and sets a DBotScore."""
    matcher = requests_mock.get(f"{BASE_URL}/v3/ipgeo", json=load_test_data("ipgeo_full"))
    result = ip_reputation_command(client, {"ip": "2.56.188.34"}, {"integrationReliability": DBotScoreReliability.B})[0]

    assert matcher.last_request.qs["include"] == ["security"]
    assert result.indicator.dbot_score.score == Common.DBotScore.BAD
    assert result.indicator.dbot_score.reliability == DBotScoreReliability.B
    assert result.outputs["Location"]["City"] == "Dallas"
    assert "IPGeolocation.io IP Geolocation" in result.readable_output
    assert "**Reputation:**" in result.readable_output


def test_ip_reputation_security_only_mode(requests_mock, client):
    """Disabling geolocation uses the cheaper dedicated security endpoint."""
    matcher = requests_mock.get(f"{BASE_URL}/v3/security", json=load_test_data("security_clean"))
    result = ip_reputation_command(
        client,
        {"ip": "91.128.103.196"},
        {"reputation_with_geolocation": False, "integrationReliability": DBotScoreReliability.C},
    )[0]

    assert matcher.call_count == 1
    assert result.indicator.dbot_score.score == Common.DBotScore.GOOD
    assert result.indicator.dbot_score.reliability == DBotScoreReliability.C
    assert "IPGeolocation.io IP Geolocation" not in result.readable_output


def test_ip_reputation_indicator_tags_reflect_signals(requests_mock, client):
    """Detected anonymizer and hosting signals become indicator tags."""
    requests_mock.get(f"{BASE_URL}/v3/ipgeo", json=load_test_data("ipgeo_full"))
    result = ip_reputation_command(client, {"ip": "2.56.188.34"}, {})[0]
    assert set(result.indicator.tags) == {
        "proxy",
        "residential-proxy",
        "vpn",
        "known-attacker",
        "cloud-provider",
    }


def test_ip_reputation_skips_private_addresses_without_a_request(requests_mock, client):
    """Private addresses are short circuited so no credit is spent."""
    matcher = requests_mock.get(f"{BASE_URL}/v3/ipgeo", json=load_test_data("ipgeo_free"))
    results = ip_reputation_command(client, {"ip": "10.0.0.1"}, {})
    assert matcher.call_count == 0
    assert results[0].entry_type == EntryType.WARNING
    assert "Locked" in results[0].readable_output


def test_ip_reputation_handles_multiple_addresses(requests_mock, client):
    """The command accepts a list and returns one result per address."""
    requests_mock.get(f"{BASE_URL}/v3/ipgeo", json=load_test_data("ipgeo_full"))
    results = ip_reputation_command(client, {"ip": "2.56.188.34,2.56.188.35"}, {})
    assert len(results) == 2


def test_ip_reputation_rate_limit_is_reported(requests_mock, client):
    """A quota error is reported per address as a warning entry."""
    requests_mock.get(f"{BASE_URL}/v3/ipgeo", status_code=429, json={"message": "quota reached"})
    results = ip_reputation_command(client, {"ip": "8.8.8.8"}, {})
    assert results[0].entry_type == EntryType.WARNING
    assert "HTTP 429" in results[0].readable_output
