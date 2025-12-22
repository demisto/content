"""
Unit tests for APIVoid integration
Tests all commands, helper functions, and error handling scenarios
"""

import pytest
from CommonServerPython import *
from APIVoid import (
    Client,
    calculate_dbot_score,
    ip_reputation_command,
    domain_reputation_command,
    url_reputation_command,
    dns_lookup_command,
    ssl_info_command,
    email_verify_command,
    parked_domain_command,
    domain_age_command,
    screenshot_command,
    url_to_pdf_command,
    site_trustworthiness_command,
    test_module as module_test,
    main,
)


# ============================================================================
# MOCK DATA - V2 API Responses
# ============================================================================

MOCK_IP_RESPONSE = {
    "ip": "8.8.8.8",
    "version": "IPv4",
    "blacklists": {
        "engines": {
            "0": {"name": "0spam", "detected": False, "reference": "https://0spam.org/", "elapsed_ms": 1},
            "1": {"name": "Barracuda", "detected": True, "reference": "https://barracuda.com/", "elapsed_ms": 0},
        },
        "detections": 1,
        "engines_count": 10,
        "detection_rate": "10%",
        "scan_time_ms": 100,
    },
    "information": {
        "reverse_dns": "dns.google",
        "continent_code": "NA",
        "continent_name": "North America",
        "country_code": "US",
        "country_name": "United States",
        "country_calling_code": "1",
        "region_name": "California",
        "city_name": "Mountain View",
        "latitude": 37.386,
        "longitude": -122.084,
        "isp": "Google LLC",
        "asn": "AS15169",
    },
    "anonymity": {"is_proxy": False, "is_webproxy": False, "is_vpn": False, "is_hosting": True, "is_tor": False},
    "risk_score": {"result": 10},
}

MOCK_DOMAIN_RESPONSE = {
    "host": "example.com",
    "blacklists": {
        "engines": {"0": {"name": "0spam", "detected": False, "reference": "https://0spam.org/", "elapsed_ms": 1}},
        "detections": 0,
        "engines_count": 10,
        "detection_rate": "0%",
        "scan_time_ms": 100,
    },
    "server_details": {
        "ip": "93.184.216.34",
        "isp": "Edgecast Inc.",
        "continent_code": "NA",
        "continent_name": "North America",
        "country_code": "US",
        "country_name": "United States",
        "region_name": "California",
        "city_name": "Los Angeles",
        "latitude": "34.0522",
        "longitude": "-118.2437",
        "reverse_dns": "example.com",
    },
    "category": {"is_anonymizer": False, "is_free_dynamic_dns": False, "is_free_hosting": False, "is_url_shortener": False},
    "risk_score": {"result": 0},
    "alexa_top_10k": False,
    "alexa_top_100k": True,
    "alexa_top_250k": True,
    "most_abused_tld": False,
    "domain_length": 11,
}

MOCK_URL_RESPONSE = {
    "url": "https://example.com/test",
    "domain_blacklist": {
        "engines": {"0": {"name": "0spam", "detected": False, "reference": "https://0spam.org/"}},
        "detections": 0,
        "engines_count": 10,
    },
    "html_info": {"title": "Example Domain", "description": "Example website", "keywords": "example, test"},
    "server_details": {
        "ip": "93.184.216.34",
        "hostname": "example.com",
        "isp": "Edgecast Inc.",
        "country_name": "United States",
        "country_code": "US",
        "continent_name": "North America",
        "continent_code": "NA",
        "region_name": "California",
        "city_name": "Los Angeles",
        "latitude": "34.0522",
        "longitude": "-118.2437",
    },
    "security_checks": {"is_domain_blacklisted": False, "is_suspicious_domain": False, "is_phishing_heuristic": False},
    "risk_score": {"result": 0},
    "url_parts": {"host": "example.com", "scheme": "https", "path": "/test", "port": 443},
}

MOCK_DNS_RESPONSE = {
    "records": {
        "found": True,
        "count": 2,
        "items": [
            {"host": "example.com", "class": "IN", "ttl": 3600, "type": "A", "ip": "93.184.216.34"},
            {"host": "example.com", "class": "IN", "ttl": 3600, "type": "A", "ip": "93.184.216.35"},
        ],
    }
}

MOCK_SSL_RESPONSE = {
    "certificate": {
        "found": True,
        "valid": True,
        "expired": False,
        "blacklisted": False,
        "name_match": True,
        "valid_peer": True,
        "fingerprint": "AA:BB:CC:DD:EE:FF",
        "details": {
            "issuer": {"common_name": "DigiCert", "country": "US", "organization": "DigiCert Inc"},
            "subject": {"common_name": "example.com", "country": "US"},
            "validity": {"valid_from": "2023-01-01", "valid_to": "2024-01-01", "days_left": 100},
        },
    }
}

MOCK_EMAIL_RESPONSE = {
    "email": "test@example.com",
    "valid_format": True,
    "username": "test",
    "domain": "example.com",
    "role_address": False,
    "disposable": False,
    "has_mx_records": True,
    "free_email": False,
    "suspicious_username": False,
    "suspicious_domain": False,
    "should_block": False,
    "score": 0,
}

MOCK_PARKED_DOMAIN_RESPONSE = {"host": "example.com", "parked_domain": False}

MOCK_DOMAIN_AGE_RESPONSE = {
    "host": "example.com",
    "domain_age_found": True,
    "domain_registered": "yes",
    "domain_creation_date": "1995-08-14",
    "domain_age_in_days": 10000,
    "domain_age_in_months": 330,
    "domain_age_in_years": 27,
}

MOCK_SCREENSHOT_RESPONSE = {
    "base64_file": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
}

MOCK_PDF_RESPONSE = {
    "base64_file": "JVBERi0xLjQKJeLjz9MKMSAwIG9iago8PC9UeXBlL0NhdGFsb2cvUGFnZXMgMiAwIFI+PgplbmRvYmoKMiAwIG9iago8PC9UeXBlL1BhZ2VzL0tpZHNbMyAwIFJdL0NvdW50IDE+PgplbmRvYmoKMyAwIG9iago8PC9UeXBlL1BhZ2UvTWVkaWFCb3hbMCAwIDMgM10+PgplbmRvYmoKeHJlZgowIDQKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAwMDAwMDEwIDAwMDAwIG4gCjAwMDAwMDAwNTMgMDAwMDAgbiAKMDAwMDAwMDEwMiAwMDAwMCBuIAp0cmFpbGVyCjw8L1NpemUgNC9Sb290IDEgMCBSPj4Kc3RhcnR4cmVmCjE0OAolJUVPRgo="
}

MOCK_SITE_TRUST_RESPONSE = {
    "host": "amazon.com",
    "dns_records": {
        "ns": [
            {
                "target": "ns1.amzndns.net",
                "ip": "156.154.65.10",
                "country_code": "US",
                "country_name": "United States of America",
                "isp": "Vercara LLC",
            },
            {
                "target": "ns2.amzndns.com",
                "ip": "156.154.68.10",
                "country_code": "US",
                "country_name": "United States of America",
                "isp": "Vercara LLC",
            },
        ],
        "mx": [
            {
                "target": "amazon-smtp.amazon.com",
                "ip": "35.172.144.184",
                "country_code": "US",
                "country_name": "United States of America",
                "isp": "Amazon Technologies Inc.",
            }
        ],
        "cname": "",
    },
    "domain_blacklist": {"engines": [], "detections": 0, "engines_count": 30},
    "server_details": {
        "ip": "205.251.242.103",
        "hostname": "s3-console-us-standard.console.aws.amazon.com",
        "continent_code": "NA",
        "continent_name": "North America",
        "country_code": "US",
        "country_name": "United States of America",
        "region_name": "Virginia",
        "city_name": "Ashburn",
        "latitude": 39.039474,
        "longitude": -77.491809,
        "isp": "Amazon.com Inc.",
        "asn": "AS16509",
    },
    "security_checks": {
        "is_suspended_site": False,
        "is_most_abused_tld": False,
        "is_domain_blacklisted": False,
        "is_suspicious_domain": False,
        "is_website_popular": True,
        "is_domain_recent": "no",
        "domain_creation_date": "1994-11-01",
        "domain_age_in_days": 11034,
        "domain_age_in_months": 355,
        "domain_age_in_years": 30,
    },
    "trust_score": {"result": 100},
}

MOCK_ERROR_RESPONSE = {"error": "Invalid API key"}


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def client():
    """
    Create a test client instance

    Given: Valid API credentials
    When: Client is initialized
    Then: Client should be created with proper headers
    """
    return Client(base_url="https://api.apivoid.com", apikey="test-api-key", verify=False, proxy=False)


@pytest.fixture
def mock_demisto(mocker):
    """
    Mock demisto functions

    Given: Demisto environment
    When: Tests are run
    Then: Demisto functions should be mocked
    """
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "credentials": {"password": "test-api-key"},
            "insecure": False,
            "proxy": False,
            "integrationReliability": "C - Fairly reliable",
            "good": "10",
            "suspicious": "30",
            "bad": "60",
        },
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "debug")
    return mocker


# ============================================================================
# TEST CLIENT CLASS
# ============================================================================


class TestClient:
    """Test Client class initialization and methods"""

    def test_client_initialization(self, client):
        """
        Test client initialization

        Given: Valid API credentials
        When: Client is initialized
        Then: Headers should contain API key
        """
        assert client._headers["X-API-Key"] == "test-api-key"
        assert client._headers["Content-Type"] == "application/json"
        assert client._base_url == "https://api.apivoid.com"

    def test_api_request(self, client, mocker):
        """
        Test API request method

        Given: A client instance with use_mock=False
        When: api_request is called
        Then: _http_request should be called with correct parameters
        """
        # Create client with use_mock=False to test actual HTTP request
        client_no_mock = Client(
            base_url="https://api.apivoid.com", apikey="test-api-key", verify=False, proxy=False, use_mock=False
        )
        mock_http = mocker.patch.object(client_no_mock, "_http_request", return_value={"result": "success"})

        result = client_no_mock.api_request("/v2/test", {"param": "value"})

        mock_http.assert_called_once_with(method="POST", url_suffix="/v2/test", json_data={"param": "value"})
        assert result == {"result": "success"}


# ============================================================================
# TEST HELPER FUNCTIONS
# ============================================================================


class TestCalculateDbotScore:
    """Test DBot score calculation logic"""

    def test_score_good_zero_detections(self):
        """
        Test DBot score calculation with zero detections

        Given: 0 detections out of 10 engines_count (0%)
        When: calculate_dbot_score is called
        Then: Score should be GOOD (1)
        """
        score = calculate_dbot_score(engines_count=10, detections=0, thresholds={"good": 10, "suspicious": 30, "bad": 60})
        assert score == Common.DBotScore.GOOD

    def test_score_good_below_threshold(self):
        """
        Test DBot score calculation below good threshold

        Given: 5 detections out of 100 engines_count (5%)
        When: calculate_dbot_score is called with good threshold 10%
        Then: Score should be GOOD (1)
        """
        score = calculate_dbot_score(engines_count=100, detections=5, thresholds={"good": 10, "suspicious": 30, "bad": 60})
        assert score == Common.DBotScore.GOOD

    def test_score_suspicious(self):
        """
        Test DBot score calculation in suspicious range

        Given: 40 detections out of 100 engines_count (40%)
        When: calculate_dbot_score is called with thresholds 10/30/60
        Then: Score should be SUSPICIOUS (2)
        """
        score = calculate_dbot_score(engines_count=100, detections=40, thresholds={"good": 10, "suspicious": 30, "bad": 60})
        assert score == Common.DBotScore.SUSPICIOUS

    def test_score_bad(self):
        """
        Test DBot score calculation in bad range

        Given: 70 detections out of 100 engines_count (70%)
        When: calculate_dbot_score is called with bad threshold 60%
        Then: Score should be BAD (3)
        """
        score = calculate_dbot_score(engines_count=100, detections=70, thresholds={"good": 10, "suspicious": 30, "bad": 60})
        assert score == Common.DBotScore.BAD

    def test_score_none_zero_engines(self):
        """
        Test DBot score calculation with zero engines_count

        Given: 0 engines_count
        When: calculate_dbot_score is called
        Then: Score should be NONE (0)
        """
        score = calculate_dbot_score(engines_count=0, detections=0, thresholds={"good": 10, "suspicious": 30, "bad": 60})
        assert score == Common.DBotScore.NONE

    def test_score_edge_case_at_threshold(self):
        """
        Test DBot score at exact threshold boundary

        Given: 30 detections out of 100 engines_count (30%)
        When: calculate_dbot_score is called with suspicious threshold 30%
        Then: Score should be NONE (0) - exactly at threshold but not above
        """
        # The logic is: if detection_rate > suspicious_threshold, then SUSPICIOUS
        # So 30% is NOT > 30%, therefore it returns NONE
        score = calculate_dbot_score(engines_count=100, detections=30, thresholds={"good": 10, "suspicious": 30, "bad": 60})
        assert score == Common.DBotScore.NONE


# ============================================================================
# TEST IP REPUTATION COMMAND
# ============================================================================


class TestIpReputationCommand:
    """Test IP reputation command"""

    def test_ip_reputation_success(self, client, mocker):
        """
        Test successful IP reputation check

        Given: Valid IP address
        When: ip_reputation_command is called
        Then: Should return CommandResults with IP indicator
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_IP_RESPONSE)

        args = {"ip": "8.8.8.8"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        result = ip_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

        assert isinstance(result, CommandResults)
        assert result.indicator.ip == "8.8.8.8"
        # MOCK_IP_RESPONSE has detections=1, engines_count=10 = 10%
        # The calculate_dbot_score logic:
        # - if detection_rate < good (10): return GOOD
        # - if detection_rate > bad (60): return BAD
        # - if detection_rate > suspicious (30): return SUSPICIOUS
        # - else: return NONE
        # For 10%: NOT < 10, NOT > 60, NOT > 30 -> returns NONE
        assert result.indicator.dbot_score.score == Common.DBotScore.NONE
        assert result.outputs_prefix == "APIVoid.IP"
        assert result.outputs_key_field == "ip"
        assert result.outputs["ip"] == "8.8.8.8"

    def test_ip_reputation_only_mode(self, client, mocker):
        """
        Test IP reputation in reputation_only mode

        Given: Valid IP address with reputation_only=True
        When: ip_reputation_command is called
        Then: Should not include custom APIVoid context
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_IP_RESPONSE)

        args = {"ip": "8.8.8.8"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        result = ip_reputation_command(client, args, True, thresholds, "C - Fairly reliable")

        assert isinstance(result, CommandResults)
        assert result.outputs == {}

    def test_ip_reputation_high_detections(self, client, mocker):
        """
        Test IP reputation with high detection rate

        Given: IP with 70% detection rate
        When: ip_reputation_command is called
        Then: DBot score should be BAD
        """
        high_detection_response = MOCK_IP_RESPONSE.copy()
        high_detection_response["blacklists"]["detections"] = 70
        high_detection_response["blacklists"]["engines_count"] = 100

        mocker.patch.object(client, "api_request", return_value=high_detection_response)

        args = {"ip": "1.2.3.4"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        result = ip_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

        assert result.indicator.dbot_score.score == Common.DBotScore.BAD

    def test_ip_reputation_api_error(self, client, mocker):
        """
        Test IP reputation with API error

        Given: API returns error response
        When: ip_reputation_command is called
        Then: Should return CommandResults with error message
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_ERROR_RESPONSE)

        args = {"ip": "8.8.8.8"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        # Should raise exception, not return CommandResults
        with pytest.raises(DemistoException, match="Error checking IP"):
            ip_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

    def test_ip_reputation_exception(self, client, mocker):
        """
        Test IP reputation with exception

        Given: API request raises exception
        When: ip_reputation_command is called
        Then: Should raise DemistoException
        """
        mocker.patch.object(client, "api_request", side_effect=Exception("Network error"))

        args = {"ip": "8.8.8.8"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        with pytest.raises(DemistoException, match="Failed to get IP reputation"):
            ip_reputation_command(client, args, False, thresholds, "C - Fairly reliable")


# ============================================================================
# TEST DOMAIN REPUTATION COMMAND
# ============================================================================


class TestDomainReputationCommand:
    """Test domain reputation command"""

    def test_domain_reputation_success(self, client, mocker):
        """
        Test successful domain reputation check

        Given: Valid domain
        When: domain_reputation_command is called
        Then: Should return CommandResults with Domain indicator
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_DOMAIN_RESPONSE)

        args = {"domain": "example.com"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        result = domain_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

        assert isinstance(result, CommandResults)
        assert result.indicator.domain == "example.com"
        assert result.indicator.dbot_score.score == Common.DBotScore.GOOD

    def test_domain_reputation_field_mapping(self, client, mocker):
        """
        Test domain reputation V2 to V1 field mapping

        Given: V2 API response with server_details
        When: domain_reputation_command is called
        Then: Should map server_details to server
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_DOMAIN_RESPONSE)

        args = {"domain": "example.com"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        result = domain_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

        # Check that server_details was mapped to server
        assert "server" in result.outputs["APIVoid.Domain(val.host && val.host == obj.host)"]

    def test_domain_reputation_only_mode(self, client, mocker):
        """
        Test domain reputation in reputation_only mode

        Given: Valid domain with reputation_only=True
        When: domain_reputation_command is called
        Then: Should not include custom APIVoid context
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_DOMAIN_RESPONSE)

        args = {"domain": "example.com"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        result = domain_reputation_command(client, args, True, thresholds, "C - Fairly reliable")

        assert result.outputs == {}


# ============================================================================
# TEST URL REPUTATION COMMAND
# ============================================================================


class TestUrlReputationCommand:
    """Test URL reputation command"""

    def test_url_reputation_success(self, client, mocker):
        """
        Test successful URL reputation check

        Given: Valid URL
        When: url_reputation_command is called
        Then: Should return CommandResults with URL indicator
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_URL_RESPONSE)

        args = {"url": "https://example.com/test"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        result = url_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

        assert isinstance(result, CommandResults)
        assert result.indicator.url == "https://example.com/test"
        assert result.indicator.dbot_score.score == Common.DBotScore.GOOD

    def test_url_reputation_field_mapping(self, client, mocker):
        """
        Test URL reputation V2 to V1 field mapping

        Given: V2 API response with html_info
        When: url_reputation_command is called
        Then: Should map html_info to web_page
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_URL_RESPONSE)

        args = {"url": "https://example.com/test"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        result = url_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

        # Check that html_info was mapped to web_page
        assert "web_page" in result.outputs["APIVoid.URL(val.url && val.url == obj.url)"]

    def test_url_reputation_adds_url_to_response(self, client, mocker):
        """
        Test URL reputation adds url to response

        Given: API response without url field
        When: url_reputation_command is called
        Then: Should add url to response
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_URL_RESPONSE)

        args = {"url": "https://example.com/test"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        result = url_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

        assert result.outputs["APIVoid.URL(val.url && val.url == obj.url)"]["url"] == "https://example.com/test"


# ============================================================================
# TEST DNS LOOKUP COMMAND
# ============================================================================


class TestDnsLookupCommand:
    """Test DNS lookup command"""

    def test_dns_lookup_success(self, client, mocker):
        """
        Test successful DNS lookup

        Given: Valid host and DNS type
        When: dns_lookup_command is called
        Then: Should return list of entry objects
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_DNS_RESPONSE)

        args = {"host": "example.com", "type": "A"}

        results = dns_lookup_command(client, args)

        assert isinstance(results, CommandResults)
        assert results.outputs_prefix == "APIVoid.DNS"
        assert results.outputs_key_field == "host"

    def test_dns_lookup_default_type(self, client, mocker):
        """
        Test DNS lookup with default type

        Given: Host without type specified
        When: dns_lookup_command is called
        Then: Should default to A record
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_DNS_RESPONSE)

        args = {"host": "example.com"}

        dns_lookup_command(client, args)

        # Verify API was called with dns_types parameter
        client.api_request.assert_called_with("/v2/dns-lookup", {"host": "example.com", "dns_types": "A"})

    def test_dns_lookup_error(self, client, mocker):
        """
        Test DNS lookup with API error

        Given: API returns error
        When: dns_lookup_command is called
        Then: Should return error CommandResults
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_ERROR_RESPONSE)

        args = {"host": "example.com", "type": "A"}

        # Should raise exception, not return CommandResults
        with pytest.raises(DemistoException, match="Error looking up DNS"):
            dns_lookup_command(client, args)


# ============================================================================
# TEST SSL INFO COMMAND
# ============================================================================


class TestSslInfoCommand:
    """Test SSL info command"""

    def test_ssl_info_success(self, client, mocker):
        """
        Test successful SSL info retrieval

        Given: Valid host with SSL certificate
        When: ssl_info_command is called
        Then: Should return CommandResults with SSL info
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_SSL_RESPONSE)

        args = {"host": "example.com"}

        result = ssl_info_command(client, args)

        assert isinstance(result, CommandResults)
        assert "APIVoid.SSL(val.host && val.host == obj.host)" in result.outputs
        assert result.outputs["APIVoid.SSL(val.host && val.host == obj.host)"]["host"] == "example.com"

    def test_ssl_info_no_certificate(self, client, mocker):
        """
        Test SSL info with no certificate

        Given: Host without SSL certificate
        When: ssl_info_command is called
        Then: Should return message indicating no SSL info
        """
        mocker.patch.object(client, "api_request", return_value={"certificate": None})

        args = {"host": "example.com"}

        result = ssl_info_command(client, args)

        assert "No SSL information" in result.readable_output


# ============================================================================
# TEST EMAIL VERIFY COMMAND
# ============================================================================


class TestEmailVerifyCommand:
    """Test email verify command"""

    def test_email_verify_success(self, client, mocker):
        """
        Test successful email verification

        Given: Valid email address
        When: email_verify_command is called
        Then: Should return CommandResults with email info
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_EMAIL_RESPONSE)

        args = {"email": "test@example.com"}

        result = email_verify_command(client, args)

        assert isinstance(result, CommandResults)
        assert result.outputs_prefix == "APIVoid.Email"
        assert result.outputs_key_field == "email"
        assert result.outputs["email"] == "test@example.com"

    def test_email_verify_empty_response(self, client, mocker):
        """
        Test email verify with empty response

        Given: Empty API response
        When: email_verify_command is called
        Then: Should return message indicating no info
        """
        mocker.patch.object(client, "api_request", return_value={})

        args = {"email": "test@example.com"}

        result = email_verify_command(client, args)

        assert "No information" in result.readable_output


# ============================================================================
# TEST PARKED DOMAIN COMMAND
# ============================================================================


class TestParkedDomainCommand:
    """Test parked domain command"""

    def test_parked_domain_success(self, client, mocker):
        """
        Test successful parked domain check

        Given: Valid domain
        When: parked_domain_command is called
        Then: Should return CommandResults with parked status
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_PARKED_DOMAIN_RESPONSE)

        args = {"domain": "example.com"}

        result = parked_domain_command(client, args)

        assert isinstance(result, CommandResults)
        assert "APIVoid.ParkedDomain(val.host && val.host == obj.host)" in result.outputs
        assert "Domain" in result.outputs


# ============================================================================
# TEST DOMAIN AGE COMMAND
# ============================================================================


class TestDomainAgeCommand:
    """Test domain age command"""

    def test_domain_age_success(self, client, mocker):
        """
        Test successful domain age retrieval

        Given: Valid domain
        When: domain_age_command is called
        Then: Should return CommandResults with age info
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_DOMAIN_AGE_RESPONSE)

        args = {"domain": "example.com"}

        result = domain_age_command(client, args)

        assert isinstance(result, CommandResults)
        assert "APIVoid.DomainAge(val.host && val.host == obj.host)" in result.outputs
        assert "Domain" in result.outputs
        assert result.outputs["Domain"]["CreationDate"] == "1995-08-14"


# ============================================================================
# TEST SCREENSHOT COMMAND
# ============================================================================


class TestScreenshotCommand:
    """Test screenshot command"""

    def test_screenshot_success(self, client, mocker):
        """
        Test successful screenshot capture

        Given: Valid URL
        When: screenshot_command is called
        Then: Should return file result
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_SCREENSHOT_RESPONSE)
        mock_file_result = mocker.patch("APIVoid.fileResult", return_value={"Type": 3, "File": "test.png"})

        args = {"url": "https://example.com"}

        result = screenshot_command(client, args)

        assert mock_file_result.called
        assert result["Type"] == 3

    def test_screenshot_error(self, client, mocker):
        """
        Test screenshot with API error

        Given: API returns error
        When: screenshot_command is called
        Then: Should raise DemistoException
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_ERROR_RESPONSE)

        args = {"url": "https://example.com"}

        with pytest.raises(DemistoException, match="Error capturing screenshot"):
            screenshot_command(client, args)

    def test_screenshot_no_data(self, client, mocker):
        """
        Test screenshot with no data returned

        Given: API returns response without base64_file
        When: screenshot_command is called
        Then: Should raise DemistoException
        """
        mocker.patch.object(client, "api_request", return_value={})

        args = {"url": "https://example.com"}

        with pytest.raises(DemistoException, match="No screenshot data returned"):
            screenshot_command(client, args)


# ============================================================================
# TEST URL TO PDF COMMAND
# ============================================================================


class TestUrlToPdfCommand:
    """Test URL to PDF command"""

    def test_url_to_pdf_success(self, client, mocker):
        """
        Test successful URL to PDF conversion

        Given: Valid URL
        When: url_to_pdf_command is called
        Then: Should return file result
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_PDF_RESPONSE)
        mock_file_result = mocker.patch("APIVoid.fileResult", return_value={"Type": 3, "File": "test.pdf"})

        args = {"url": "https://example.com"}

        result = url_to_pdf_command(client, args)

        assert mock_file_result.called
        assert result["Type"] == 3

    def test_url_to_pdf_error(self, client, mocker):
        """
        Test URL to PDF with API error

        Given: API returns error
        When: url_to_pdf_command is called
        Then: Should raise DemistoException
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_ERROR_RESPONSE)

        args = {"url": "https://example.com"}

        with pytest.raises(DemistoException, match="Error converting URL to PDF"):
            url_to_pdf_command(client, args)


# ============================================================================
# TEST SITE TRUSTWORTHINESS COMMAND
# ============================================================================


class TestSiteTrustworthinessCommand:
    """Test site trustworthiness command"""

    def test_site_trust_success(self, client, mocker):
        """
        Test successful site trustworthiness check

        Given: Valid host with actual API response structure
        When: site_trustworthiness_command is called
        Then: Should return CommandResults with trust info and domain_age mapped from security_checks
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_SITE_TRUST_RESPONSE)

        args = {"host": "amazon.com"}

        result = site_trustworthiness_command(client, args)

        assert isinstance(result, CommandResults)
        assert result.outputs_prefix == "APIVoid.SiteTrust"
        assert result.outputs_key_field == "host"
        assert result.outputs["host"] == "amazon.com"

        # Verify domain_age is created from security_checks fields
        assert "domain_age" in result.outputs
        assert result.outputs["domain_age"]["domain_creation_date"] == "1994-11-01"
        assert result.outputs["domain_age"]["domain_age_in_days"] == 11034
        assert result.outputs["domain_age"]["found"] is True

    def test_site_trust_with_dns_records(self, client, mocker):
        """
        Test site trustworthiness with DNS records

        Given: Response includes NS records in dns_records.ns list
        When: site_trustworthiness_command is called
        Then: Should include dns_records in output
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_SITE_TRUST_RESPONSE)

        args = {"host": "amazon.com"}

        result = site_trustworthiness_command(client, args)

        # Verify dns_records are included
        assert "dns_records" in result.outputs
        assert "ns" in result.outputs["dns_records"]
        assert len(result.outputs["dns_records"]["ns"]) == 2
        assert result.outputs["dns_records"]["ns"][0]["target"] == "ns1.amzndns.net"

    def test_site_trust_without_domain_age(self, client, mocker):
        """
        Test site trustworthiness without domain creation date

        Given: Response without domain age fields in security_checks
        When: site_trustworthiness_command is called
        Then: Should not include domain_age in output
        """
        # Create response without domain age fields in security_checks
        response_no_age = {
            "host": "example.com",
            "dns_records": {"ns": [], "mx": [], "cname": ""},
            "domain_blacklist": {"engines": [], "detections": 0, "engines_count": 30},
            "server_details": {
                "ip": "93.184.216.34",
                "hostname": "example.com",
                "isp": "Edgecast Inc.",
                "country_name": "United States",
            },
            "security_checks": {
                "is_suspended_site": False,
                "is_domain_blacklisted": False,
                "is_suspicious_domain": False,
                # No domain age fields here
            },
            "trust_score": {"result": 50},
        }
        mocker.patch.object(client, "api_request", return_value=response_no_age)

        args = {"host": "example.com"}

        result = site_trustworthiness_command(client, args)

        # domain_age should not be created if no age fields exist in security_checks
        assert isinstance(result, CommandResults)
        assert result.outputs_prefix == "APIVoid.SiteTrust"
        assert result.outputs_key_field == "host"
        # Since security_checks has no domain age fields, domain_age should not be in outputs
        assert "domain_age" not in result.outputs

    def test_site_trust_api_error(self, client, mocker):
        """
        Test site trustworthiness with API error

        Given: API returns error response
        When: site_trustworthiness_command is called
        Then: Should return CommandResults with error message
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_ERROR_RESPONSE)

        args = {"host": "example.com"}

        # Should raise exception, not return CommandResults
        with pytest.raises(DemistoException, match="Error getting site trustworthiness"):
            site_trustworthiness_command(client, args)


# ============================================================================
# TEST MODULE
# ============================================================================


class TestTestModule:
    """Test the test-module command"""

    def test_module_success(self, client, mocker):
        """
        Test successful test-module

        Given: Valid API credentials
        When: test_module is called
        Then: Should return 'ok'
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_IP_RESPONSE)

        result = module_test(client)

        assert result == "ok"

    def test_module_api_error(self, client, mocker):
        """
        Test test-module with API error

        Given: API returns error
        When: test_module is called
        Then: Should return error message
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_ERROR_RESPONSE)

        result = module_test(client)

        assert "Test Failed" in result

    def test_module_exception(self, client, mocker):
        """
        Test test-module with exception

        Given: API request raises exception
        When: test_module is called
        Then: Should return error message
        """
        mocker.patch.object(client, "api_request", side_effect=Exception("Connection error"))

        result = module_test(client)

        assert "Test Failed" in result


# ============================================================================
# TEST MAIN FUNCTION
# ============================================================================


class TestMain:
    """Test main function and command routing"""

    def test_main_test_module(self, mock_demisto, mocker):
        """
        Test main function with test-module command

        Given: test-module command
        When: main is called
        Then: Should call test_module and return results
        """
        mocker.patch.object(demisto, "command", return_value="test-module")
        mock_return_results = mocker.patch("APIVoid.return_results")
        mocker.patch("APIVoid.test_module", return_value="ok")

        main()

        mock_return_results.assert_called_once_with("ok")

    def test_main_ip_command(self, mock_demisto, mocker):
        """
        Test main function with ip command

        Given: ip command
        When: main is called
        Then: Should call ip_reputation_command with reputation_only=True
        """
        mocker.patch.object(demisto, "command", return_value="ip")
        mocker.patch.object(demisto, "args", return_value={"ip": "8.8.8.8"})
        mocker.patch("APIVoid.return_results")
        mock_ip_cmd = mocker.patch("APIVoid.ip_reputation_command", return_value=CommandResults(readable_output="test"))

        main()

        # Verify reputation_only was True
        assert mock_ip_cmd.call_args[0][2] is True

    def test_main_apivoid_ip_command(self, mock_demisto, mocker):
        """
        Test main function with apivoid-ip command

        Given: apivoid-ip command
        When: main is called
        Then: Should call ip_reputation_command with reputation_only=False
        """
        mocker.patch.object(demisto, "command", return_value="apivoid-ip")
        mocker.patch.object(demisto, "args", return_value={"ip": "8.8.8.8"})
        mocker.patch("APIVoid.return_results")
        mock_ip_cmd = mocker.patch("APIVoid.ip_reputation_command", return_value=CommandResults(readable_output="test"))

        main()

        # Verify reputation_only was False
        assert mock_ip_cmd.call_args[0][2] is False

    def test_main_domain_command(self, mock_demisto, mocker):
        """
        Test main function with domain command

        Given: domain command
        When: main is called
        Then: Should call domain_reputation_command
        """
        mocker.patch.object(demisto, "command", return_value="domain")
        mocker.patch.object(demisto, "args", return_value={"domain": "example.com"})
        mocker.patch("APIVoid.return_results")
        mock_domain_cmd = mocker.patch("APIVoid.domain_reputation_command", return_value=CommandResults(readable_output="test"))

        main()

        assert mock_domain_cmd.called

    def test_main_url_command(self, mock_demisto, mocker):
        """
        Test main function with url command

        Given: url command
        When: main is called
        Then: Should call url_reputation_command
        """
        mocker.patch.object(demisto, "command", return_value="url")
        mocker.patch.object(demisto, "args", return_value={"url": "https://example.com"})
        mocker.patch("APIVoid.return_results")
        mock_url_cmd = mocker.patch("APIVoid.url_reputation_command", return_value=CommandResults(readable_output="test"))

        main()

        assert mock_url_cmd.called

    def test_main_dns_lookup_command(self, mock_demisto, mocker):
        """
        Test main function with apivoid-dns-lookup command

        Given: apivoid-dns-lookup command
        When: main is called
        Then: Should call dns_lookup_command and use demisto.results
        """
        mocker.patch.object(demisto, "command", return_value="apivoid-dns-lookup")
        mocker.patch.object(demisto, "args", return_value={"host": "example.com", "type": "A"})
        mock_results = mocker.patch.object(demisto, "results")
        mock_dns_cmd = mocker.patch("APIVoid.dns_lookup_command", return_value=[{"test": "data"}])

        main()

        assert mock_dns_cmd.called
        mock_results.assert_called_once()

    def test_main_unknown_command(self, mock_demisto, mocker):
        """
        Test main function with unknown command

        Given: Unknown command
        When: main is called
        Then: Should raise NotImplementedError
        """
        mocker.patch.object(demisto, "command", return_value="unknown-command")
        mock_return_error = mocker.patch("APIVoid.return_error")

        main()

        # Verify return_error was called with NotImplementedError message
        assert mock_return_error.called
        error_msg = mock_return_error.call_args[0][0]
        assert "not implemented" in error_msg.lower()

    def test_main_exception_handling(self, mock_demisto, mocker):
        """
        Test main function exception handling

        Given: Command that raises exception
        When: main is called
        Then: Should call return_error
        """
        mocker.patch.object(demisto, "command", return_value="ip")
        mocker.patch.object(demisto, "args", return_value={"ip": "8.8.8.8"})
        mocker.patch("APIVoid.ip_reputation_command", side_effect=Exception("Test error"))
        mock_return_error = mocker.patch("APIVoid.return_error")

        main()

        assert mock_return_error.called
        error_msg = mock_return_error.call_args[0][0]
        assert "Test error" in error_msg

    def test_main_params_called_once(self, mock_demisto, mocker):
        """
        Test that demisto.params() is called only once

        Given: Any command
        When: main is called
        Then: demisto.params() should be called exactly once
        """
        mocker.patch.object(demisto, "command", return_value="test-module")
        mock_params = mocker.patch.object(
            demisto,
            "params",
            return_value={
                "credentials": {"password": "test-key"},
                "insecure": False,
                "proxy": False,
                "integrationReliability": "C - Fairly reliable",
                "good": "10",
                "suspicious": "30",
                "bad": "60",
            },
        )
        mocker.patch("APIVoid.test_module", return_value="ok")
        mocker.patch("APIVoid.return_results")

        main()

        # Verify params was called exactly once
        assert mock_params.call_count == 1


# ============================================================================
# TEST EDGE CASES AND ERROR SCENARIOS
# ============================================================================


class TestEdgeCases:
    """Test edge cases and error scenarios"""

    def test_empty_blacklist_response(self, client, mocker):
        """
        Test handling of empty blacklist data

        Given: API response with empty blacklists
        When: ip_reputation_command is called
        Then: Should handle gracefully with NONE score
        """
        empty_response = {"ip": "1.2.3.4", "blacklists": {}, "information": {}, "risk_score": {}}
        mocker.patch.object(client, "api_request", return_value=empty_response)

        args = {"ip": "1.2.3.4"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        result = ip_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

        assert result.indicator.dbot_score.score == Common.DBotScore.NONE

    def test_missing_optional_fields(self, client, mocker):
        """
        Test handling of missing optional fields

        Given: API response with minimal data
        When: Commands are called
        Then: Should not raise exceptions
        """
        minimal_response = {"ip": "1.2.3.4", "blacklists": {"engines_count": 10, "detections": 0}, "information": {}}
        mocker.patch.object(client, "api_request", return_value=minimal_response)

        args = {"ip": "1.2.3.4"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        # Should not raise exception
        result = ip_reputation_command(client, args, False, thresholds, "C - Fairly reliable")
        assert isinstance(result, CommandResults)

    def test_special_characters_in_url(self, client, mocker):
        """
        Test URL with special characters

        Given: URL with special characters
        When: screenshot_command is called
        Then: Should handle filename creation properly
        """
        mocker.patch.object(client, "api_request", return_value=MOCK_SCREENSHOT_RESPONSE)
        mock_file_result = mocker.patch("APIVoid.fileResult", return_value={"Type": 3})

        args = {"url": "https://example.com/path?param=value&other=123"}

        screenshot_command(client, args)

        # Verify fileResult was called with sanitized filename
        assert mock_file_result.called
        filename = mock_file_result.call_args[0][0]
        assert ".png" in filename
