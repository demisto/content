"""
Unit tests for APIVoid integration
Tests all commands, helper functions, and error handling scenarios with strict HTTP request validation
"""

import pytest
import json
import os
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
# HELPER FUNCTION TO LOAD MOCK DATA FROM FILES
# ============================================================================


def load_mock_response(filename: str) -> dict:
    """
    Load mock response data from JSON file in test_data directory

    Args:
        filename: Name of the JSON file (e.g., 'ip-reputation-response.json')

    Returns:
        Dictionary containing the mock response data
    """
    test_data_dir = os.path.join(os.path.dirname(__file__), "test_data")
    file_path = os.path.join(test_data_dir, filename)

    with open(file_path) as f:
        return json.load(f)


# ============================================================================
# MOCK DATA - V2 API Responses (loaded from files)
# ============================================================================

MOCK_IP_RESPONSE = load_mock_response("ip-reputation-response.json")
MOCK_DOMAIN_RESPONSE = load_mock_response("domain-reputation-response.json")
MOCK_URL_RESPONSE = load_mock_response("url-reputation-response.json")
MOCK_DNS_RESPONSE = load_mock_response("dns-lookup-response.json")
MOCK_SSL_RESPONSE = load_mock_response("ssl-info-response.json")
MOCK_EMAIL_RESPONSE = load_mock_response("email-verify-response.json")
MOCK_PARKED_DOMAIN_RESPONSE = load_mock_response("parked-domain-response.json")
MOCK_DOMAIN_AGE_RESPONSE = load_mock_response("domain-age-response.json")
MOCK_SCREENSHOT_RESPONSE = load_mock_response("screenshot-response.json")
MOCK_PDF_RESPONSE = load_mock_response("pdf-response.json")
MOCK_SITE_TRUST_RESPONSE = load_mock_response("site-trust-response.json")
MOCK_ERROR_RESPONSE = load_mock_response("error-response.json")


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
# TEST CLIENT CLASS WITH STRICT REQUEST VALIDATION
# ============================================================================


class TestClientWithStrictValidation:
    """Test Client class with strict HTTP request validation"""

    def test_client_initialization(self, client):
        """
        Test client initialization

        Given: Valid API credentials
        When: Client is initialized
        Then: Headers should contain API key and Content-Type
        """
        assert client._headers["X-API-Key"] == "test-api-key"
        assert client._headers["Content-Type"] == "application/json"
        assert client._base_url == "https://api.apivoid.com"

    def test_api_request_validates_method(self, client, mocker):
        """
        Test API request uses POST method

        Given: A client instance
        When: api_request is called
        Then: Should use POST method
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value={"result": "success"})

        client.api_request("/v2/test", {"param": "value"})

        # Validate exact method
        assert mock_http.call_args[1]["method"] == "POST"

    def test_api_request_validates_url_suffix(self, client, mocker):
        """
        Test API request uses correct URL suffix

        Given: A client instance
        When: api_request is called with endpoint
        Then: Should use exact URL suffix
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value={"result": "success"})

        client.api_request("/v2/ip-reputation", {"ip": "8.8.8.8"})

        # Validate exact URL suffix
        assert mock_http.call_args[1]["url_suffix"] == "/v2/ip-reputation"

    def test_api_request_validates_json_data(self, client, mocker):
        """
        Test API request sends correct JSON data

        Given: A client instance
        When: api_request is called with data
        Then: Should send exact JSON data
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value={"result": "success"})

        test_data = {"ip": "8.8.8.8"}
        client.api_request("/v2/ip-reputation", test_data)

        # Validate exact JSON data
        assert mock_http.call_args[1]["json_data"] == test_data

    def test_api_request_validates_headers(self, client, mocker):
        """
        Test API request includes correct headers

        Given: A client instance
        When: api_request is called
        Then: Should include X-API-Key and Content-Type headers
        """
        mocker.patch.object(client, "_http_request", return_value={"result": "success"})

        client.api_request("/v2/test", {"param": "value"})

        # Validate headers are set in client
        assert client._headers["X-API-Key"] == "test-api-key"
        assert client._headers["Content-Type"] == "application/json"


# ============================================================================
# TEST IP REPUTATION WITH STRICT REQUEST VALIDATION
# ============================================================================


class TestIpReputationWithStrictValidation:
    """Test IP reputation command with strict HTTP request validation"""

    def test_ip_reputation_request_validation(self, client, mocker):
        """
        Test IP reputation sends exact request format

        Given: Valid IP address
        When: ip_reputation_command is called
        Then: Should send POST to /v2/ip-reputation with exact JSON body {"ip": "value"}
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_IP_RESPONSE)

        args = {"ip": "8.8.8.8"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        ip_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

        # Strict validation of request
        mock_http.assert_called_once()
        call_kwargs = mock_http.call_args[1]
        assert call_kwargs["method"] == "POST"
        assert call_kwargs["url_suffix"] == "/v2/ip-reputation"
        assert call_kwargs["json_data"] == {"ip": "8.8.8.8"}

    def test_ip_reputation_different_ip_addresses(self, client, mocker):
        """
        Test IP reputation with different IP addresses

        Given: Different IP addresses
        When: ip_reputation_command is called
        Then: Should send correct IP in request body
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_IP_RESPONSE)
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        test_ips = ["8.8.8.8", "1.1.1.1", "192.168.1.1", "10.0.0.1"]

        for test_ip in test_ips:
            mock_http.reset_mock()
            args = {"ip": test_ip}
            ip_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

            # Validate exact IP in request
            assert mock_http.call_args[1]["json_data"]["ip"] == test_ip

    def test_ip_reputation_success(self, client, mocker):
        """
        Test successful IP reputation check

        Given: Valid IP address
        When: ip_reputation_command is called
        Then: Should return CommandResults with IP indicator
        """
        mocker.patch.object(client, "_http_request", return_value=MOCK_IP_RESPONSE)

        args = {"ip": "8.8.8.8"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        result = ip_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

        assert isinstance(result, CommandResults)
        assert result.indicator.ip == "8.8.8.8"
        assert result.outputs_prefix == "APIVoid.IP"
        assert result.outputs_key_field == "ip"


# ============================================================================
# TEST DOMAIN REPUTATION WITH STRICT REQUEST VALIDATION
# ============================================================================


class TestDomainReputationWithStrictValidation:
    """Test domain reputation command with strict HTTP request validation"""

    def test_domain_reputation_request_validation(self, client, mocker):
        """
        Test domain reputation sends exact request format

        Given: Valid domain
        When: domain_reputation_command is called
        Then: Should send POST to /v2/domain-reputation with exact JSON body {"host": "value"}
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_DOMAIN_RESPONSE)

        args = {"domain": "google.com"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        domain_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

        # Strict validation of request
        mock_http.assert_called_once()
        call_kwargs = mock_http.call_args[1]
        assert call_kwargs["method"] == "POST"
        assert call_kwargs["url_suffix"] == "/v2/domain-reputation"
        assert call_kwargs["json_data"] == {"host": "google.com"}

    def test_domain_reputation_different_domains(self, client, mocker):
        """
        Test domain reputation with different domains

        Given: Different domains
        When: domain_reputation_command is called
        Then: Should send correct domain in request body
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_DOMAIN_RESPONSE)
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        test_domains = ["example.com", "google.com", "test.org", "subdomain.example.com"]

        for test_domain in test_domains:
            mock_http.reset_mock()
            args = {"domain": test_domain}
            domain_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

            # Validate exact domain in request
            assert mock_http.call_args[1]["json_data"]["host"] == test_domain


# ============================================================================
# TEST URL REPUTATION WITH STRICT REQUEST VALIDATION
# ============================================================================


class TestUrlReputationWithStrictValidation:
    """Test URL reputation command with strict HTTP request validation"""

    def test_url_reputation_request_validation(self, client, mocker):
        """
        Test URL reputation sends exact request format

        Given: Valid URL
        When: url_reputation_command is called
        Then: Should send POST to /v2/url-reputation with exact JSON body {"url": "value"}
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_URL_RESPONSE)

        args = {"url": "https://example.com"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        url_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

        # Strict validation of request
        mock_http.assert_called_once()
        call_kwargs = mock_http.call_args[1]
        assert call_kwargs["method"] == "POST"
        assert call_kwargs["url_suffix"] == "/v2/url-reputation"
        assert call_kwargs["json_data"] == {"url": "https://example.com"}

    def test_url_reputation_different_urls(self, client, mocker):
        """
        Test URL reputation with different URLs

        Given: Different URLs
        When: url_reputation_command is called
        Then: Should send correct URL in request body
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_URL_RESPONSE)
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        test_urls = [
            "https://example.com",
            "http://test.org/path",
            "https://www.disney.com?param=value",
        ]

        for test_url in test_urls:
            mock_http.reset_mock()
            args = {"url": test_url}
            url_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

            # Validate exact URL in request
            assert mock_http.call_args[1]["json_data"]["url"] == test_url


# ============================================================================
# TEST DNS LOOKUP WITH STRICT REQUEST VALIDATION
# ============================================================================


class TestDnsLookupWithStrictValidation:
    """Test DNS lookup command with strict HTTP request validation"""

    def test_dns_lookup_request_validation(self, client, mocker):
        """
        Test DNS lookup sends exact request format

        Given: Valid host and DNS type
        When: dns_lookup_command is called
        Then: Should send POST to /v2/dns-lookup with exact JSON body {"host": "value", "dns_types": "type"}
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_DNS_RESPONSE)

        args = {"host": "example.com", "type": "A"}

        dns_lookup_command(client, args)

        # Strict validation of request
        mock_http.assert_called_once()
        call_kwargs = mock_http.call_args[1]
        assert call_kwargs["method"] == "POST"
        assert call_kwargs["url_suffix"] == "/v2/dns-lookup"
        assert call_kwargs["json_data"] == {"host": "example.com", "dns_types": "A"}

    def test_dns_lookup_default_type(self, client, mocker):
        """
        Test DNS lookup with default type

        Given: Host without type specified
        When: dns_lookup_command is called
        Then: Should default to A record in request
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_DNS_RESPONSE)

        args = {"host": "example.com"}

        dns_lookup_command(client, args)

        # Validate default type is A
        assert mock_http.call_args[1]["json_data"]["dns_types"] == "A"

    def test_dns_lookup_different_types(self, client, mocker):
        """
        Test DNS lookup with different DNS types

        Given: Different DNS types
        When: dns_lookup_command is called
        Then: Should send correct dns_types in request
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_DNS_RESPONSE)

        test_types = ["A", "AAAA", "MX", "NS", "TXT", "A,AAAA,MX,NS,TXT,SOA,DMARC,CAA,SRV"]

        for dns_type in test_types:
            mock_http.reset_mock()
            args = {"host": "example.com", "type": dns_type}
            dns_lookup_command(client, args)

            # Validate exact dns_types in request
            assert mock_http.call_args[1]["json_data"]["dns_types"] == dns_type


# ============================================================================
# TEST SSL INFO WITH STRICT REQUEST VALIDATION
# ============================================================================


class TestSslInfoWithStrictValidation:
    """Test SSL info command with strict HTTP request validation"""

    def test_ssl_info_request_validation(self, client, mocker):
        """
        Test SSL info sends exact request format

        Given: Valid host
        When: ssl_info_command is called
        Then: Should send POST to /v2/ssl-info with exact JSON body {"host": "value"}
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_SSL_RESPONSE)

        args = {"host": "paypal.com"}

        ssl_info_command(client, args)

        # Strict validation of request
        mock_http.assert_called_once()
        call_kwargs = mock_http.call_args[1]
        assert call_kwargs["method"] == "POST"
        assert call_kwargs["url_suffix"] == "/v2/ssl-info"
        assert call_kwargs["json_data"] == {"host": "paypal.com"}

    def test_ssl_info_different_hosts(self, client, mocker):
        """
        Test SSL info with different hosts

        Given: Different hosts
        When: ssl_info_command is called
        Then: Should send correct host in request body
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_SSL_RESPONSE)

        test_hosts = ["example.com", "google.com", "github.com"]

        for test_host in test_hosts:
            mock_http.reset_mock()
            args = {"host": test_host}
            ssl_info_command(client, args)

            # Validate exact host in request
            assert mock_http.call_args[1]["json_data"]["host"] == test_host


# ============================================================================
# TEST EMAIL VERIFY WITH STRICT REQUEST VALIDATION
# ============================================================================


class TestEmailVerifyWithStrictValidation:
    """Test email verify command with strict HTTP request validation"""

    def test_email_verify_request_validation(self, client, mocker):
        """
        Test email verify sends exact request format

        Given: Valid email address
        When: email_verify_command is called
        Then: Should send POST to /v2/email-verify with exact JSON body {"email": "value"}
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_EMAIL_RESPONSE)

        args = {"email": "test@test.com"}

        email_verify_command(client, args)

        # Strict validation of request
        mock_http.assert_called_once()
        call_kwargs = mock_http.call_args[1]
        assert call_kwargs["method"] == "POST"
        assert call_kwargs["url_suffix"] == "/v2/email-verify"
        assert call_kwargs["json_data"] == {"email": "test@test.com"}

    def test_email_verify_different_emails(self, client, mocker):
        """
        Test email verify with different email addresses

        Given: Different email addresses
        When: email_verify_command is called
        Then: Should send correct email in request body
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_EMAIL_RESPONSE)

        test_emails = ["test@example.com", "user@domain.org", "admin@company.co.uk"]

        for test_email in test_emails:
            mock_http.reset_mock()
            args = {"email": test_email}
            email_verify_command(client, args)

            # Validate exact email in request
            assert mock_http.call_args[1]["json_data"]["email"] == test_email


# ============================================================================
# TEST PARKED DOMAIN WITH STRICT REQUEST VALIDATION
# ============================================================================


class TestParkedDomainWithStrictValidation:
    """Test parked domain command with strict HTTP request validation"""

    def test_parked_domain_request_validation(self, client, mocker):
        """
        Test parked domain sends exact request format

        Given: Valid domain
        When: parked_domain_command is called
        Then: Should send POST to /v2/parked-domain with exact JSON body {"domain": "value"}
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_PARKED_DOMAIN_RESPONSE)

        args = {"domain": "example.com"}

        parked_domain_command(client, args)

        # Strict validation of request
        mock_http.assert_called_once()
        call_kwargs = mock_http.call_args[1]
        assert call_kwargs["method"] == "POST"
        assert call_kwargs["url_suffix"] == "/v2/parked-domain"
        assert call_kwargs["json_data"] == {"domain": "example.com"}

    def test_parked_domain_different_domains(self, client, mocker):
        """
        Test parked domain with different domains

        Given: Different domains
        When: parked_domain_command is called
        Then: Should send correct domain in request body
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_PARKED_DOMAIN_RESPONSE)

        test_domains = ["test.com", "example.org", "parked.net"]

        for test_domain in test_domains:
            mock_http.reset_mock()
            args = {"domain": test_domain}
            parked_domain_command(client, args)

            # Validate exact domain in request
            assert mock_http.call_args[1]["json_data"]["domain"] == test_domain


# ============================================================================
# TEST DOMAIN AGE WITH STRICT REQUEST VALIDATION
# ============================================================================


class TestDomainAgeWithStrictValidation:
    """Test domain age command with strict HTTP request validation"""

    def test_domain_age_request_validation(self, client, mocker):
        """
        Test domain age sends exact request format

        Given: Valid domain
        When: domain_age_command is called
        Then: Should send POST to /v2/domain-age with exact JSON body {"domain": "value"}
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_DOMAIN_AGE_RESPONSE)

        args = {"domain": "example.com"}

        domain_age_command(client, args)

        # Strict validation of request
        mock_http.assert_called_once()
        call_kwargs = mock_http.call_args[1]
        assert call_kwargs["method"] == "POST"
        assert call_kwargs["url_suffix"] == "/v2/domain-age"
        assert call_kwargs["json_data"] == {"domain": "example.com"}

    def test_domain_age_different_domains(self, client, mocker):
        """
        Test domain age with different domains

        Given: Different domains
        When: domain_age_command is called
        Then: Should send correct domain in request body
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_DOMAIN_AGE_RESPONSE)

        test_domains = ["google.com", "amazon.com", "old-domain.org"]

        for test_domain in test_domains:
            mock_http.reset_mock()
            args = {"domain": test_domain}
            domain_age_command(client, args)

            # Validate exact domain in request
            assert mock_http.call_args[1]["json_data"]["domain"] == test_domain


# ============================================================================
# TEST SCREENSHOT WITH STRICT REQUEST VALIDATION
# ============================================================================


class TestScreenshotWithStrictValidation:
    """Test screenshot command with strict HTTP request validation"""

    def test_screenshot_request_validation(self, client, mocker):
        """
        Test screenshot sends exact request format

        Given: Valid URL
        When: screenshot_command is called
        Then: Should send POST to /v2/screenshot with exact JSON body {"url": "value"}
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_SCREENSHOT_RESPONSE)
        mocker.patch("APIVoid.fileResult", return_value={"Type": 3, "File": "test.png"})

        args = {"url": "https://example.com"}

        screenshot_command(client, args)

        # Strict validation of request
        mock_http.assert_called_once()
        call_kwargs = mock_http.call_args[1]
        assert call_kwargs["method"] == "POST"
        assert call_kwargs["url_suffix"] == "/v2/screenshot"
        assert call_kwargs["json_data"] == {"url": "https://example.com"}


# ============================================================================
# TEST URL TO PDF WITH STRICT REQUEST VALIDATION
# ============================================================================


class TestUrlToPdfWithStrictValidation:
    """Test URL to PDF command with strict HTTP request validation"""

    def test_url_to_pdf_request_validation(self, client, mocker):
        """
        Test URL to PDF sends exact request format

        Given: Valid URL
        When: url_to_pdf_command is called
        Then: Should send POST to /v2/url-to-pdf with exact JSON body {"url": "value"}
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_PDF_RESPONSE)
        mocker.patch("APIVoid.fileResult", return_value={"Type": 3, "File": "test.pdf"})

        args = {"url": "https://example.com"}

        url_to_pdf_command(client, args)

        # Strict validation of request
        mock_http.assert_called_once()
        call_kwargs = mock_http.call_args[1]
        assert call_kwargs["method"] == "POST"
        assert call_kwargs["url_suffix"] == "/v2/url-to-pdf"
        assert call_kwargs["json_data"] == {"url": "https://example.com"}


# ============================================================================
# TEST SITE TRUSTWORTHINESS WITH STRICT REQUEST VALIDATION
# ============================================================================


class TestSiteTrustworthinessWithStrictValidation:
    """Test site trustworthiness command with strict HTTP request validation"""

    def test_site_trust_request_validation(self, client, mocker):
        """
        Test site trustworthiness sends exact request format

        Given: Valid host
        When: site_trustworthiness_command is called
        Then: Should send POST to /v2/site-trust with exact JSON body {"host": "value"}
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_SITE_TRUST_RESPONSE)

        args = {"host": "amazon.com"}

        site_trustworthiness_command(client, args)

        # Strict validation of request
        mock_http.assert_called_once()
        call_kwargs = mock_http.call_args[1]
        assert call_kwargs["method"] == "POST"
        assert call_kwargs["url_suffix"] == "/v2/site-trust"
        assert call_kwargs["json_data"] == {"host": "amazon.com"}

    def test_site_trust_different_hosts(self, client, mocker):
        """
        Test site trustworthiness with different hosts

        Given: Different hosts
        When: site_trustworthiness_command is called
        Then: Should send correct host in request body
        """
        mock_http = mocker.patch.object(client, "_http_request", return_value=MOCK_SITE_TRUST_RESPONSE)

        test_hosts = ["google.com", "microsoft.com", "apple.com"]

        for test_host in test_hosts:
            mock_http.reset_mock()
            args = {"host": test_host}
            site_trustworthiness_command(client, args)

            # Validate exact host in request
            assert mock_http.call_args[1]["json_data"]["host"] == test_host


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


# ============================================================================
# TEST MALICIOUS DESCRIPTION IN DBOT SCORE
# ============================================================================


class TestMaliciousDescription:
    """Test malicious_description in DBotScore when score is BAD"""

    def test_ip_reputation_bad_score_has_malicious_description(self, client, mocker):
        """
        Test IP reputation with BAD score includes malicious_description

        Given: IP with high detection rate (80%)
        When: ip_reputation_command is called with bad threshold 60%
        Then: DBotScore should have malicious_description with detection rate
        """
        # Create mock response with high detection rate
        mock_response = MOCK_IP_RESPONSE.copy()
        mock_response["blacklists"]["detections"] = 8
        mock_response["blacklists"]["engines_count"] = 10

        mocker.patch.object(client, "_http_request", return_value=mock_response)

        args = {"ip": "8.8.8.8"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        result = ip_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

        # Verify DBotScore has malicious_description
        assert result.indicator.dbot_score.score == Common.DBotScore.BAD
        assert result.indicator.dbot_score.malicious_description == "Detection rate of 8/10"

    def test_domain_reputation_bad_score_has_malicious_description(self, client, mocker):
        """
        Test domain reputation with BAD score includes malicious_description

        Given: Domain with high detection rate (70%)
        When: domain_reputation_command is called with bad threshold 60%
        Then: DBotScore should have malicious_description with detection rate
        """
        # Create mock response with high detection rate
        mock_response = MOCK_DOMAIN_RESPONSE.copy()
        mock_response["blacklists"]["detections"] = 7
        mock_response["blacklists"]["engines_count"] = 10

        mocker.patch.object(client, "_http_request", return_value=mock_response)

        args = {"domain": "malicious.com"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        result = domain_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

        # Verify DBotScore has malicious_description
        assert result.indicator.dbot_score.score == Common.DBotScore.BAD
        assert result.indicator.dbot_score.malicious_description == "Detection rate of 7/10"

    def test_url_reputation_bad_score_has_malicious_description(self, client, mocker):
        """
        Test URL reputation with BAD score includes malicious_description

        Given: URL with high detection rate (75%)
        When: url_reputation_command is called with bad threshold 60%
        Then: DBotScore should have malicious_description with detection rate
        """
        # Create mock response with high detection rate
        mock_response = MOCK_URL_RESPONSE.copy()
        mock_response["domain_blacklist"]["detections"] = 15
        mock_response["domain_blacklist"]["engines_count"] = 20

        mocker.patch.object(client, "_http_request", return_value=mock_response)

        args = {"url": "https://example.com"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        result = url_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

        # Verify DBotScore has malicious_description
        assert result.indicator.dbot_score.score == Common.DBotScore.BAD
        assert result.indicator.dbot_score.malicious_description == "Detection rate of 15/20"

    def test_ip_reputation_good_score_has_malicious_description(self, client, mocker):
        """
        Test IP reputation with GOOD score still includes malicious_description

        Given: IP with low detection rate (5%)
        When: ip_reputation_command is called
        Then: DBotScore should have malicious_description even when score is GOOD
        """
        # Create mock response with low detection rate
        mock_response = MOCK_IP_RESPONSE.copy()
        mock_response["blacklists"]["detections"] = 1
        mock_response["blacklists"]["engines_count"] = 20

        mocker.patch.object(client, "_http_request", return_value=mock_response)

        args = {"ip": "8.8.8.8"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        result = ip_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

        # Verify DBotScore has malicious_description even for GOOD score
        assert result.indicator.dbot_score.score == Common.DBotScore.GOOD
        assert result.indicator.dbot_score.malicious_description == "Detection rate of 1/20"


# ============================================================================
# TEST ERROR HANDLING
# ============================================================================


class TestErrorHandling:
    """Test error handling scenarios"""

    def test_ip_reputation_api_error(self, client, mocker):
        """
        Test IP reputation with API error

        Given: API returns error response
        When: ip_reputation_command is called
        Then: Should raise DemistoException
        """
        mocker.patch.object(client, "_http_request", return_value=MOCK_ERROR_RESPONSE)

        args = {"ip": "8.8.8.8"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        with pytest.raises(DemistoException, match="Error checking IP"):
            ip_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

    def test_domain_reputation_api_error(self, client, mocker):
        """
        Test domain reputation with API error

        Given: API returns error response
        When: domain_reputation_command is called
        Then: Should raise DemistoException
        """
        mocker.patch.object(client, "_http_request", return_value=MOCK_ERROR_RESPONSE)

        args = {"domain": "example.com"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        with pytest.raises(DemistoException, match="Error checking domain"):
            domain_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

    def test_url_reputation_api_error(self, client, mocker):
        """
        Test URL reputation with API error

        Given: API returns error response
        When: url_reputation_command is called
        Then: Should raise DemistoException
        """
        mocker.patch.object(client, "_http_request", return_value=MOCK_ERROR_RESPONSE)

        args = {"url": "https://example.com"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        with pytest.raises(DemistoException, match="Error checking URL"):
            url_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

    def test_dns_lookup_api_error(self, client, mocker):
        """
        Test DNS lookup with API error

        Given: API returns error response
        When: dns_lookup_command is called
        Then: Should raise DemistoException
        """
        mocker.patch.object(client, "_http_request", return_value=MOCK_ERROR_RESPONSE)

        args = {"host": "example.com", "type": "A"}

        with pytest.raises(DemistoException, match="Error looking up DNS"):
            dns_lookup_command(client, args)

    def test_screenshot_no_data(self, client, mocker):
        """
        Test screenshot with no data returned

        Given: API returns response without base64_file
        When: screenshot_command is called
        Then: Should raise DemistoException
        """
        mocker.patch.object(client, "_http_request", return_value={})

        args = {"url": "https://example.com"}

        with pytest.raises(DemistoException, match="No screenshot data returned"):
            screenshot_command(client, args)

    def test_url_to_pdf_no_data(self, client, mocker):
        """
        Test URL to PDF with no data returned

        Given: API returns response without base64_file
        When: url_to_pdf_command is called
        Then: Should raise DemistoException
        """
        mocker.patch.object(client, "_http_request", return_value={})

        args = {"url": "https://example.com"}

        with pytest.raises(DemistoException, match="No PDF data returned"):
            url_to_pdf_command(client, args)


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
        mocker.patch.object(client, "_http_request", return_value=MOCK_IP_RESPONSE)

        result = module_test(client)

        assert result == "ok"

    def test_module_api_error(self, client, mocker):
        """
        Test test-module with API error

        Given: API returns error
        When: test_module is called
        Then: Should return error message
        """
        mocker.patch.object(client, "_http_request", return_value=MOCK_ERROR_RESPONSE)

        result = module_test(client)

        assert "Test Failed" in result

    def test_module_exception(self, client, mocker):
        """
        Test test-module with exception

        Given: API request raises exception
        When: test_module is called
        Then: Should return error message
        """
        mocker.patch.object(client, "_http_request", side_effect=Exception("Connection error"))

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
        Then: Should call domain_reputation_command with reputation_only=True
        """
        mocker.patch.object(demisto, "command", return_value="domain")
        mocker.patch.object(demisto, "args", return_value={"domain": "example.com"})
        mocker.patch("APIVoid.return_results")
        mock_domain_cmd = mocker.patch("APIVoid.domain_reputation_command", return_value=CommandResults(readable_output="test"))

        main()

        # Verify reputation_only was True
        assert mock_domain_cmd.call_args[0][2] is True

    def test_main_apivoid_domain_command(self, mock_demisto, mocker):
        """
        Test main function with apivoid-domain command

        Given: apivoid-domain command
        When: main is called
        Then: Should call domain_reputation_command with reputation_only=False
        """
        mocker.patch.object(demisto, "command", return_value="apivoid-domain")
        mocker.patch.object(demisto, "args", return_value={"domain": "example.com"})
        mocker.patch("APIVoid.return_results")
        mock_domain_cmd = mocker.patch("APIVoid.domain_reputation_command", return_value=CommandResults(readable_output="test"))

        main()

        # Verify reputation_only was False
        assert mock_domain_cmd.call_args[0][2] is False

    def test_main_url_command(self, mock_demisto, mocker):
        """
        Test main function with url command

        Given: url command
        When: main is called
        Then: Should call url_reputation_command with reputation_only=True
        """
        mocker.patch.object(demisto, "command", return_value="url")
        mocker.patch.object(demisto, "args", return_value={"url": "https://example.com"})
        mocker.patch("APIVoid.return_results")
        mock_url_cmd = mocker.patch("APIVoid.url_reputation_command", return_value=CommandResults(readable_output="test"))

        main()

        # Verify reputation_only was True
        assert mock_url_cmd.call_args[0][2] is True

    def test_main_apivoid_url_command(self, mock_demisto, mocker):
        """
        Test main function with apivoid-url command

        Given: apivoid-url command
        When: main is called
        Then: Should call url_reputation_command with reputation_only=False
        """
        mocker.patch.object(demisto, "command", return_value="apivoid-url")
        mocker.patch.object(demisto, "args", return_value={"url": "https://example.com"})
        mocker.patch("APIVoid.return_results")
        mock_url_cmd = mocker.patch("APIVoid.url_reputation_command", return_value=CommandResults(readable_output="test"))

        main()

        # Verify reputation_only was False
        assert mock_url_cmd.call_args[0][2] is False

    def test_main_dns_lookup_command(self, mock_demisto, mocker):
        """
        Test main function with apivoid-dns-lookup command

        Given: apivoid-dns-lookup command
        When: main is called
        Then: Should call dns_lookup_command
        """
        mocker.patch.object(demisto, "command", return_value="apivoid-dns-lookup")
        mocker.patch.object(demisto, "args", return_value={"host": "example.com"})
        mocker.patch("APIVoid.return_results")
        mock_dns_cmd = mocker.patch("APIVoid.dns_lookup_command", return_value=CommandResults(readable_output="test"))

        main()

        mock_dns_cmd.assert_called_once()

    def test_main_ssl_info_command(self, mock_demisto, mocker):
        """
        Test main function with apivoid-ssl-info command

        Given: apivoid-ssl-info command
        When: main is called
        Then: Should call ssl_info_command
        """
        mocker.patch.object(demisto, "command", return_value="apivoid-ssl-info")
        mocker.patch.object(demisto, "args", return_value={"host": "example.com"})
        mocker.patch("APIVoid.return_results")
        mock_ssl_cmd = mocker.patch("APIVoid.ssl_info_command", return_value=CommandResults(readable_output="test"))

        main()

        mock_ssl_cmd.assert_called_once()

    def test_main_email_verify_command(self, mock_demisto, mocker):
        """
        Test main function with apivoid-email-verify command

        Given: apivoid-email-verify command
        When: main is called
        Then: Should call email_verify_command
        """
        mocker.patch.object(demisto, "command", return_value="apivoid-email-verify")
        mocker.patch.object(demisto, "args", return_value={"email": "test@example.com"})
        mocker.patch("APIVoid.return_results")
        mock_email_cmd = mocker.patch("APIVoid.email_verify_command", return_value=CommandResults(readable_output="test"))

        main()

        mock_email_cmd.assert_called_once()

    def test_main_parked_domain_command(self, mock_demisto, mocker):
        """
        Test main function with apivoid-parked-domain command

        Given: apivoid-parked-domain command
        When: main is called
        Then: Should call parked_domain_command
        """
        mocker.patch.object(demisto, "command", return_value="apivoid-parked-domain")
        mocker.patch.object(demisto, "args", return_value={"domain": "example.com"})
        mocker.patch("APIVoid.return_results")
        mock_parked_cmd = mocker.patch("APIVoid.parked_domain_command", return_value=CommandResults(readable_output="test"))

        main()

        mock_parked_cmd.assert_called_once()

    def test_main_domain_age_command(self, mock_demisto, mocker):
        """
        Test main function with apivoid-domain-age command

        Given: apivoid-domain-age command
        When: main is called
        Then: Should call domain_age_command
        """
        mocker.patch.object(demisto, "command", return_value="apivoid-domain-age")
        mocker.patch.object(demisto, "args", return_value={"domain": "example.com"})
        mocker.patch("APIVoid.return_results")
        mock_age_cmd = mocker.patch("APIVoid.domain_age_command", return_value=CommandResults(readable_output="test"))

        main()

        mock_age_cmd.assert_called_once()

    def test_main_screenshot_command(self, mock_demisto, mocker):
        """
        Test main function with apivoid-url-to-image command

        Given: apivoid-url-to-image command
        When: main is called
        Then: Should call screenshot_command
        """
        mocker.patch.object(demisto, "command", return_value="apivoid-url-to-image")
        mocker.patch.object(demisto, "args", return_value={"url": "https://example.com"})
        mocker.patch("APIVoid.return_results")
        mock_screenshot_cmd = mocker.patch("APIVoid.screenshot_command", return_value={"Type": 3, "File": "test.png"})

        main()

        mock_screenshot_cmd.assert_called_once()

    def test_main_url_to_pdf_command(self, mock_demisto, mocker):
        """
        Test main function with apivoid-url-to-pdf command

        Given: apivoid-url-to-pdf command
        When: main is called
        Then: Should call url_to_pdf_command
        """
        mocker.patch.object(demisto, "command", return_value="apivoid-url-to-pdf")
        mocker.patch.object(demisto, "args", return_value={"url": "https://example.com"})
        mocker.patch("APIVoid.return_results")
        mock_pdf_cmd = mocker.patch("APIVoid.url_to_pdf_command", return_value={"Type": 3, "File": "test.pdf"})

        main()

        mock_pdf_cmd.assert_called_once()

    def test_main_site_trustworthiness_command(self, mock_demisto, mocker):
        """
        Test main function with apivoid-site-trustworthiness command

        Given: apivoid-site-trustworthiness command
        When: main is called
        Then: Should call site_trustworthiness_command
        """
        mocker.patch.object(demisto, "command", return_value="apivoid-site-trustworthiness")
        mocker.patch.object(demisto, "args", return_value={"host": "example.com"})
        mocker.patch("APIVoid.return_results")
        mock_trust_cmd = mocker.patch("APIVoid.site_trustworthiness_command", return_value=CommandResults(readable_output="test"))

        main()

        mock_trust_cmd.assert_called_once()

    def test_main_deprecated_command(self, mock_demisto, mocker):
        """
        Test main function with deprecated command

        Given: apivoid-threatlog command (deprecated)
        When: main is called
        Then: Should raise DemistoException
        """
        mocker.patch.object(demisto, "command", return_value="apivoid-threatlog")
        mocker.patch.object(demisto, "args", return_value={})
        mock_return_error = mocker.patch("APIVoid.return_error")

        main()

        mock_return_error.assert_called_once()
        assert "is not supported in API V2" in mock_return_error.call_args[0][0]

    def test_main_not_implemented_command(self, mock_demisto, mocker):
        """
        Test main function with not implemented command

        Given: unknown-command
        When: main is called
        Then: Should raise NotImplementedError
        """
        mocker.patch.object(demisto, "command", return_value="unknown-command")
        mocker.patch.object(demisto, "args", return_value={})
        mock_return_error = mocker.patch("APIVoid.return_error")

        main()

        mock_return_error.assert_called_once()
        assert "not implemented" in mock_return_error.call_args[0][0].lower()


# ============================================================================
# TEST EXCEPTION HANDLING IN COMMANDS
# ============================================================================


class TestExceptionHandling:
    """Test exception handling in all commands"""

    def test_ip_reputation_http_exception(self, client, mocker):
        """
        Test IP reputation with HTTP exception

        Given: HTTP request raises exception
        When: ip_reputation_command is called
        Then: Should raise DemistoException with proper message
        """
        mocker.patch.object(client, "_http_request", side_effect=Exception("Connection timeout"))

        args = {"ip": "8.8.8.8"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        with pytest.raises(DemistoException, match="Failed to get IP reputation"):
            ip_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

    def test_domain_reputation_http_exception(self, client, mocker):
        """
        Test domain reputation with HTTP exception

        Given: HTTP request raises exception
        When: domain_reputation_command is called
        Then: Should raise DemistoException with proper message
        """
        mocker.patch.object(client, "_http_request", side_effect=Exception("Network error"))

        args = {"domain": "example.com"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        with pytest.raises(DemistoException, match="Failed to get domain reputation"):
            domain_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

    def test_url_reputation_http_exception(self, client, mocker):
        """
        Test URL reputation with HTTP exception

        Given: HTTP request raises exception
        When: url_reputation_command is called
        Then: Should raise DemistoException with proper message
        """
        mocker.patch.object(client, "_http_request", side_effect=Exception("Timeout"))

        args = {"url": "https://example.com"}
        thresholds = {"good": 10, "suspicious": 30, "bad": 60}

        with pytest.raises(DemistoException, match="Failed to get URL reputation"):
            url_reputation_command(client, args, False, thresholds, "C - Fairly reliable")

    def test_dns_lookup_http_exception(self, client, mocker):
        """
        Test DNS lookup with HTTP exception

        Given: HTTP request raises exception
        When: dns_lookup_command is called
        Then: Should raise DemistoException with proper message
        """
        mocker.patch.object(client, "_http_request", side_effect=Exception("DNS error"))

        args = {"host": "example.com", "type": "A"}

        with pytest.raises(DemistoException, match="Failed to get DNS records"):
            dns_lookup_command(client, args)

    def test_ssl_info_http_exception(self, client, mocker):
        """
        Test SSL info with HTTP exception

        Given: HTTP request raises exception
        When: ssl_info_command is called
        Then: Should raise DemistoException with proper message
        """
        mocker.patch.object(client, "_http_request", side_effect=Exception("SSL error"))

        args = {"host": "example.com"}

        with pytest.raises(DemistoException, match="Failed to get SSL info"):
            ssl_info_command(client, args)

    def test_email_verify_http_exception(self, client, mocker):
        """
        Test email verify with HTTP exception

        Given: HTTP request raises exception
        When: email_verify_command is called
        Then: Should raise DemistoException with proper message
        """
        mocker.patch.object(client, "_http_request", side_effect=Exception("Email error"))

        args = {"email": "test@example.com"}

        with pytest.raises(DemistoException, match="Failed to verify email"):
            email_verify_command(client, args)

    def test_parked_domain_http_exception(self, client, mocker):
        """
        Test parked domain with HTTP exception

        Given: HTTP request raises exception
        When: parked_domain_command is called
        Then: Should raise DemistoException with proper message
        """
        mocker.patch.object(client, "_http_request", side_effect=Exception("Parked error"))

        args = {"domain": "example.com"}

        with pytest.raises(DemistoException, match="Failed to check parked domain"):
            parked_domain_command(client, args)

    def test_domain_age_http_exception(self, client, mocker):
        """
        Test domain age with HTTP exception

        Given: HTTP request raises exception
        When: domain_age_command is called
        Then: Should raise DemistoException with proper message
        """
        mocker.patch.object(client, "_http_request", side_effect=Exception("Age error"))

        args = {"domain": "example.com"}

        with pytest.raises(DemistoException, match="Failed to get domain age"):
            domain_age_command(client, args)

    def test_screenshot_http_exception(self, client, mocker):
        """
        Test screenshot with HTTP exception

        Given: HTTP request raises exception
        When: screenshot_command is called
        Then: Should raise DemistoException with proper message
        """
        mocker.patch.object(client, "_http_request", side_effect=Exception("Screenshot error"))

        args = {"url": "https://example.com"}

        with pytest.raises(DemistoException, match="Failed to capture screenshot"):
            screenshot_command(client, args)

    def test_url_to_pdf_http_exception(self, client, mocker):
        """
        Test URL to PDF with HTTP exception

        Given: HTTP request raises exception
        When: url_to_pdf_command is called
        Then: Should raise DemistoException with proper message
        """
        mocker.patch.object(client, "_http_request", side_effect=Exception("PDF error"))

        args = {"url": "https://example.com"}

        with pytest.raises(DemistoException, match="Failed to convert URL to PDF"):
            url_to_pdf_command(client, args)

    def test_site_trustworthiness_http_exception(self, client, mocker):
        """
        Test site trustworthiness with HTTP exception

        Given: HTTP request raises exception
        When: site_trustworthiness_command is called
        Then: Should raise DemistoException with proper message
        """
        mocker.patch.object(client, "_http_request", side_effect=Exception("Trust error"))

        args = {"host": "example.com"}

        with pytest.raises(DemistoException, match="Failed to get site trustworthiness"):
            site_trustworthiness_command(client, args)


# ============================================================================
# TEST EDGE CASES AND EMPTY RESPONSES
# ============================================================================


class TestEdgeCases:
    """Test edge cases and empty response handling"""

    def test_dns_lookup_no_records(self, client, mocker):
        """
        Test DNS lookup with no records

        Given: API returns empty records
        When: dns_lookup_command is called
        Then: Should return CommandResults with appropriate message
        """
        mocker.patch.object(client, "_http_request", return_value={"host": "example.com", "records": {}})

        args = {"host": "example.com", "type": "A"}

        result = dns_lookup_command(client, args)

        assert isinstance(result, CommandResults)
        assert "No DNS records found" in result.readable_output

    def test_dns_lookup_no_matching_type(self, client, mocker):
        """
        Test DNS lookup with no matching record type

        Given: API returns records but not the requested type
        When: dns_lookup_command is called
        Then: Should return CommandResults with appropriate message
        """
        mocker.patch.object(
            client, "_http_request", return_value={"host": "example.com", "records": {"mx": [{"target": "mail.example.com"}]}}
        )

        args = {"host": "example.com", "type": "A"}

        result = dns_lookup_command(client, args)

        assert isinstance(result, CommandResults)
        assert "No A records found" in result.readable_output

    def test_ssl_info_no_certificate(self, client, mocker):
        """
        Test SSL info with no certificate

        Given: API returns empty certificate
        When: ssl_info_command is called
        Then: Should return CommandResults with appropriate message
        """
        mocker.patch.object(client, "_http_request", return_value={"host": "example.com", "certificate": {}})

        args = {"host": "example.com"}

        result = ssl_info_command(client, args)

        assert isinstance(result, CommandResults)
        assert "No SSL information" in result.readable_output

    def test_ssl_info_api_error(self, client, mocker):
        """
        Test SSL info with API error

        Given: API returns error response
        When: ssl_info_command is called
        Then: Should raise DemistoException
        """
        mocker.patch.object(client, "_http_request", return_value=MOCK_ERROR_RESPONSE)

        args = {"host": "example.com"}

        with pytest.raises(DemistoException, match="Error getting SSL info"):
            ssl_info_command(client, args)

    def test_email_verify_empty_response(self, client, mocker):
        """
        Test email verify with empty response

        Given: API returns empty response
        When: email_verify_command is called
        Then: Should return CommandResults with appropriate message
        """
        mocker.patch.object(client, "_http_request", return_value={})

        args = {"email": "test@example.com"}

        result = email_verify_command(client, args)

        assert isinstance(result, CommandResults)
        assert "No information" in result.readable_output

    def test_email_verify_api_error(self, client, mocker):
        """
        Test email verify with API error

        Given: API returns error response
        When: email_verify_command is called
        Then: Should raise DemistoException
        """
        mocker.patch.object(client, "_http_request", return_value=MOCK_ERROR_RESPONSE)

        args = {"email": "test@example.com"}

        with pytest.raises(DemistoException, match="Error verifying email"):
            email_verify_command(client, args)

    def test_parked_domain_empty_response(self, client, mocker):
        """
        Test parked domain with empty response

        Given: API returns empty response
        When: parked_domain_command is called
        Then: Should return CommandResults with appropriate message
        """
        mocker.patch.object(client, "_http_request", return_value={})

        args = {"domain": "example.com"}

        result = parked_domain_command(client, args)

        assert isinstance(result, CommandResults)
        assert "No information" in result.readable_output

    def test_parked_domain_api_error(self, client, mocker):
        """
        Test parked domain with API error

        Given: API returns error response
        When: parked_domain_command is called
        Then: Should raise DemistoException
        """
        mocker.patch.object(client, "_http_request", return_value=MOCK_ERROR_RESPONSE)

        args = {"domain": "example.com"}

        with pytest.raises(DemistoException, match="Error checking parked domain"):
            parked_domain_command(client, args)

    def test_domain_age_empty_response(self, client, mocker):
        """
        Test domain age with empty response

        Given: API returns empty response
        When: domain_age_command is called
        Then: Should return CommandResults with appropriate message
        """
        mocker.patch.object(client, "_http_request", return_value={})

        args = {"domain": "example.com"}

        result = domain_age_command(client, args)

        assert isinstance(result, CommandResults)
        assert "No information" in result.readable_output

    def test_domain_age_api_error(self, client, mocker):
        """
        Test domain age with API error

        Given: API returns error response
        When: domain_age_command is called
        Then: Should raise DemistoException
        """
        mocker.patch.object(client, "_http_request", return_value=MOCK_ERROR_RESPONSE)

        args = {"domain": "example.com"}

        with pytest.raises(DemistoException, match="Error getting domain age"):
            domain_age_command(client, args)

    def test_screenshot_api_error(self, client, mocker):
        """
        Test screenshot with API error

        Given: API returns error response
        When: screenshot_command is called
        Then: Should raise DemistoException
        """
        mocker.patch.object(client, "_http_request", return_value=MOCK_ERROR_RESPONSE)

        args = {"url": "https://example.com"}

        with pytest.raises(DemistoException, match="Error capturing screenshot"):
            screenshot_command(client, args)

    def test_url_to_pdf_api_error(self, client, mocker):
        """
        Test URL to PDF with API error

        Given: API returns error response
        When: url_to_pdf_command is called
        Then: Should raise DemistoException
        """
        mocker.patch.object(client, "_http_request", return_value=MOCK_ERROR_RESPONSE)

        args = {"url": "https://example.com"}

        with pytest.raises(DemistoException, match="Error converting URL to PDF"):
            url_to_pdf_command(client, args)

    def test_site_trustworthiness_empty_response(self, client, mocker):
        """
        Test site trustworthiness with empty response

        Given: API returns empty response
        When: site_trustworthiness_command is called
        Then: Should return CommandResults with appropriate message
        """
        mocker.patch.object(client, "_http_request", return_value={})

        args = {"host": "example.com"}

        result = site_trustworthiness_command(client, args)

        assert isinstance(result, CommandResults)
        assert "No information" in result.readable_output

    def test_site_trustworthiness_api_error(self, client, mocker):
        """
        Test site trustworthiness with API error

        Given: API returns error response
        When: site_trustworthiness_command is called
        Then: Should raise DemistoException
        """
        mocker.patch.object(client, "_http_request", return_value=MOCK_ERROR_RESPONSE)

        args = {"host": "example.com"}

        with pytest.raises(DemistoException, match="Error getting site trustworthiness"):
            site_trustworthiness_command(client, args)
