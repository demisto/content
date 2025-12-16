"""
SpecterOpsBHE integration for Cortex XSOAR - Unit Tests file
"""

import sys

sys.path.append("/home/ishika/demisto-env/content/Packs/ApiModules/Scripts/DemistoClassApiModule/")
sys.path.append("/home/ishika/demisto-env/content")
from unittest.mock import Mock, patch
from urllib.parse import urljoin

import demistomock as demisto
import pytest
import requests
import SpecterOpsBHE
from SpecterOpsBHE import (
    BAD_REQUEST,
    ENDPOINTS,
    FORBIDDEN_REQUEST,
    NOT_FOUND,
    SERVER_ERROR,
    TOO_MANY_REQUEST,
    UNAUTHORIZED_REQUEST,
    BloodHoundBadRequestException,
    BloodHoundException,
    BloodHoundForbiddenException,
    BloodHoundNotFoundException,
    BloodHoundRateLimitException,
    BloodHoundServerErrorException,
    BloodHoundUnauthorizedException,
    Client,
    _create_event_dict,
    _create_incident_dict,
    _extract_bhe_instance,
    _extract_object_ids,
    _extract_object_names,
    _get_azure_type_path,
    _get_last_timestamp_for_finding_type,
    _group_attack_paths_by_domain,
    _handle_fetch_asset_information,
    _paginate_and_filter_attack_paths,
    _process_az_tenant,
    _update_primary_response,
    acquire_lock,
    collect_available_types,
    create_incidents,
    does_path_exists_between_nodes,
    fetch_attack_path_details,
    fetch_incidents,
    fetch_path_info,
    fetch_asset_info,
    filter_domains,
    filter_finding_types,
    get_available_domains,
    get_available_types_for_domain,
    get_finding_type_long_remediation,
    get_finding_type_short_description,
    get_finding_type_short_remediation,
    get_object_id,
    get_object_id_by_name,
    get_path_title,
    get_attack_path_details_page,
    release_lock,
)

RETURN_ERROR_TARGET = "SpecterOpsBHE.return_error"


@pytest.fixture
def mock_client():
    """Create a mock Client instance for testing"""
    return Client(
        bhe_domain="https://test.bhe.example.com",
        bhe_token_id="test_token_id",
        bhe_token_key="test_token_key",
        bhe_finding_domain="all",
        bhe_finding_category="all",
    )


@pytest.fixture
def mock_response():
    """Create a mock response object"""
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.return_value = {"data": []}
    response.text = ""
    response.content = b""
    response.raise_for_status = Mock()
    return response


class TestClient:
    """Test cases for Client class"""

    def test_client_initialization(self):
        """Test Client initialization with all parameters"""
        client = Client(
            bhe_domain="https://test.bhe.example.com",
            bhe_token_id="test_token_id",
            bhe_token_key="test_token_key",
            bhe_finding_domain="domain1,domain2",
            bhe_finding_category="type1,type2",
            custom_proxy_url="http://proxy.example.com",
            custom_proxy_username="proxy_user",
            custom_proxy_password="proxy_pass",
        )
        assert client.bhe_domain == "https://test.bhe.example.com"
        assert client._Client__token_id == "test_token_id"
        assert client._Client__token_key == "test_token_key"
        assert client.bhe_finding_domain == "domain1,domain2"
        assert client.bhe_finding_category == "type1,type2"
        assert client.custom_proxy_url == "http://proxy.example.com"

    def test_get_full_url(self, mock_client):
        """Test _get_full_url method"""
        url = mock_client._get_full_url("available_domain")
        expected = urljoin("https://test.bhe.example.com", ENDPOINTS["available_domain"])
        assert url == expected

    def test_get_full_url_with_params(self, mock_client):
        """Test _get_full_url with parameters"""
        url = mock_client._get_full_url("search", query="test%20query")
        expected = urljoin("https://test.bhe.example.com", ENDPOINTS["search"].format(query="test%20query"))
        assert url == expected

    def test_get_headers(self, mock_client):
        """Test _get_headers method generates correct headers"""
        headers = mock_client._get_headers("GET", "/api/v2/test")
        assert "User-Agent" in headers
        assert "Authorization" in headers
        assert "RequestDate" in headers
        assert "Signature" in headers
        assert "Content-Type" in headers
        assert headers["Authorization"] == "bhesignature test_token_id"
        assert headers["Content-Type"] == "application/json"

    def test_get_headers_exception(self, mock_client):
        """Test _get_headers raises exception on error"""
        mock_client._Client__token_key = None
        with pytest.raises(BloodHoundException):
            mock_client._get_headers("GET", "/api/v2/test")

    def test_validate_response_success(self, mock_client, mock_response):
        """Test _validate_response with successful response"""
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()
        # Should not raise any exception
        mock_client._validate_response(mock_response)

    def test_validate_response_bad_request(self, mock_client, mock_response):
        """Test _validate_response with 400 Bad Request"""
        mock_response.status_code = BAD_REQUEST
        mock_response.json.return_value = {"message": "Bad Request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError()
        with pytest.raises(BloodHoundBadRequestException):
            mock_client._validate_response(mock_response)

    def test_validate_response_unauthorized(self, mock_client, mock_response):
        """Test _validate_response with 401 Unauthorized"""
        mock_response.status_code = UNAUTHORIZED_REQUEST
        mock_response.json.return_value = {"message": "Unauthorized"}
        mock_response.raise_for_status.side_effect = requests.HTTPError()
        with pytest.raises(BloodHoundUnauthorizedException):
            mock_client._validate_response(mock_response)

    def test_validate_response_forbidden(self, mock_client, mock_response):
        """Test _validate_response with 403 Forbidden"""
        mock_response.status_code = FORBIDDEN_REQUEST
        mock_response.json.return_value = {"message": "Forbidden"}
        mock_response.raise_for_status.side_effect = requests.HTTPError()
        with pytest.raises(BloodHoundForbiddenException):
            mock_client._validate_response(mock_response)

    def test_validate_response_not_found(self, mock_client, mock_response):
        """Test _validate_response with 404 Not Found"""
        mock_response.status_code = NOT_FOUND
        mock_response.json.return_value = {"message": "Not Found"}
        mock_response.raise_for_status.side_effect = requests.HTTPError()
        with pytest.raises(BloodHoundNotFoundException):
            mock_client._validate_response(mock_response)

    def test_validate_response_rate_limit(self, mock_client, mock_response):
        """Test _validate_response with 429 Rate Limit"""
        mock_response.status_code = TOO_MANY_REQUEST
        mock_response.json.return_value = {"message": "Rate Limit"}
        mock_response.raise_for_status.side_effect = requests.HTTPError()
        with pytest.raises(BloodHoundRateLimitException):
            mock_client._validate_response(mock_response)

    def test_validate_response_server_error(self, mock_client, mock_response):
        """Test _validate_response with 500 Server Error"""
        mock_response.status_code = SERVER_ERROR
        mock_response.json.return_value = {"message": "Internal Server Error"}
        mock_response.raise_for_status.side_effect = requests.HTTPError()
        with pytest.raises(BloodHoundServerErrorException):
            mock_client._validate_response(mock_response)

    def test_validate_response_no_json(self, mock_client, mock_response):
        """Test _validate_response when response has no JSON"""
        mock_response.status_code = BAD_REQUEST
        mock_response.json.side_effect = Exception("No JSON")
        mock_response.content = b"Error content"
        mock_response.raise_for_status.side_effect = requests.HTTPError()
        with pytest.raises(BloodHoundException):
            mock_client._validate_response(mock_response)

    def test_build_proxy_dict_no_proxy(self, mock_client):
        """Test _build_proxy_dict when no proxy is configured"""
        result = mock_client._build_proxy_dict()
        assert result is None

    def test_build_proxy_dict_with_proxy(self):
        """Test _build_proxy_dict with proxy configured"""
        client = Client(
            bhe_domain="https://test.bhe.example.com",
            bhe_token_id="test_token_id",
            bhe_token_key="test_token_key",
            bhe_finding_domain="all",
            bhe_finding_category="all",
            custom_proxy_url="http://proxy.example.com:8080",
        )
        result = client._build_proxy_dict()
        assert result is not None
        assert "http" in result
        assert "https" in result
        assert "proxy.example.com:8080" in result["http"]

    def test_build_proxy_dict_with_auth(self):
        """Test _build_proxy_dict with proxy authentication"""
        client = Client(
            bhe_domain="https://test.bhe.example.com",
            bhe_token_id="test_token_id",
            bhe_token_key="test_token_key",
            bhe_finding_domain="all",
            bhe_finding_category="all",
            custom_proxy_url="http://proxy.example.com:8080",
            custom_proxy_username="user",
            custom_proxy_password="pass",
        )
        result = client._build_proxy_dict()
        assert result is not None
        assert "user:pass@" in result["http"]

    def test_build_proxy_dict_invalid_url(self):
        """Test _build_proxy_dict with invalid proxy URL"""
        client = Client(
            bhe_domain="https://test.bhe.example.com",
            bhe_token_id="test_token_id",
            bhe_token_key="test_token_key",
            bhe_finding_domain="all",
            bhe_finding_category="all",
            custom_proxy_url="http://",
            custom_proxy_username="user",
            custom_proxy_password="pass",
        )
        with pytest.raises(BloodHoundException):
            client._build_proxy_dict()

    @patch("SpecterOpsBHE.requests.request")
    def test_api_request_success(self, mock_request, mock_client, mock_response):
        """Test _api_request with successful response"""
        mock_response.json.return_value = {"data": [{"id": "123"}]}
        mock_request.return_value = mock_response
        result = mock_client._api_request("available_domain")
        assert result == {"data": [{"id": "123"}]}
        mock_request.assert_called_once()

    @patch("SpecterOpsBHE.requests.request")
    def test_api_request_retry_on_rate_limit(self, mock_request, mock_client, mock_response):
        """Test _api_request retries on rate limit"""
        # First call raises rate limit, second succeeds
        rate_limit_response = Mock(spec=requests.Response)
        rate_limit_response.status_code = TOO_MANY_REQUEST
        rate_limit_response.json.return_value = {"message": "Rate Limit"}
        rate_limit_response.raise_for_status.side_effect = requests.HTTPError()
        rate_limit_response.content = b""

        mock_response.json.return_value = {"data": []}
        mock_request.side_effect = [rate_limit_response, mock_response]

        # Should retry and succeed
        result = mock_client._api_request("available_domain")
        assert result == {"data": []}
        assert mock_request.call_count == 2

    @patch("SpecterOpsBHE.requests.request")
    def test_api_request_retry_on_server_error(self, mock_request, mock_client, mock_response):
        """Test _api_request retries on server error"""
        server_error_response = Mock(spec=requests.Response)
        server_error_response.status_code = SERVER_ERROR
        server_error_response.json.return_value = {"message": "Server Error"}
        server_error_response.raise_for_status.side_effect = requests.HTTPError()
        server_error_response.content = b""

        mock_response.json.return_value = {"data": []}
        mock_request.side_effect = [server_error_response, mock_response]

        result = mock_client._api_request("available_domain")
        assert result == {"data": []}
        assert mock_request.call_count == 2

    @patch("SpecterOpsBHE.requests.request")
    def test_api_request_proxy_error(self, mock_request, mock_client):
        """Test _api_request handles proxy errors"""
        mock_request.side_effect = requests.exceptions.ProxyError("Proxy error")
        with pytest.raises(BloodHoundException) as exc_info:
            mock_client._api_request("available_domain")
        assert "Proxy error" in str(exc_info.value)

    @patch("SpecterOpsBHE.requests.request")
    def test_api_request_connection_error(self, mock_request, mock_client):
        """Test _api_request handles connection errors"""
        mock_request.side_effect = requests.exceptions.ConnectionError("Connection error")
        with pytest.raises(BloodHoundException) as exc_info:
            mock_client._api_request("available_domain")
        assert "Connection error" in str(exc_info.value)

    @patch("SpecterOpsBHE.requests.request")
    def test_test_connection(self, mock_request, mock_client, mock_response):
        """Test test_connection method"""
        mock_request.return_value = mock_response
        result = mock_client.test_connection()
        assert result == mock_response
        mock_request.assert_called_once()


class TestHelperFunctions:
    """Test cases for helper functions"""

    def test_extract_bhe_instance(self):
        """Test _extract_bhe_instance function"""
        assert _extract_bhe_instance("https://test.bhe.example.com") == "TEST"
        assert _extract_bhe_instance("http://my-bhe.example.com") == "MY-BHE"
        assert _extract_bhe_instance("invalid") == "INVALID"

    def test_extract_object_ids_with_from_principal(self):
        """Test _extract_object_ids with FromPrincipalProps"""
        item = {
            "FromPrincipalProps": {"objectid": "id1"},
            "ToPrincipalProps": {"objectid": "id2"},
        }
        result = _extract_object_ids(item)
        assert "id1" in result
        assert "id2" in result

    def test_extract_object_ids_with_props(self):
        """Test _extract_object_ids with Props"""
        item = {"Props": {"objectid": "id1"}}
        result = _extract_object_ids(item)
        assert result == ["id1"]

    def test_extract_object_ids_empty(self):
        """Test _extract_object_ids with no object IDs"""
        item = {}
        result = _extract_object_ids(item)
        assert result == []

    def test_extract_object_names_with_from_principal(self):
        """Test _extract_object_names with FromPrincipalProps"""
        item = {
            "FromPrincipalProps": {"name": "name1"},
            "ToPrincipalProps": {"name": "name2"},
        }
        result = _extract_object_names(item)
        assert "name1" in result
        assert "name2" in result

    def test_extract_object_names_with_props(self):
        """Test _extract_object_names with Props"""
        item = {"Props": {"name": "name1"}}
        result = _extract_object_names(item)
        assert result == ["name1"]

    def test_get_azure_type_path(self):
        """Test _get_azure_type_path function"""
        assert _get_azure_type_path("AZServicePrincipal") == "service-principals"
        assert _get_azure_type_path("AZApp") == "applications"
        assert _get_azure_type_path("AZUser") == "users"
        assert _get_azure_type_path("AZGroup") == "groups"

    def test_create_event_dict(self):
        """Test _create_event_dict function"""
        item = {
            "id": "attack123",
            "Severity": "high",
            "DomainSID": "S-1-5-21",
            "ImpactPercentage": 0.5,
            "ImpactCount": 10,
            "ExposurePercentage": 0.3,
            "ExposureCount": 5,
            "AcceptedUntil": None,
            "Accepted": False,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
            "ToPrincipalProps": {"objectid": "obj123", "name": "TestPrincipal"},
            "Principal": "principal1",
            "PrincipalKind": "User",
            "PrincipalName": "test@example.com",
            "Environment": "Azure",
        }
        event = _create_event_dict(
            item,
            "test.domain.com",
            "Test Attack Path",
            "test_finding",
            "2024-01-01T00:00:00Z",
            "Short remediation",
            "Long remediation",
            "Short description",
        )
        assert event["AttackId"] == "attack123"
        assert event["Severity"] == "high"
        assert event["Domain"] == "test.domain.com"
        assert event["PathTitle"] == "Test Attack Path"
        assert event["ImpactPercentage"] == 50.0
        assert event["ExposurePercentage"] == 30.0

    def test_create_incident_dict(self):
        """Test _create_incident_dict function"""
        event = {
            "AttackId": "attack123",
            "Domain": "test.domain.com",
            "Severity": "high",
        }
        incident = _create_incident_dict(
            "TEST",
            "test.domain.com",
            "Test Attack Path",
            event,
            "high",
            "2024-01-01T00:00:00Z",
            "Short description",
            "Short remediation",
        )
        assert incident["name"] == "TEST - test.domain.com - Test Attack Path"
        assert incident["type"] == "SpecterOpsBHE Attack Path"
        assert incident["severity"] == 3  # high severity
        assert "rawJSON" in incident

    def test_group_attack_paths_by_domain(self):
        """Test _group_attack_paths_by_domain function"""
        attack_path_details = {
            ("domain1", "finding1"): [{"id": "path1"}],
            ("domain1", "finding2"): [{"id": "path2"}],
            ("domain2", "finding1"): [{"id": "path3"}],
        }
        domains = {
            "domain1": {"name": "domain1.com"},
            "domain2": {"name": "domain2.com"},
        }
        attack_paths_info = {
            "finding1": {"title": "Finding 1"},
            "finding2": {"title": "Finding 2"},
        }
        result = _group_attack_paths_by_domain(attack_path_details, domains, attack_paths_info)
        assert "domain1.com" in result
        assert "domain2.com" in result
        assert "Finding 1" in result["domain1.com"]
        assert "Finding 2" in result["domain1.com"]


class TestDomainFunctions:
    """Test cases for domain-related functions"""

    @patch.object(Client, "_api_request")
    def test_get_available_domains_success(self, mock_api_request, mock_client):
        """Test get_available_domains with successful response"""
        mock_api_request.return_value = {"data": [{"id": "1", "name": "domain1", "collected": True}]}
        status, response = get_available_domains(mock_client)
        assert status is True
        assert response == {"data": [{"id": "1", "name": "domain1", "collected": True}]}

    @patch.object(Client, "_api_request")
    def test_get_available_domains_failure(self, mock_api_request, mock_client):
        """Test get_available_domains with failure"""
        mock_api_request.side_effect = Exception("API Error")
        status, response = get_available_domains(mock_client)
        assert status is False
        assert isinstance(response, Exception)

    def test_filter_domains_all(self):
        """Test filter_domains with 'all' selection"""
        domains = {"1": {"name": "domain1"}, "2": {"name": "domain2"}}
        result = filter_domains(domains, "all")
        assert result == domains

    def test_filter_domains_specific(self):
        """Test filter_domains with specific domain selection"""
        domains = {"1": {"name": "domain1"}, "2": {"name": "domain2"}}
        result = filter_domains(domains, "domain1")
        assert "1" in result
        assert "2" not in result

    def test_filter_domains_multiple(self):
        """Test filter_domains with multiple domains"""
        domains = {"1": {"name": "domain1"}, "2": {"name": "domain2"}, "3": {"name": "domain3"}}
        result = filter_domains(domains, "domain1, domain2")
        assert "1" in result
        assert "2" in result
        assert "3" not in result

    def test_filter_domains_no_match(self):
        """Test filter_domains with no matching domains"""
        domains = {"1": {"name": "domain1"}}
        with pytest.raises(Exception):
            filter_domains(domains, "nonexistent")

    @patch.object(Client, "_api_request")
    def test_get_available_types_for_domain(self, mock_api_request, mock_client):
        """Test get_available_types_for_domain"""
        mock_api_request.return_value = {"data": ["type1", "type2"]}
        result = get_available_types_for_domain(mock_client, "domain1")
        assert result == ["type1", "type2"]

    @patch.object(Client, "_api_request")
    def test_collect_available_types(self, mock_api_request, mock_client):
        """Test collect_available_types"""
        mock_api_request.return_value = {"data": ["type1", "type2"]}
        domains = {"1": {"name": "domain1"}, "2": {"name": "domain2"}}
        result = collect_available_types(mock_client, domains)
        assert "available_types" in result["1"]
        assert "available_types" in result["2"]

    def test_filter_finding_types_all(self):
        """Test filter_finding_types with 'all' selection"""
        domains = {"1": {"available_types": ["type1", "type2"]}}
        result = filter_finding_types(domains, "all")
        assert result == domains

    def test_filter_finding_types_specific(self):
        """Test filter_finding_types with specific types"""
        domains = {"1": {"available_types": ["type1", "type2", "type3"]}}
        result = filter_finding_types(domains, "type1, type2")
        assert result["1"]["available_types"] == ["type1", "type2"]


class TestPathFunctions:
    """Test cases for path-related functions"""

    @patch.object(Client, "_api_request")
    def test_get_path_title(self, mock_api_request, mock_client):
        """Test get_path_title"""
        mock_response = Mock()
        mock_response.text = "# Test Title"
        mock_api_request.return_value = mock_response
        result = get_path_title(mock_client, "finding_type")
        assert result == "# Test Title"

    @patch.object(Client, "_api_request")
    def test_get_finding_type_short_description(self, mock_api_request, mock_client):
        """Test get_finding_type_short_description"""
        mock_response = Mock()
        mock_response.text = "Short description"
        mock_api_request.return_value = mock_response
        result = get_finding_type_short_description(mock_client, "finding_type")
        assert result == "Short description"

    @patch.object(Client, "_api_request")
    def test_get_finding_type_short_remediation(self, mock_api_request, mock_client):
        """Test get_finding_type_short_remediation"""
        mock_response = Mock()
        mock_response.text = "Short remediation"
        mock_api_request.return_value = mock_response
        result = get_finding_type_short_remediation(mock_client, "finding_type")
        assert result == "Short remediation"

    @patch.object(Client, "_api_request")
    def test_get_finding_type_long_remediation(self, mock_api_request, mock_client):
        """Test get_finding_type_long_remediation"""
        mock_response = Mock()
        mock_response.text = "Long remediation"
        mock_api_request.return_value = mock_response
        result = get_finding_type_long_remediation(mock_client, "finding_type")
        assert result == "Long remediation"

    @patch.object(Client, "_api_request")
    def test_fetch_path_info(self, mock_api_request, mock_client):
        """Test fetch_path_info"""
        mock_response = Mock()
        mock_response.text = "Test content"
        mock_api_request.return_value = mock_response

        domains = {"1": {"available_types": ["type1", "type2"]}}
        result = fetch_path_info(mock_client, domains)
        assert "type1" in result
        assert "type2" in result
        assert "title" in result["type1"]
        assert "short_remediation" in result["type1"]

    @patch.object(Client, "_api_request")
    def test_get_attack_path_details_page(self, mock_api_request, mock_client):
        """Test get_attack_path_details_page"""
        mock_api_request.return_value = {"data": [{"id": "path1"}, {"id": "path2"}]}
        result = get_attack_path_details_page(mock_client, "domain1", "finding1", skip=0)
        assert len(result) == 2
        assert result[0]["id"] == "path1"

    @patch.object(Client, "_api_request")
    def test_get_attack_path_details_page_with_date_filter(self, mock_api_request, mock_client):
        """Test get_attack_path_details_page with created_at filter"""
        mock_api_request.return_value = {"data": [{"id": "path1"}]}
        result = get_attack_path_details_page(mock_client, "domain1", "finding1", skip=0, created_at="2024-01-01")
        assert len(result) == 1

    def test_get_last_timestamp_for_finding_type(self):
        """Test _get_last_timestamp_for_finding_type"""
        last_run = {"domain1:finding1": "2024-01-01T00:00:00Z"}
        result = _get_last_timestamp_for_finding_type(last_run, "domain1:finding1", "domain1")
        assert result == "2024-01-01T00:00:00Z"

    def test_get_last_timestamp_legacy(self):
        """Test _get_last_timestamp_for_finding_type with legacy format"""
        last_run = {"domain1": "2024-01-01T00:00:00Z"}
        result = _get_last_timestamp_for_finding_type(last_run, "domain1:finding1", "domain1")
        assert result == "2024-01-01T00:00:00Z"

    @patch("SpecterOpsBHE.get_attack_path_details_page")
    def test_paginate_and_filter_attack_paths(self, mock_get_page, mock_client):
        """Test _paginate_and_filter_attack_paths"""
        # First page with newer paths
        page1 = [
            {"id": "path1", "created_at": "2024-01-02T00:00:00Z"},
            {"id": "path2", "created_at": "2024-01-03T00:00:00Z"},
        ]
        # Second page is empty
        page2 = []
        mock_get_page.side_effect = [page1, page2]

        finding_type_latest_dates = {}
        result = _paginate_and_filter_attack_paths(
            mock_client,
            "domain1",
            "finding1",
            "domain1:finding1",
            "2024-01-01T00:00:00Z",
            finding_type_latest_dates,
        )
        assert len(result) == 2
        assert finding_type_latest_dates["domain1:finding1"] == "2024-01-03T00:00:00Z"

    @patch("SpecterOpsBHE._paginate_and_filter_attack_paths")
    @patch("SpecterOpsBHE._get_last_timestamp_for_finding_type")
    def test_fetch_attack_path_details(self, mock_get_timestamp, mock_paginate, mock_client):
        """Test fetch_attack_path_details"""
        mock_get_timestamp.return_value = "2024-01-01T00:00:00Z"
        # Return a list with attack paths - the mock needs to update finding_type_latest_dates
        attack_paths = [{"id": "path1", "created_at": "2024-01-02T00:00:00Z"}]

        def side_effect(client, domain_id, finding_type, finding_type_key, last_timestamp, finding_type_latest_dates):
            # Simulate the side effect of updating finding_type_latest_dates
            finding_type_latest_dates[finding_type_key] = "2024-01-02T00:00:00Z"
            return attack_paths

        mock_paginate.side_effect = side_effect

        domains = {"1": {"name": "domain1", "available_types": ["finding1"]}}
        last_run = {}
        attack_path_details, finding_type_latest_dates = fetch_attack_path_details(mock_client, last_run, domains)
        # attack_path_details is a dict with (domain_id, finding_type) as keys
        assert len(attack_path_details) > 0
        assert ("1", "finding1") in attack_path_details
        assert len(finding_type_latest_dates) > 0
        assert "domain1:finding1" in finding_type_latest_dates


class TestAssetFunctions:
    """Test cases for asset-related functions"""

    @patch.object(Client, "_api_request")
    def test_get_object_id_by_name_success(self, mock_api_request, mock_client):
        """Test get_object_id_by_name with successful response"""
        mock_api_request.return_value = {"data": [{"id": "123", "name": "test"}]}
        result = get_object_id_by_name(mock_client, "test")
        assert result["status"] == "success"
        assert result["data"] == [{"id": "123", "name": "test"}]

    @patch.object(Client, "_api_request")
    def test_get_object_id_by_name_not_found(self, mock_api_request, mock_client):
        """Test get_object_id_by_name when object not found"""
        mock_api_request.return_value = {"data": []}
        result = get_object_id_by_name(mock_client, "nonexistent")
        assert result["status"] == "success"
        assert result["message"] == "Object ID Not found."

    @patch.object(Client, "_api_request")
    def test_get_object_id_by_name_error(self, mock_api_request, mock_client):
        """Test get_object_id_by_name with error"""
        mock_api_request.side_effect = Exception("API Error")
        result = get_object_id_by_name(mock_client, "test")
        assert result["status"] == "error"

    @patch("SpecterOpsBHE.get_object_id_by_name")
    def test_get_object_id(self, mock_get_by_name, mock_client):
        """Test get_object_id function"""
        mock_get_by_name.return_value = {"status": "success", "data": [{"id": "123"}]}
        result = get_object_id(mock_client, ["test1", "test2"])
        assert "test1" in result
        assert "test2" in result

    @patch.object(Client, "_api_request")
    def test_handle_fetch_asset_information_success(self, mock_api_request, mock_client):
        """Test _handle_fetch_asset_information with successful response"""
        # Mock search response
        search_response = {"data": [{"id": "123", "type": "User"}]}
        # Mock primary response
        primary_response = {"data": {"name": "test", "type": "User"}}
        mock_api_request.side_effect = [search_response, primary_response]

        result = _handle_fetch_asset_information(mock_client, "123")
        assert result["status"] == "success"
        assert result["data"]["name"] == "test"

    @patch.object(Client, "_api_request")
    def test_handle_fetch_asset_information_azure(self, mock_api_request, mock_client):
        """Test _handle_fetch_asset_information with Azure type"""
        search_response = {"data": [{"id": "123", "type": "AZUser"}]}
        primary_response = {"data": {"name": "test", "type": "AZUser"}}
        related_response = {"count": 5}
        mock_api_request.side_effect = [search_response, primary_response, related_response]

        result = _handle_fetch_asset_information(mock_client, "123")
        assert result["status"] == "success"

    @patch.object(Client, "_api_request")
    def test_handle_fetch_asset_information_not_found(self, mock_api_request, mock_client):
        """Test _handle_fetch_asset_information when object not found"""
        mock_api_request.return_value = {"data": []}
        result = _handle_fetch_asset_information(mock_client, "123")
        # According to the code, empty data list returns error status (not [] is True)
        assert result["status"] == "error"
        assert "not available" in result["message"].lower()

    @patch("SpecterOpsBHE._handle_fetch_asset_information")
    def test_fetch_asset_info(self, mock_fetch, mock_client):
        """Test fetch_asset_info function"""
        mock_fetch.return_value = {"status": "success", "data": {"name": "test"}}
        result = fetch_asset_info(mock_client, ["123", "456"])
        assert "123" in result
        assert "456" in result

    @patch.object(Client, "_api_request")
    def test_update_primary_response(self, mock_api_request, mock_client):
        """Test _update_primary_response"""
        mock_api_request.return_value = {"count": 10}
        primary_response = {"data": {}}
        _update_primary_response(mock_client, primary_response, "123", "AZUser", "group-membership", "group_membership")
        assert primary_response["data"]["group_membership"] == 10

    @patch.object(Client, "_api_request")
    def test_process_az_tenant(self, mock_api_request, mock_client):
        """Test _process_az_tenant"""
        mock_api_request.return_value = {"count": 5}
        primary_response = {"data": {}}
        result = _process_az_tenant(mock_client, "123", primary_response)
        assert "Successfully" in result
        assert "inbound_object_control" in primary_response["data"]


class TestPathExistence:
    """Test cases for path existence functions"""

    @patch.object(Client, "_api_request")
    def test_does_path_exists_between_nodes_success(self, mock_api_request, mock_client):
        """Test does_path_exists_between_nodes when path exists"""
        mock_response = Mock()
        mock_api_request.return_value = mock_response
        result = does_path_exists_between_nodes(mock_client, "node1", "node2")
        assert result["status"] == "success"
        assert result["data"] is True

    @patch.object(Client, "_api_request")
    def test_does_path_exists_between_nodes_not_found(self, mock_api_request, mock_client):
        """Test does_path_exists_between_nodes when path doesn't exist"""
        mock_api_request.side_effect = BloodHoundServerErrorException("Path not found")
        result = does_path_exists_between_nodes(mock_client, "node1", "node2")
        assert result["status"] == "error"
        assert result["data"] is False

    @patch.object(Client, "_api_request")
    def test_does_path_exists_between_nodes_error(self, mock_api_request, mock_client):
        """Test does_path_exists_between_nodes with error"""
        mock_api_request.side_effect = Exception("API Error")
        result = does_path_exists_between_nodes(mock_client, "node1", "node2")
        assert result["status"] == "error"


class TestIncidentCreation:
    """Test cases for incident creation"""

    def test_create_incidents_empty(self, mock_client):
        """Test create_incidents with empty attack paths"""
        attack_path_details = {}
        domains = {}
        attack_paths_info = {}
        result = create_incidents(mock_client, attack_path_details, domains, attack_paths_info)
        assert result == []

    @patch("SpecterOpsBHE._group_attack_paths_by_domain")
    @patch("SpecterOpsBHE._extract_bhe_instance")
    def test_create_incidents(self, mock_extract, mock_group, mock_client):
        """Test create_incidents with valid data"""
        mock_extract.return_value = "TEST"
        mock_group.return_value = {
            "domain1.com": {
                "Test Path": [
                    (
                        "finding1",
                        {
                            "id": "path1",
                            "Severity": "high",
                            "DomainSID": "S-1-5-21",
                            "ImpactPercentage": 0.5,
                            "ImpactCount": 10,
                            "ExposurePercentage": 0.3,
                            "ExposureCount": 5,
                            "created_at": "2024-01-01T00:00:00Z",
                            "updated_at": "2024-01-01T00:00:00Z",
                            "ToPrincipalProps": {"objectid": "obj123", "name": "Test"},
                        },
                    )
                ]
            }
        }

        attack_path_details = {("domain1", "finding1"): [{"id": "path1"}]}
        domains = {"domain1": {"name": "domain1.com"}}
        attack_paths_info = {
            "finding1": {"title": "Test Path", "short_remediation": "", "long_remediation": "", "short_description": ""}
        }

        result = create_incidents(mock_client, attack_path_details, domains, attack_paths_info)
        assert len(result) > 0
        assert result[0]["type"] == "SpecterOpsBHE Attack Path"


class TestLockMechanism:
    """Test cases for lock mechanism"""

    def test_acquire_lock_first_time(self):
        """Test acquire_lock when no lock exists"""
        demisto.setIntegrationContext({})
        result = acquire_lock()
        assert result is True
        ctx = demisto.getIntegrationContext()
        assert "lock_time" in ctx

    def test_acquire_lock_already_locked(self):
        """Test acquire_lock when lock already exists"""
        import time

        demisto.setIntegrationContext({"lock_time": str(time.time())})
        SpecterOpsBHE.LOCK_TIMEOUT = 600
        result = acquire_lock()
        assert result is False

    def test_release_lock(self):
        """Test release_lock"""
        demisto.setIntegrationContext({"lock_time": "123456"})
        release_lock()
        ctx = demisto.getIntegrationContext()
        assert "lock_time" not in ctx
        assert "last_fetch_time" in ctx


class TestTestModule:
    """Test cases for test_module function"""

    @patch.object(Client, "test_connection")
    def test_test_module_success(self, mock_test, mock_client):
        """Test test_module with successful connection"""
        mock_test.return_value = Mock()
        result = SpecterOpsBHE.test_module(mock_client)
        assert result == "ok"

    @patch.object(Client, "test_connection")
    def test_test_module_unauthorized(self, mock_test, mock_client):
        """Test test_module with unauthorized error"""
        mock_test.side_effect = BloodHoundUnauthorizedException("Unauthorized")
        result = SpecterOpsBHE.test_module(mock_client)
        assert "Unauthorized" in result

    @patch.object(Client, "test_connection")
    def test_test_module_bad_request(self, mock_test, mock_client):
        """Test test_module with bad request"""
        mock_test.side_effect = BloodHoundBadRequestException("Bad Request")
        result = SpecterOpsBHE.test_module(mock_client)
        assert "Bad Request" in result

    @patch.object(Client, "test_connection")
    def test_test_module_forbidden(self, mock_test, mock_client):
        """Test test_module with forbidden error"""
        mock_test.side_effect = BloodHoundForbiddenException("Forbidden")
        result = SpecterOpsBHE.test_module(mock_client)
        assert "Forbidden" in result

    @patch.object(Client, "test_connection")
    def test_test_module_server_error(self, mock_test, mock_client):
        """Test test_module with server error"""
        mock_test.side_effect = BloodHoundServerErrorException("Server Error")
        result = SpecterOpsBHE.test_module(mock_client)
        assert "Server error" in result

    @patch.object(Client, "test_connection")
    def test_test_module_dns_error(self, mock_test, mock_client):
        """Test test_module with DNS resolution error"""
        mock_test.side_effect = Exception("Name does not resolve")
        result = SpecterOpsBHE.test_module(mock_client)
        assert "Invalid domain" in result


class TestFetchIncidents:
    """Test cases for fetch_incidents function"""

    @patch("SpecterOpsBHE.release_lock")
    @patch("SpecterOpsBHE.create_incidents")
    @patch("SpecterOpsBHE.fetch_attack_path_details")
    @patch("SpecterOpsBHE.fetch_path_info")
    @patch("SpecterOpsBHE.filter_finding_types")
    @patch("SpecterOpsBHE.collect_available_types")
    @patch("SpecterOpsBHE.filter_domains")
    @patch("SpecterOpsBHE.get_available_domains")
    @patch("SpecterOpsBHE.acquire_lock")
    def test_fetch_incidents_success(
        self,
        mock_acquire,
        mock_get_domains,
        mock_filter_domains,
        mock_collect_types,
        mock_filter_types,
        mock_fetch_path_info,
        mock_fetch_paths,
        mock_create,
        mock_release,
        mock_client,
    ):
        """Test fetch_incidents with successful execution"""
        mock_acquire.return_value = True
        mock_get_domains.return_value = (True, {"data": [{"id": "1", "name": "domain1", "collected": True}]})
        mock_filter_domains.return_value = {"1": {"name": "domain1"}}
        mock_collect_types.return_value = {"1": {"name": "domain1", "available_types": ["type1"]}}
        mock_filter_types.return_value = {"1": {"name": "domain1", "available_types": ["type1"]}}
        mock_fetch_path_info.return_value = {
            "type1": {"title": "Test", "short_remediation": "", "long_remediation": "", "short_description": ""}
        }
        mock_fetch_paths.return_value = ({}, {})
        mock_create.return_value = []

        demisto.setLastRun({})
        fetch_incidents(mock_client)
        mock_release.assert_called_once()

    @patch("SpecterOpsBHE.acquire_lock")
    def test_fetch_incidents_lock_not_acquired(self, mock_acquire, mock_client):
        """Test fetch_incidents when lock cannot be acquired"""
        mock_acquire.return_value = False
        fetch_incidents(mock_client)
        # Should return early without processing

    @patch("SpecterOpsBHE.release_lock")
    @patch("SpecterOpsBHE.get_available_domains")
    @patch("SpecterOpsBHE.acquire_lock")
    def test_fetch_incidents_domain_fetch_failure(self, mock_acquire, mock_get_domains, mock_release, mock_client):
        """Test fetch_incidents when domain fetch fails"""
        mock_acquire.return_value = True
        mock_get_domains.return_value = (False, None)
        fetch_incidents(mock_client)
        mock_release.assert_called_once()


class TestMainFunction:
    """Test cases for main function"""

    @patch("SpecterOpsBHE.return_results")
    @patch("SpecterOpsBHE.test_module")
    @patch("SpecterOpsBHE.demisto")
    def test_main_test_module(self, mock_demisto, mock_test_module, mock_return_results):
        """Test main function with test-module command"""
        mock_demisto.params.return_value = {
            "url": "test.bhe.example.com",
            "token_id": "test_id",
            "token_key": "test_key",
            "finding_domain": "all",
            "finding_category": "all",
            "incidentFetchInterval": 10,
        }
        mock_demisto.command.return_value = "test-module"
        mock_demisto.args.return_value = {}
        mock_test_module.return_value = "ok"

        SpecterOpsBHE.main()
        mock_test_module.assert_called_once()

    @patch("SpecterOpsBHE.return_results")
    @patch("SpecterOpsBHE.get_object_id")
    @patch("SpecterOpsBHE.demisto")
    def test_main_get_object_id(self, mock_demisto, mock_get_object_id, mock_return_results):
        """Test main function with bhe-get-object-id command"""
        mock_demisto.params.return_value = {
            "url": "test.bhe.example.com",
            "token_id": "test_id",
            "token_key": "test_key",
            "finding_domain": "all",
            "finding_category": "all",
        }
        mock_demisto.command.return_value = "bhe-get-object-id"
        mock_demisto.args.return_value = {"object_names": "test1,test2"}

        SpecterOpsBHE.main()
        mock_get_object_id.assert_called_once()

    @patch("SpecterOpsBHE.return_results")
    @patch("SpecterOpsBHE.fetch_asset_info")
    @patch("SpecterOpsBHE.demisto")
    def test_main_fetch_asset_info(self, mock_demisto, mock_fetch_asset_info, mock_return_results):
        """Test main function with bhe-fetch-asset-info command"""
        mock_demisto.params.return_value = {
            "url": "test.bhe.example.com",
            "token_id": "test_id",
            "token_key": "test_key",
            "finding_domain": "all",
            "finding_category": "all",
        }
        mock_demisto.command.return_value = "bhe-fetch-asset-info"
        mock_demisto.args.return_value = {"object_ids": "123,456"}

        SpecterOpsBHE.main()
        mock_fetch_asset_info.assert_called_once()

    @patch("SpecterOpsBHE.return_results")
    @patch("SpecterOpsBHE.does_path_exists_between_nodes")
    @patch("SpecterOpsBHE.demisto")
    def test_main_does_path_exist(self, mock_demisto, mock_does_path_exist, mock_return_results):
        """Test main function with bhe-does-path-exist command"""
        mock_demisto.params.return_value = {
            "url": "test.bhe.example.com",
            "token_id": "test_id",
            "token_key": "test_key",
            "finding_domain": "all",
            "finding_category": "all",
        }
        mock_demisto.command.return_value = "bhe-does-path-exist"
        mock_demisto.args.return_value = {"FromPrincipal": "node1", "ToPrincipal": "node2"}

        SpecterOpsBHE.main()
        mock_does_path_exist.assert_called_once()

    @patch("SpecterOpsBHE.return_results")
    @patch("SpecterOpsBHE.demisto")
    def test_main_does_path_exist_missing_args(self, mock_demisto, mock_return_results):
        """Test main function with bhe-does-path-exist missing arguments"""
        mock_demisto.params.return_value = {
            "url": "test.bhe.example.com",
            "token_id": "test_id",
            "token_key": "test_key",
            "finding_domain": "all",
            "finding_category": "all",
        }
        mock_demisto.command.return_value = "bhe-does-path-exist"
        mock_demisto.args.return_value = {}

        SpecterOpsBHE.main()
        mock_return_results.assert_called()

    @patch("SpecterOpsBHE.fetch_incidents")
    @patch("SpecterOpsBHE.demisto")
    def test_main_fetch_incidents(self, mock_demisto, mock_fetch_incidents):
        """Test main function with fetch-incidents command"""
        mock_demisto.params.return_value = {
            "url": "test.bhe.example.com",
            "token_id": "test_id",
            "token_key": "test_key",
            "finding_domain": "all",
            "finding_category": "all",
        }
        mock_demisto.command.return_value = "fetch-incidents"
        mock_demisto.args.return_value = {}

        SpecterOpsBHE.main()
        mock_fetch_incidents.assert_called_once()

    @patch("SpecterOpsBHE.return_error")
    @patch("SpecterOpsBHE.demisto")
    def test_main_unknown_command(self, mock_demisto, mock_return_error):
        """Test main function with unknown command"""
        mock_demisto.params.return_value = {
            "url": "test.bhe.example.com",
            "token_id": "test_id",
            "token_key": "test_key",
            "finding_domain": "all",
            "finding_category": "all",
        }
        mock_demisto.command.return_value = "unknown-command"
        mock_demisto.args.return_value = {}

        SpecterOpsBHE.main()
        mock_return_error.assert_called_once()


# Additional edge case tests


class TestEdgeCases:
    """Test cases for edge cases and error scenarios"""

    def test_extract_object_ids_none_values(self):
        """Test _extract_object_ids with None values"""
        item = {
            "FromPrincipalProps": {"objectid": None},
            "ToPrincipalProps": {"objectid": "id2"},
        }
        result = _extract_object_ids(item)
        assert "id2" in result
        assert None not in result

    def test_create_event_dict_missing_fields(self):
        """Test _create_event_dict with missing optional fields"""
        item = {
            "id": "attack123",
            "Severity": "low",
        }
        event = _create_event_dict(
            item,
            "test.domain.com",
            "Test Path",
            "finding1",
            "2024-01-01T00:00:00Z",
            "",
            "",
            "",
        )
        assert event["AttackId"] == "attack123"
        assert event["ImpactPercentage"] == 0.0

    @patch.object(Client, "_api_request")
    def test_handle_fetch_asset_information_memory_error(self, mock_api_request, mock_client):
        """Test _handle_fetch_asset_information with memory limitation error"""
        mock_api_request.side_effect = BloodHoundException("Memory limitation encountered")
        result = _handle_fetch_asset_information(mock_client, "123")
        assert result["status"] == "error"
        assert "memory" in result["message"].lower() or "limitation" in result["message"].lower()

    def test_filter_domains_empty_string(self):
        """Test filter_domains with empty string"""
        domains = {"1": {"name": "domain1"}}
        result = filter_domains(domains, "")
        assert result == domains

    def test_filter_finding_types_empty_string(self):
        """Test filter_finding_types with empty string"""
        domains = {"1": {"available_types": ["type1"]}}
        result = filter_finding_types(domains, "")
        assert result == domains

    @patch.object(Client, "_api_request")
    def test_fetch_primary_response_directory_type(self, mock_api_request, mock_client):
        """Test _fetch_primary_response with directory type"""
        from SpecterOpsBHE import _fetch_primary_response

        mock_api_request.return_value = {"data": {"name": "test", "type": "User"}}
        result = _fetch_primary_response(mock_client, "123", "User")
        assert result["data"]["name"] == "test"
        mock_api_request.assert_called_once()

    @patch.object(Client, "_api_request")
    def test_fetch_primary_response_azure_type(self, mock_api_request, mock_client):
        """Test _fetch_primary_response with Azure type"""
        from SpecterOpsBHE import _fetch_primary_response

        mock_api_request.return_value = {"data": {"name": "test", "type": "AZUser"}}
        result = _fetch_primary_response(mock_client, "123", "AZUser")
        assert result["data"]["name"] == "test"

    @patch.object(Client, "_api_request")
    def test_fetch_primary_response_base_type(self, mock_api_request, mock_client):
        """Test _fetch_primary_response with base type"""
        from SpecterOpsBHE import _fetch_primary_response

        mock_api_request.return_value = {"data": {"name": "test"}}
        result = _fetch_primary_response(mock_client, "123", "UnknownType")
        assert result["data"]["name"] == "test"

    @patch.object(Client, "_api_request")
    def test_handle_azure_types(self, mock_api_request, mock_client):
        """Test _handle_azure_types function"""
        from SpecterOpsBHE import _handle_azure_types

        primary_response = {"data": {}}
        mock_api_request.return_value = {"count": 5}
        _handle_azure_types(mock_client, "123", "AZUser", primary_response)
        # Should update primary_response with related counts
        assert mock_api_request.called

    @patch.object(Client, "_api_request")
    def test_process_az_tenant_timeout(self, mock_api_request, mock_client):
        """Test _process_az_tenant with timeout error"""
        mock_api_request.side_effect = requests.exceptions.Timeout("Timeout error")
        primary_response = {"data": {}}
        result = _process_az_tenant(mock_client, "123", primary_response)
        assert "Skipped" in result or "timeout" in result.lower()

    def test_create_event_dict_with_from_principal(self):
        """Test _create_event_dict with FromPrincipal"""
        item = {
            "id": "attack123",
            "Severity": "medium",
            "FromPrincipal": "from_principal",
            "FromPrincipalName": "from_name",
            "FromPrincipalKind": "User",
            "FromEnvironment": "Azure",
            "FromPrincipalProps": {"objectid": "from_id"},
            "ToPrincipalProps": {"objectid": "to_id", "name": "to_name"},
        }
        event = _create_event_dict(
            item,
            "test.domain.com",
            "Test Path",
            "finding1",
            "2024-01-01T00:00:00Z",
            "",
            "",
            "",
        )
        assert event["NonTierZeroPrincipal"] == "from_principal"
        assert event["NonTierZeroPrincipalName"] == "from_name"
        assert event["NonTierZeroPrincipalObjectId"] == "from_id"

    def test_create_incident_dict_severity_mapping(self):
        """Test _create_incident_dict with different severity levels"""
        event = {"AttackId": "attack123", "Domain": "test.domain.com", "Severity": "critical"}
        incident = _create_incident_dict(
            "TEST", "test.domain.com", "Test Path", event, "critical", "2024-01-01T00:00:00Z", "", ""
        )
        assert incident["severity"] == 4  # critical

        event["Severity"] = "low"
        incident = _create_incident_dict("TEST", "test.domain.com", "Test Path", event, "low", "2024-01-01T00:00:00Z", "", "")
        assert incident["severity"] == 1  # low

    @patch("SpecterOpsBHE.time.time")
    def test_acquire_lock_with_last_fetch(self, mock_time):
        """Test acquire_lock when last_fetch_time is recent"""
        mock_time.return_value = 1000.0
        SpecterOpsBHE.LOCK_TIMEOUT = 600
        demisto.setIntegrationContext({"last_fetch_time": "500.0"})  # Within timeout
        result = acquire_lock()
        assert result is False  # Should not acquire lock

    @patch("SpecterOpsBHE.time.time")
    def test_acquire_lock_after_timeout(self, mock_time):
        """Test acquire_lock when lock has timed out"""
        mock_time.return_value = 2000.0
        SpecterOpsBHE.LOCK_TIMEOUT = 600
        demisto.setIntegrationContext({"lock_time": "1000.0"})  # Lock expired
        result = acquire_lock()
        assert result is True  # Should acquire lock

    @patch.object(Client, "_api_request")
    def test_get_path_title_empty_response(self, mock_api_request, mock_client):
        """Test get_path_title with empty response"""
        mock_response = Mock()
        mock_response.text = ""
        mock_api_request.return_value = mock_response
        result = get_path_title(mock_client, "finding_type")
        assert result == ""

    @patch.object(Client, "_api_request")
    def test_get_path_title_exception(self, mock_api_request, mock_client):
        """Test get_path_title with exception"""
        mock_api_request.side_effect = Exception("API Error")
        result = get_path_title(mock_client, "finding_type")
        assert result == ""

    def test_extract_bhe_instance_with_port(self):
        """Test _extract_bhe_instance with port in URL"""
        result = _extract_bhe_instance("https://test.bhe.example.com:8080")
        assert result == "TEST"

    def test_group_attack_paths_by_domain_unknown_domain(self):
        """Test _group_attack_paths_by_domain with unknown domain"""
        attack_path_details = {("unknown", "finding1"): [{"id": "path1"}]}
        domains = {"domain1": {"name": "domain1.com"}}
        attack_paths_info = {"finding1": {"title": "Finding 1"}}
        result = _group_attack_paths_by_domain(attack_path_details, domains, attack_paths_info)
        assert "unknown" in result
