import pytest
from unittest.mock import Mock, patch
from CommonServerPython import *

# Import the module under test
from PANOSSecurityAdvisoriesEnrichment import (
    Client,
    enrich_cve,
    flatten_advisory_dict,
    parse_version,
    sort_versions_and_changes,
    get_external_cves,
)


# Global fixtures that can be used across all test classes
@pytest.fixture
def mock_client():
    """Create a mock client for testing"""
    client = Mock(spec=Client)
    return client


@pytest.fixture
def sample_cve_data():
    """Sample CVE data response"""
    return {
        "cveMetadata": {"cveId": "CVE-2072-1234", "datePublished": "2023-01-15T00:00:00Z"},
        "containers": {
            "cna": {
                "title": "Sample CVE Title",
                "descriptions": [{"value": "Sample CVE description for testing purposes"}],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                        }
                    }
                ],
                "affected": [
                    {
                        "product": "PAN-OS",
                        "platforms": ["Panorama"],
                        "versions": [{"version": "10.0.0", "status": "affected", "lessThan": "10.0.5"}],
                    }
                ],
                "workarounds": [{"value": "Apply the latest updates"}],
                "solutions": [{"value": "Upgrade to the latest version"}],
                "providerMetadata": {"dateUpdated": "2023-01-20T00:00:00Z"},
            }
        },
    }


@pytest.fixture
def sample_pan_sa_data():
    """Sample PAN-SA CSAF data response"""
    return {
        "vulnerabilities": [
            {
                "cve": "CVE-2023-5678",
                "references": [{"category": "external", "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5678"}],
                "notes": [{"category": "description", "text": "External CVE description"}],
            }
        ]
    }


class TestClient:
    """Test class for the Client class"""

    def test_client_initialization(self):
        """Test client initialization with correct URLs"""
        client = Client()
        assert client.base_url == "https://security.paloaltonetworks.com"
        assert client.advisories_url == "https://security.paloaltonetworks.com/json/"
        assert client.csaf_url == "https://security.paloaltonetworks.com/csaf/"

    @patch("requests.get")
    def test_get_cve_success(self, mock_get):
        """Test successful CVE retrieval"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"cveId": "CVE-2023-1234"}
        mock_get.return_value = mock_response

        client = Client()
        result = client.get_cve("CVE-2023-1234")

        assert result == {"cveId": "CVE-2023-1234"}
        mock_get.assert_called_once_with("https://security.paloaltonetworks.com/json/CVE-2023-1234")

    @patch("PANOSSecurityAdvisoriesEnrichment.requests.get")
    def test_get_cve_error(self, mock_get):
        """Test error handling in get_cve"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"error": "no such entry"}
        mock_get.return_value = mock_response

        client = Client()
        result = client.get_cve("INVALID-CVE")

        # Verify that return_results was called with the expected message
        assert result == {"error": "no such entry"}
        mock_get.assert_called_once_with(f"{client.advisories_url}INVALID-CVE")

    @patch("requests.get")
    def test_get_pan_sa_advisories_success(self, mock_get):
        """Test successful PAN-SA advisory retrieval"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_get.return_value = mock_response

        client = Client()
        result = client.get_pan_sa_advisories("PAN-SA-2023-0001")

        assert result == {"vulnerabilities": []}

    @patch("requests.get")
    def test_get_pan_sa_advisories_404(self, mock_get):
        """Test 404 handling in get_pan_sa_advisories"""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        client = Client()
        result = client.get_pan_sa_advisories("PAN-SA-2023-0001")

        assert result == "CSAF not available for PAN-SA-2023-0001"


class TestEnrichCVE:
    """Test class for the enrich_cve function"""

    def test_enrich_cve_standard_cve(self, mock_client, sample_cve_data):
        """Test enriching a standard CVE (not PAN-SA)"""
        # Setup
        cve_id = "CVE-2072-1234"
        mock_client.get_cve.return_value = sample_cve_data

        # Execute
        result = enrich_cve(mock_client, cve_id)

        # Assert
        assert isinstance(result, dict)
        assert result["Type"] == entryTypes["note"]
        assert result["ContentsFormat"] == formats["json"]

        # Check EntryContext structure
        assert "PANOSSecurityAdvisories.Advisory" in result["EntryContext"]
        advisory = result["EntryContext"]["PANOSSecurityAdvisories.Advisory"]

        # Assert specific advisory content
        assert advisory["cve_id"] == "CVE-2072-1234"
        assert advisory["title"] == "Sample CVE Title"
        assert advisory["description"] == "Sample CVE description for testing purposes"
        assert advisory["cvss_score"] == 7.5
        assert advisory["cvss_severity"] == "HIGH"
        assert advisory["external_cve_list"] == []  # Should be empty for non-PAN-SA

        # Verify client was called correctly
        mock_client.get_cve.assert_called_once_with(cve_id)

    def test_enrich_cve_pan_sa_with_fixture(self, mock_client, sample_cve_data, sample_pan_sa_data):
        """Test enriching a PAN-SA CVE"""
        # Setup
        cve_id = "PAN-SA-2023-0001"

        mock_client.get_cve.return_value = sample_cve_data
        mock_client.get_pan_sa_advisories.return_value = sample_pan_sa_data

        # Execute
        result = enrich_cve(mock_client, cve_id)

        # Assert
        assert isinstance(result, dict)
        advisory = result["EntryContext"]["PANOSSecurityAdvisories.Advisory"]

        # Should contain the external CVE from sample_pan_sa_data
        assert len(advisory["external_cve_list"]) == 1
        assert advisory["external_cve_list"][0]["id"] == "CVE-2023-5678"
        assert advisory["external_cve_list"][0]["link"] == "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5678"
        assert advisory["external_cve_list"][0]["description"] == "External CVE description"

        # Verify both client methods were called
        mock_client.get_cve.assert_called_once_with(cve_id)
        mock_client.get_pan_sa_advisories.assert_called_once_with(cve_id)

    def test_enrich_cve_invalid_cve(self, mock_client):
        """Test handling of error when CVE not found"""
        cve_id = "CVE-2023-INVALID"
        mock_client.get_cve.side_effect = {"error": "no such entry"}

        result = enrich_cve(mock_client, cve_id)
        assert isinstance(result, dict)
        assert result["Contents"] == {"error": "This is not a valid Palo Alto Networks CVE ID"}


class TestVersionParsing:
    """Test class for version parsing functions"""

    @pytest.mark.parametrize(
        "version,expected",
        [
            ("10.0.0", (10, 0, 0, 0)),
            ("9.1.5-h1", (9, 1, 5, 1)),
            ("11.2.3-h10", (11, 2, 3, 10)),
            ("invalid-version", (0, 0, 0, 0)),
            ("", (0, 0, 0, 0)),
        ],
    )
    def test_parse_version(self, version, expected):
        """Test version parsing with various inputs"""
        result = parse_version(version)
        assert result == expected

    def test_sort_versions_and_changes(self):
        """Test sorting of versions and changes"""
        data = [
            {
                "versions": [
                    {"version": "10.0.0", "changes": [{"at": "10.0.5"}, {"at": "10.0.2"}]},
                    {"version": "9.1.0"},
                    {"version": "11.0.0"},
                ]
            }
        ]

        result = sort_versions_and_changes(data)

        # Should be sorted in descending order
        versions = result[0]["versions"]
        assert versions[0]["version"] == "11.0.0"
        assert versions[1]["version"] == "10.0.0"
        assert versions[2]["version"] == "9.1.0"


class TestFlattenAdvisoryDict:
    """Test class for flatten_advisory_dict function"""

    def test_flatten_advisory_dict_empty_data(self):
        """Test with empty or malformed data"""
        result = flatten_advisory_dict({}, [])
        assert result == {}

    def test_flatten_advisory_dict_missing_fields(self):
        """Test with missing optional fields"""
        minimal_data = {"cveMetadata": {"cveId": "CVE-2023-1234"}, "containers": {"cna": {}}}
        result = flatten_advisory_dict(minimal_data, [])

        assert result["cve_id"] == "CVE-2023-1234"
        assert result["title"] == ""
        assert result["description"] == ""
        assert result["cvss_score"] is None

    def test_flatten_advisory_dict_multiple_metrics(self):
        """Test with multiple CVSS metrics (should pick highest score)"""
        data_with_multiple_metrics = {
            "cveMetadata": {"cveId": "CVE-2023-1234"},
            "containers": {
                "cna": {
                    "metrics": [
                        {"cvssV3_1": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}},
                        {"cvssV3_1": {"baseScore": 9.0, "baseSeverity": "CRITICAL"}},
                        {"cvssV3_1": {"baseScore": 7.0, "baseSeverity": "HIGH"}},
                    ]
                }
            },
        }
        result = flatten_advisory_dict(data_with_multiple_metrics, [])

        assert result["cvss_score"] == 9.0
        assert result["cvss_severity"] == "CRITICAL"


class TestGetExternalCves:
    """Test class for get_external_cves function"""

    def test_get_external_cves_invalid_format(self, mock_client):
        """Test with invalid PAN-SA ID format"""
        with pytest.raises(ValueError, match="Invalid PAN-SA ID format"):
            get_external_cves(mock_client, "INVALID-FORMAT")

    def test_get_external_cves_csaf_not_available(self, mock_client):
        """Test when CSAF data is not available"""
        mock_client.get_pan_sa_advisories.return_value = "CSAF not available for PAN-SA-2023-0001"

        result = get_external_cves(mock_client, "PAN-SA-2023-0001")
        assert result == []

    def test_get_external_cves_no_vulnerabilities(self, mock_client):
        """Test with response containing no vulnerabilities"""
        mock_client.get_pan_sa_advisories.return_value = {"other_data": "value"}

        result = get_external_cves(mock_client, "PAN-SA-2023-0001")
        assert result == []

    def test_get_external_cves_incomplete_data(self, mock_client):
        """Test with incomplete vulnerability data"""
        incomplete_data = {
            "vulnerabilities": [
                {"cve": "CVE-2023-1234"},  # Missing references and notes
                {  # Missing CVE ID
                    "references": [{"category": "external", "url": "http://example.com"}],
                    "notes": [{"category": "description", "text": "Description"}],
                },
            ]
        }
        mock_client.get_pan_sa_advisories.return_value = incomplete_data

        result = get_external_cves(mock_client, "PAN-SA-2023-0001")
        assert result == []  # Should return empty list for incomplete data
