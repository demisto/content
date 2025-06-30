import pytest
from unittest.mock import Mock, patch
from CommonServerPython import *

# Import the module under test
from PANOSSecurityAdvisoriesEnrichment import Client, enrich_cve
class TestClient:
    """Test class for the Client class"""
    
    def test_client_initialization(self):
        """Test client initialization with correct URLs"""
        client = Client()
        assert client.base_url == "https://security.paloaltonetworks.com"
        assert client.advisories_url == "https://security.paloaltonetworks.com/json/"
        assert client.csaf_url == "https://security.paloaltonetworks.com/csaf/"

    @patch('requests.get')
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

    @patch('requests.get')
    def test_get_cve_404_error(self, mock_get):
        """Test 404 error handling in get_cve"""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        client = Client()
        with pytest.raises(DemistoException, match="CVE not found"):
            client.get_cve("INVALID-CVE")

    @patch('requests.get')
    def test_get_pan_sa_advisories_success(self, mock_get):
        """Test successful PAN-SA advisory retrieval"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_get.return_value = mock_response
        
        client = Client()
        result = client.get_pan_sa_advisories("PAN-SA-2023-0001")
        
        assert result == {"vulnerabilities": []}

    @patch('requests.get')
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

    @pytest.fixture
    def mock_client(self):
        """Create a mock client for testing"""
        client = Mock(spec=Client)
        return client

    @pytest.fixture
    def sample_cve_data(self):
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
    def sample_pan_sa_data(self):
        """Sample PAN-SA CSAF data response"""
        return {
            "vulnerabilities": [
                {
                    "cve": "CVE-2023-5678",
                    "references": [
                        {"category": "external", "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5678"}
                    ],
                    "notes": [{"category": "description", "text": "External CVE description"}],
                }
            ]
        }

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
        assert "PAN-OS_Security_Advisories.Advisory" in result["EntryContext"]
        advisory = result["EntryContext"]["PAN-OS_Security_Advisories.Advisory"]

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
        advisory = result["EntryContext"]["PAN-OS_Security_Advisories.Advisory"]

        # Should contain the external CVE from sample_pan_sa_data
        assert len(advisory["external_cve_list"]) == 1
        assert advisory["external_cve_list"][0]["id"] == "CVE-2023-5678"
        assert advisory["external_cve_list"][0]["link"] == "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5678"
        assert advisory["external_cve_list"][0]["description"] == "External CVE description"

        # Verify both client methods were called
        mock_client.get_cve.assert_called_once_with(cve_id)
        mock_client.get_pan_sa_advisories.assert_called_once_with(cve_id)

    def test_enrich_cve_404_error(self, mock_client):
        """Test handling of 404 error when CVE not found"""
        cve_id = "CVE-2023-INVALID"
        mock_client.get_cve.side_effect = DemistoException("CVE not found: This is not a valid Palo Alto Networks CVE ID.")
        
        with pytest.raises(DemistoException, match="CVE not found"):
            enrich_cve(mock_client, cve_id)

    