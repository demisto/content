import pytest
from unittest.mock import Mock, patch
from CommonServerPython import *

# Import the module under test
from PAN_OS_Security_Advisories_Enrichment import Client, enrich_cve


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
                        {
                            "category": "external",
                            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5678"
                        }
                    ],
                    "notes": [
                        {
                            "category": "description",
                            "text": "External CVE description"
                        }
                    ]
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