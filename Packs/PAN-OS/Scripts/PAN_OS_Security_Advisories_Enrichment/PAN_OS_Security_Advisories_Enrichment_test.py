import pytest
from unittest.mock import Mock
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
        assert "PAN_OS_Security_Advisories_Enrichment.Advisory" in result["EntryContext"]
        advisory = result["EntryContext"]["PAN_OS_Security_Advisories_Enrichment.Advisory"]

        # Assert specific advisory content
        assert advisory["cve_id"] == "CVE-2072-1234"
        assert advisory["title"] == "Sample CVE Title"
        assert advisory["description"] == "Sample CVE description for testing purposes"
        assert advisory["cvss_score"] == 7.5
        assert advisory["cvss_severity"] == "HIGH"
        assert advisory["external_cve_list"] == []  # Should be empty for non-PAN-SA

        # Verify client was called correctly
        mock_client.get_cve.assert_called_once_with(cve_id)
