import pytest
from Unit42Intelligence import Client, ip_command, domain_command, url_command, file_command, test_module
from CommonServerPython import *


class MockResponse:
    def __init__(self, json_data, status_code=200):
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        return self.json_data


@pytest.fixture
def client():
    return Client(
        base_url="https://api.unit42.paloaltonetworks.com",
        api_key="test_api_key",
        verify=True,
        proxy=False,
        reliability="A - Completely reliable",
    )


def test_ip_command_malicious(client, mocker):
    """Test IP command with malicious verdict"""
    mock_response = {
        "verdict": "malicious",
        "verdict_category": "malware",
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "seen_by": ["source1", "source2"],
        "enriched_threat_object_association": [
            {"name": "APT29", "type": "threat_actor"},
            {"name": "Cobalt Strike", "type": "malware_family"},
        ],
    }

    mocker.patch.object(client, "lookup_indicator", return_value=mock_response)

    args = {"ip": "1.2.3.4", "create_relationships": True}
    result = ip_command(client, args)

    assert result.outputs["Address"] == "1.2.3.4"
    assert result.outputs["Verdict"] == "malicious"
    assert len(result.outputs["Tags"]) == 2
    assert result.indicator.ip == "1.2.3.4"
    assert result.indicator.dbot_score.score == Common.DBotScore.BAD
    assert result.indicator.dbot_score.malicious_description == "Unit 42 Intelligence classified this ip as malicious"


def test_domain_command_benign(client, mocker):
    """Test domain command with benign verdict"""
    mock_response = {
        "verdict": "benign",
        "verdict_category": "legitimate",
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "seen_by": ["source1"],
        "enriched_threat_object_association": [],
    }

    mocker.patch.object(client, "lookup_indicator", return_value=mock_response)

    args = {"domain": "example.com", "create_relationships": True}
    result = domain_command(client, args)

    assert result.outputs["Name"] == "example.com"
    assert result.outputs["Verdict"] == "benign"
    assert result.indicator.domain == "example.com"
    assert result.indicator.dbot_score.score == Common.DBotScore.GOOD
    assert result.indicator.dbot_score.malicious_description is None


def test_url_command_suspicious(client, mocker):
    """Test URL command with suspicious verdict"""
    mock_response = {
        "verdict": "suspicious",
        "verdict_category": "phishing",
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "seen_by": ["source1"],
        "enriched_threat_object_association": [{"name": "Phishing Campaign 2023", "type": "campaign"}],
    }

    mocker.patch.object(client, "lookup_indicator", return_value=mock_response)

    args = {"url": "http://malicious.example.com", "create_relationships": True}
    result = url_command(client, args)

    assert result.outputs["Data"] == "http://malicious.example.com"
    assert result.outputs["Verdict"] == "suspicious"
    assert result.indicator.url == "http://malicious.example.com"
    assert result.indicator.dbot_score.score == Common.DBotScore.SUSPICIOUS
    assert result.indicator.dbot_score.malicious_description is None


def test_file_command_malicious(client, mocker):
    """Test file command with malicious verdict"""
    mock_response = {
        "verdict": "malicious",
        "verdict_category": "trojan",
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "seen_by": ["wildfire", "source2"],
        "enriched_threat_object_association": [{"name": "Zeus", "type": "malware_family"}],
    }

    mocker.patch.object(client, "lookup_indicator", return_value=mock_response)

    test_hash = "a" * 64  # SHA256 hash
    args = {"file": test_hash, "create_relationships": True}
    result = file_command(client, args)

    assert result.outputs["Hash"] == test_hash
    assert result.outputs["Verdict"] == "malicious"
    assert result.indicator.sha256 == test_hash
    assert result.indicator.dbot_score.score == Common.DBotScore.BAD
    assert result.indicator.dbot_score.malicious_description == "Unit 42 Intelligence classified this file as malicious"


def test_test_module_success(client, mocker):
    """Test the test-module command success"""
    mock_response = {"verdict": "benign", "verdict_category": "legitimate"}

    mocker.patch.object(client, "lookup_indicator", return_value=mock_response)

    result = test_module(client)
    assert result == "ok"


def test_test_module_failure(client, mocker):
    """Test the test-module command failure"""
    mocker.patch.object(client, "lookup_indicator", side_effect=Exception("API Error"))

    result = test_module(client)
    assert "Test failed" in result


def test_client_initialization():
    """Test client initialization"""
    client = Client(
        base_url="https://api.unit42.paloaltonetworks.com",
        api_key="test_key",
        verify=True,
        proxy=False,
        reliability="B - Usually reliable",
    )

    assert client._base_url == "https://api.unit42.paloaltonetworks.com"
    assert client.reliability == "B - Usually reliable"
    assert "Bearer test_key" in client._headers["Authorization"]


def test_create_dbot_score_malicious():
    """Test DBotScore creation with malicious verdict"""
    from Unit42Intelligence import create_dbot_score

    dbot_score = create_dbot_score(
        indicator="1.2.3.4", indicator_type="ip", verdict="malicious", reliability="A - Completely reliable"
    )

    assert dbot_score.indicator == "1.2.3.4"
    assert dbot_score.indicator_type == "ip"
    assert dbot_score.score == Common.DBotScore.BAD
    assert dbot_score.malicious_description == "Unit 42 Intelligence classified this ip as malicious"
    assert dbot_score.reliability == "A - Completely reliable"


def test_create_dbot_score_benign():
    """Test DBotScore creation with benign verdict"""
    from Unit42Intelligence import create_dbot_score

    dbot_score = create_dbot_score(
        indicator="example.com", indicator_type="domain", verdict="benign", reliability="A - Completely reliable"
    )

    assert dbot_score.indicator == "example.com"
    assert dbot_score.indicator_type == "domain"
    assert dbot_score.score == Common.DBotScore.GOOD
    assert dbot_score.malicious_description is None
    assert dbot_score.reliability == "A - Completely reliable"


def test_extract_response_data():
    """Test response data extraction"""
    from Unit42Intelligence import extract_response_data

    mock_response = {
        "verdict": "malicious",
        "verdict_category": "malware",
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "seen_by": ["source1", "source2"],
        "enriched_threat_object_association": [{"name": "APT29", "type": "threat_actor"}],
    }

    result = extract_response_data(mock_response)

    assert result["verdict"] == "malicious"
    assert result["verdict_category"] == "malware"
    assert result["first_seen"] == "2023-01-01T00:00:00Z"
    assert result["last_seen"] == "2023-12-31T23:59:59Z"
    assert result["seen_by"] == ["source1", "source2"]
    assert len(result["tags"]) == 1
    assert result["tags"][0]["name"] == "APT29"


def test_create_context_data():
    """Test context data creation with updated parameter order"""
    from Unit42Intelligence import create_context_data

    response_data = {
        "verdict": "malicious",
        "verdict_category": "malware",
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "seen_by": ["source1", "source2"],
        "tags": [{"name": "APT29", "type": "threat_actor"}, {"name": "Cobalt Strike", "type": "malware_family"}],
    }

    # Test with IP indicator (Address key)
    result = create_context_data("Address", "1.2.3.4", response_data)

    assert result["Address"] == "1.2.3.4"
    assert result["Verdict"] == "malicious"
    assert result["VerdictCategory"] == "malware"
    assert result["FirstSeen"] == "2023-01-01T00:00:00Z"
    assert result["LastSeen"] == "2023-12-31T23:59:59Z"
    assert result["SeenBy"] == ["source1", "source2"]
    assert len(result["Tags"]) == 2
    assert result["Tags"][0] == "APT29"
    assert result["Tags"][1] == "Cobalt Strike"

    # Test with Domain indicator (Name key)
    result = create_context_data("Name", "example.com", response_data)
    assert result["Name"] == "example.com"
    assert result["Verdict"] == "malicious"

    # Test with URL indicator (Data key)
    result = create_context_data("Data", "http://malicious.com", response_data)
    assert result["Data"] == "http://malicious.com"
    assert result["Verdict"] == "malicious"

    # Test with File indicator (Hash key)
    test_hash = "a" * 64
    result = create_context_data("Hash", test_hash, response_data)
    assert result["Hash"] == test_hash
    assert result["Verdict"] == "malicious"


def test_file_hash_detection():
    """Test file hash type detection"""
    from Unit42Intelligence import file_command

    # Test different hash lengths
    md5_hash = "a" * 32
    sha1_hash = "b" * 40
    sha256_hash = "c" * 64

    # Mock response
    mock_response = {
        "verdict": "benign",
        "verdict_category": "clean",
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "seen_by": ["source1"],
        "enriched_threat_object_association": [],
    }

    client = Client(
        base_url="https://api.unit42.paloaltonetworks.com",
        api_key="test_key",
        verify=True,
        proxy=False,
        reliability="A - Completely reliable",
    )

    # Test MD5
    import unittest.mock

    with unittest.mock.patch.object(client, "lookup_indicator", return_value=mock_response):
        args = {"file": md5_hash, "create_relationships": True}
        result = file_command(client, args)
        assert result.indicator.md5 == md5_hash
        assert result.indicator.sha1 is None
        assert result.indicator.sha256 is None

    # Test SHA1
    with unittest.mock.patch.object(client, "lookup_indicator", return_value=mock_response):
        args = {"file": sha1_hash, "create_relationships": True}
        result = file_command(client, args)
        assert result.indicator.md5 is None
        assert result.indicator.sha1 == sha1_hash
        assert result.indicator.sha256 is None

    # Test SHA256
    with unittest.mock.patch.object(client, "lookup_indicator", return_value=mock_response):
        args = {"file": sha256_hash, "create_relationships": True}
        result = file_command(client, args)
        assert result.indicator.md5 is None
        assert result.indicator.sha1 is None
        assert result.indicator.sha256 == sha256_hash
