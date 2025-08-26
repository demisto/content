import pytest
from Unit42Intelligence import (
    Client,
    ip_command,
    domain_command,
    url_command,
    file_command,
    test_module,
    create_relationships,
    extract_response_data,
    create_context_data,
    create_dbot_score,
)
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
    """
    Given:
        - A Unit42Intelligence client
        - A mock API response with malicious verdict and threat objects
    When:
        - Running ip_command with create_relationships enabled
    Then:
        - Returns CommandResults with malicious verdict
        - Creates proper IP indicator with DBotScore
        - Extracts threat object names as tags
        - Creates relationships with threat actors and malware families
    """
    mock_response = {
        "indicator_value": "1.2.3.4",
        "indicator_type": "ip",
        "verdict": "malicious",
        "verdict_category": [{"value": "malware"}],
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "source": ["source1", "source2"],
        "counts": [],
        "threat_object_association": [
            {"name": "APT29", "threat_object_class": "actor"},
            {"name": "Cobalt Strike", "threat_object_class": "malware_family"},
        ],
    }

    mocker.patch.object(client, "lookup_indicator", return_value=mock_response)

    args = {"ip": "1.2.3.4", "create_relationships": True}
    result = ip_command(client, args)

    assert result.outputs["Value"] == "1.2.3.4"
    assert result.outputs["Verdict"] == "malicious"
    assert len(result.outputs["VerdictCategory"]) == 1
    assert result.indicator.ip == "1.2.3.4"
    assert result.indicator.dbot_score.score == Common.DBotScore.BAD
    assert result.indicator.dbot_score.malicious_description == "Unit 42 Intelligence classified this ip as malicious"


def test_domain_command_benign(client, mocker):
    """
    Given:
        - A Unit42Intelligence client
        - A mock API response with benign verdict and no threat objects
    When:
        - Running domain_command with create_relationships enabled
    Then:
        - Returns CommandResults with benign verdict
        - Creates proper Domain indicator with good DBotScore
        - No malicious description is set
    """
    mock_response = {
        "indicator_value": "example.com",
        "indicator_type": "domain",
        "verdict": "benign",
        "verdict_category": [{"value": "legitimate"}],
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "source": ["source1"],
        "counts": [],
        "threat_object_association": [],
    }

    mocker.patch.object(client, "lookup_indicator", return_value=mock_response)

    args = {"domain": "example.com", "create_relationships": True}
    result = domain_command(client, args)

    assert result.outputs["Value"] == "example.com"
    assert result.outputs["Verdict"] == "benign"
    assert result.indicator.domain == "example.com"
    assert result.indicator.dbot_score.score == Common.DBotScore.GOOD
    assert result.indicator.dbot_score.malicious_description is None


def test_url_command_suspicious(client, mocker):
    """
    Given:
        - A Unit42Intelligence client
        - A mock API response with suspicious verdict and campaign threat object
    When:
        - Running url_command with create_relationships enabled
    Then:
        - Returns CommandResults with suspicious verdict
        - Creates proper URL indicator with suspicious DBotScore
        - No malicious description is set for suspicious verdict
    """
    mock_response = {
        "indicator_value": "http://malicious.example.com",
        "indicator_type": "url",
        "verdict": "suspicious",
        "verdict_category": [{"value": "phishing"}],
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "source": ["source1"],
        "counts": [],
        "threat_object_association": [{"name": "Phishing Campaign 2023", "threat_object_class": "campaign"}],
    }

    mocker.patch.object(client, "lookup_indicator", return_value=mock_response)

    args = {"url": "http://malicious.example.com", "create_relationships": True}
    result = url_command(client, args)

    assert result.outputs["Value"] == "http://malicious.example.com"
    assert result.outputs["Verdict"] == "suspicious"
    assert result.indicator.url == "http://malicious.example.com"
    assert result.indicator.dbot_score.score == Common.DBotScore.SUSPICIOUS
    assert result.indicator.dbot_score.malicious_description is None


def test_file_command_malicious(client, mocker):
    """
    Given:
        - A Unit42Intelligence client
        - A mock API response with malicious verdict and malware family threat object
        - A SHA256 hash (64 characters)
    When:
        - Running file_command with create_relationships enabled
    Then:
        - Returns CommandResults with malicious verdict
        - Creates proper File indicator with SHA256 hash and bad DBotScore
        - Sets malicious description for file type
    """
    test_hash = "a" * 64  # SHA256 hash
    mock_response = {
        "indicator_value": test_hash,
        "indicator_type": "file",
        "verdict": "malicious",
        "verdict_category": [{"value": "trojan"}],
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "source": ["wildfire", "source2"],
        "counts": [],
        "threat_object_association": [{"name": "Zeus", "threat_object_class": "malware_family"}],
    }

    mocker.patch.object(client, "lookup_indicator", return_value=mock_response)
    args = {"file": test_hash, "create_relationships": True}
    result = file_command(client, args)

    assert result.outputs["Value"] == test_hash
    assert result.outputs["Verdict"] == "malicious"
    assert result.indicator.sha256 == test_hash
    assert result.indicator.dbot_score.score == Common.DBotScore.BAD
    assert result.indicator.dbot_score.malicious_description == "Unit 42 Intelligence classified this file as malicious"


def test_test_module_success(client, mocker):
    """
    Given:
        - A Unit42Intelligence client
        - A mock API response that succeeds
    When:
        - Running test_module function
    Then:
        - Returns 'ok' indicating successful connection
    """
    mock_response = {"verdict": "benign", "verdict_category": "legitimate"}

    mocker.patch.object(client, "lookup_indicator", return_value=mock_response)

    result = test_module(client)
    assert result == "ok"


def test_test_module_failure(client, mocker):
    """
    Given:
        - A Unit42Intelligence client
        - A mock API that raises an exception
    When:
        - Running test_module function
    Then:
        - Returns error message containing 'Test failed'
    """
    mocker.patch.object(client, "lookup_indicator", side_effect=Exception("API Error"))

    result = test_module(client)
    assert "Test failed" in result


def test_client_initialization():
    """
    Given:
        - Client configuration parameters
    When:
        - Initializing Unit42Intelligence Client
    Then:
        - Sets correct base URL, reliability, and authorization header
    """
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
    """
    Given:
        - An indicator with malicious verdict
    When:
        - Creating DBotScore using create_dbot_score function
    Then:
        - Returns DBotScore with BAD score and malicious description
    """
    dbot_score = create_dbot_score(
        indicator="1.2.3.4", indicator_type="ip", verdict="malicious", reliability="A - Completely reliable"
    )

    assert dbot_score.indicator == "1.2.3.4"
    assert dbot_score.indicator_type == "ip"
    assert dbot_score.score == Common.DBotScore.BAD
    assert dbot_score.malicious_description == "Unit 42 Intelligence classified this ip as malicious"
    assert dbot_score.reliability == "A - Completely reliable"


def test_create_dbot_score_benign():
    """
    Given:
        - An indicator with benign verdict
    When:
        - Creating DBotScore using create_dbot_score function
    Then:
        - Returns DBotScore with GOOD score and no malicious description
    """
    dbot_score = create_dbot_score(
        indicator="example.com", indicator_type="domain", verdict="benign", reliability="A - Completely reliable"
    )

    assert dbot_score.indicator == "example.com"
    assert dbot_score.indicator_type == "domain"
    assert dbot_score.score == Common.DBotScore.GOOD
    assert dbot_score.malicious_description is None
    assert dbot_score.reliability == "A - Completely reliable"


def test_create_dbot_score_suspicious():
    """
    Given:
        - An indicator with suspicious verdict
    When:
        - Creating DBotScore using create_dbot_score function
    Then:
        - Returns DBotScore with SUSPICIOUS score and no malicious description
    """
    dbot_score = create_dbot_score(
        indicator="suspicious.com", indicator_type="domain", verdict="suspicious", reliability="A - Completely reliable"
    )

    assert dbot_score.indicator == "suspicious.com"
    assert dbot_score.indicator_type == "domain"
    assert dbot_score.score == Common.DBotScore.SUSPICIOUS
    assert dbot_score.malicious_description is None
    assert dbot_score.reliability == "A - Completely reliable"


def test_create_dbot_score_unknown():
    """
    Given:
        - An indicator with unknown verdict
        - Reliability parameter
    When:
        - create_dbot_score is called
    Then:
        - Returns DBotScore with NONE score
        - No malicious description is set
        - Reliability is correctly assigned
    """
    dbot_score = create_dbot_score(
        indicator="unknown.com", indicator_type="domain", verdict="unknown", reliability="A - Completely reliable"
    )

    assert dbot_score.indicator == "unknown.com"
    assert dbot_score.indicator_type == "domain"
    assert dbot_score.score == Common.DBotScore.NONE
    assert dbot_score.malicious_description is None
    assert dbot_score.reliability == "A - Completely reliable"


def test_extract_response_data():
    """
    Given:
        - A mock API response with all fields present
    When:
        - extract_response_data is called
    Then:
        - Extracts all response fields correctly
        - Maps threat_object_association to threat_objects
        - Returns properly structured data dictionary
    """
    mock_response = {
        "indicator_value": "1.2.3.4",
        "indicator_type": "ip",
        "verdict": "malicious",
        "verdict_category": [{"value": "malware"}],
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "source": ["source1", "source2"],
        "counts": [1, 2, 3],
        "threat_object_association": [{"name": "APT29", "threat_object_class": "actor"}],
    }

    result = extract_response_data(mock_response)

    assert result["indicator_value"] == "1.2.3.4"
    assert result["indicator_type"] == "ip"
    assert result["verdict"] == "malicious"
    assert result["verdict_category"] == ["malware"]
    assert result["first_seen"] == "2023-01-01T00:00:00Z"
    assert result["last_seen"] == "2023-12-31T23:59:59Z"
    assert result["seen_by"] == ["source1", "source2"]
    assert result["counts"] == [1, 2, 3]
    assert len(result["relationships"]) == 1
    assert result["relationships"][0]["name"] == "APT29"


def test_create_context_data():
    """
    Given:
        - Indicator key, value, and response data with threat objects
    When:
        - create_context_data is called
    Then:
        - Creates context dictionary with proper structure
        - Extracts threat object names as tags
        - Maps all response fields correctly
    """
    response_data = {
        "indicator_value": "1.2.3.4",
        "indicator_type": "ip",
        "verdict": "malicious",
        "verdict_category": ["malware"],
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "seen_by": ["source1", "source2"],
        "counts": [1, 2, 3],
        "relationships": [
            {"name": "APT29", "threat_object_class": "actor"},
            {"name": "Cobalt Strike", "threat_object_class": "malware_family"},
        ],
    }

    result = create_context_data(response_data)

    assert result["Value"] == "1.2.3.4"
    assert result["Type"] == "ip"
    assert result["Verdict"] == "malicious"
    assert result["VerdictCategory"] == ["malware"]
    assert result["FirstSeen"] == "2023-01-01T00:00:00Z"
    assert result["LastSeen"] == "2023-12-31T23:59:59Z"
    assert result["SeenBy"] == ["source1", "source2"]
    assert result["Counts"] == [1, 2, 3]
    assert len(result["EnrichedThreatObjectAssociation"]) == 2
    assert result["EnrichedThreatObjectAssociation"][0]["name"] == "APT29"
    assert result["EnrichedThreatObjectAssociation"][1]["name"] == "Cobalt Strike"


def test_create_relationships_malware_family():
    """
    Given:
        - Threat objects with malware_family threat class
    When:
        - create_relationships is called with create_relationships enabled
    Then:
        - Creates relationship with FeedIndicatorType.Malware
        - Sets proper entity types and relationship name
    """
    threat_objects = [{"name": "Cobalt Strike", "threat_object_class": "malware_family"}]

    relationships = create_relationships("1.2.3.4", FeedIndicatorType.IP, threat_objects, True)

    assert len(relationships) == 1
    assert relationships[0]._entity_a == "1.2.3.4"
    assert relationships[0]._entity_a_type == FeedIndicatorType.IP
    assert relationships[0]._entity_b == "Cobalt Strike"
    assert relationships[0]._entity_b_type == ThreatIntel.ObjectsNames.MALWARE
    assert relationships[0]._name == EntityRelationship.Relationships.RELATED_TO


def test_create_relationships_actor():
    """
    Given:
        - Threat objects with actor threat class
    When:
        - create_relationships is called with create_relationships enabled
    Then:
        - Creates relationship with FeedIndicatorType.ThreatActor
        - Sets proper entity types and relationship name
    """
    threat_objects = [{"name": "APT29", "threat_object_class": "actor"}]

    relationships = create_relationships("example.com", FeedIndicatorType.Domain, threat_objects, True)

    assert len(relationships) == 1
    assert relationships[0]._entity_a == "example.com"
    assert relationships[0]._entity_a_type == FeedIndicatorType.Domain
    assert relationships[0]._entity_b == "APT29"
    assert relationships[0]._entity_b_type == ThreatIntel.ObjectsNames.THREAT_ACTOR
    assert relationships[0]._name == EntityRelationship.Relationships.RELATED_TO


def test_create_relationships_campaign():
    """
    Given:
        - Threat objects with campaign threat class
    When:
        - create_relationships is called with create_relationships enabled
    Then:
        - Creates relationship with FeedIndicatorType.Campaign
        - Sets proper entity types and relationship name
    """
    threat_objects = [{"name": "Operation XYZ", "threat_object_class": "campaign"}]

    relationships = create_relationships("malicious.com", FeedIndicatorType.URL, threat_objects, True)

    assert len(relationships) == 1
    assert relationships[0]._entity_a == "malicious.com"
    assert relationships[0]._entity_a_type == FeedIndicatorType.URL
    assert relationships[0]._entity_b == "Operation XYZ"
    assert relationships[0]._entity_b_type == ThreatIntel.ObjectsNames.CAMPAIGN
    assert relationships[0]._name == EntityRelationship.Relationships.RELATED_TO


def test_create_relationships_attack_patterns():
    """
    Given:
        - Threat objects with various attack pattern threat classes (malicious_behavior, exploit, etc.)
    When:
        - create_relationships is called with create_relationships enabled
    Then:
        - Creates relationships with FeedIndicatorType.AttackPattern for all
        - Maps different attack pattern classes to same indicator type
    """
    threat_objects = [
        {"name": "Spear Phishing", "threat_object_class": "malicious_behavior"},
        {"name": "CVE-2023-1234", "threat_object_class": "exploit"},
        {"name": "Data Exfiltration", "threat_object_class": "malicious behavior"},
        {"name": "T1566", "threat_object_class": "attack pattern"},
    ]

    relationships = create_relationships("hash123", FeedIndicatorType.File, threat_objects, True)

    assert len(relationships) == 4
    for relationship in relationships:
        assert relationship._entity_a == "hash123"
        assert relationship._entity_a_type == FeedIndicatorType.File
        assert relationship._entity_b_type == ThreatIntel.ObjectsNames.ATTACK_PATTERN
        assert relationship._name == EntityRelationship.Relationships.RELATED_TO


def test_create_relationships_disabled():
    """
    Given:
        - Valid threat objects with actor threat class
        - create_relationships parameter set to False
    When:
        - create_relationships is called with create_relationships disabled
    Then:
        - Returns an empty list of relationships
        - No relationships are created regardless of threat objects
    """
    threat_objects = [{"name": "APT29", "threat_object_class": "actor"}]

    relationships = create_relationships("1.2.3.4", FeedIndicatorType.IP, threat_objects, False)

    assert len(relationships) == 0


def test_create_relationships_empty_threat_objects():
    """
    Given:
        - An empty list of threat objects
    When:
        - create_relationships is called with create_relationships enabled
    Then:
        - Returns an empty list of relationships
    """
    threat_objects = []

    relationships = create_relationships("1.2.3.4", FeedIndicatorType.IP, threat_objects, True)

    assert len(relationships) == 0


def test_create_relationships_unknown_threat_class():
    """
    Given:
        - Threat objects with one unknown threat class and one known threat class
    When:
        - create_relationships is called with create_relationships enabled
    Then:
        - Only creates relationships for known threat classes
        - Skips unknown threat classes
    """
    threat_objects = [
        {"name": "Unknown Threat", "threat_object_class": "unknown_class"},
        {"name": "APT29", "threat_object_class": "actor"},  # This should still work
    ]

    relationships = create_relationships("1.2.3.4", FeedIndicatorType.IP, threat_objects, True)

    # Only the known threat class should create a relationship
    assert len(relationships) == 1
    assert relationships[0]._entity_b == "APT29"
    assert relationships[0]._entity_b_type == ThreatIntel.ObjectsNames.THREAT_ACTOR


def test_create_relationships_missing_name():
    """
    Given:
        - Threat objects where one has missing name and one has valid name
    When:
        - create_relationships is called with create_relationships enabled
    Then:
        - Only creates relationships for threat objects with valid names
        - Skips threat objects with missing names
    """
    threat_objects = [
        {"threat_object_class": "actor"},  # Missing name
        {"name": "APT29", "threat_object_class": "actor"},  # This should still work
    ]

    relationships = create_relationships("1.2.3.4", FeedIndicatorType.IP, threat_objects, True)

    # Only the threat object with name should create a relationship
    assert len(relationships) == 1
    assert relationships[0]._entity_b == "APT29"


def test_file_hash_detection():
    """
    Given:
        - Different hash types (MD5, SHA1, SHA256) with their respective lengths
        - Mock API responses for each hash type
    When:
        - file_command is called with each hash type
    Then:
        - Correctly identifies and processes each hash type
        - Returns appropriate CommandResults for each hash
    """
    # Test different hash lengths
    md5_hash = "a" * 32
    sha1_hash = "b" * 40
    sha256_hash = "c" * 64

    # Mock response
    mock_response = {
        "indicator_value": "test_hash",
        "indicator_type": "file",
        "verdict": "benign",
        "verdict_category": [{"value": "clean"}],
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "source": ["source1"],
        "counts": [],
        "threat_object_association": [],
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


def test_multiple_threat_objects():
    """
    Given:
        - Multiple threat objects of different types (actor, malware, campaign)
    When:
        - create_relationships is called with create_relationships enabled
    Then:
        - Creates relationships for all threat objects
        - Maps each threat class to correct FeedIndicatorType
        - Returns list with all relationships
    """
    threat_objects = [
        {"name": "APT29", "threat_object_class": "actor"},
        {"name": "Cobalt Strike", "threat_object_class": "malware_family"},
        {"name": "Operation Ghost", "threat_object_class": "campaign"},
        {"name": "Spear Phishing", "threat_object_class": "malicious_behavior"},
    ]

    relationships = create_relationships("1.2.3.4", FeedIndicatorType.IP, threat_objects, True)

    assert len(relationships) == 4

    # Check each relationship type
    entity_b_types = [rel._entity_b_type for rel in relationships]
    assert ThreatIntel.ObjectsNames.THREAT_ACTOR in entity_b_types
    assert ThreatIntel.ObjectsNames.MALWARE in entity_b_types
    assert ThreatIntel.ObjectsNames.CAMPAIGN in entity_b_types
    assert ThreatIntel.ObjectsNames.ATTACK_PATTERN in entity_b_types


def test_extract_response_data_missing_fields():
    """
    Given:
        - A mock API response with only required fields (missing optional fields)
    When:
        - extract_response_data is called
    Then:
        - Uses default values for missing fields
        - Returns properly structured data with empty defaults
        - Handles missing threat_object_association gracefully
    """
    mock_response = {
        "verdict": "unknown",
        # Missing other fields
    }

    result = extract_response_data(mock_response)

    assert result["verdict"] == "unknown"
    assert result["indicator_value"] == ""
    assert result["indicator_type"] == ""
    assert result["verdict_category"] == []
    assert result["first_seen"] == ""
    assert result["last_seen"] == ""
    assert result["seen_by"] == []
    assert result["counts"] == []
    assert result["relationships"] == []


def test_create_context_data_empty_threat_objects():
    """
    Given:
        - Response data with empty threat objects list
    When:
        - create_context_data is called
    Then:
        - Creates context dictionary with empty relationships list
        - All other fields are properly mapped
        - No errors occur with empty relationships
    """
    response_data = {
        "indicator_value": "1.2.3.4",
        "indicator_type": "ip",
        "verdict": "benign",
        "verdict_category": ["legitimate"],
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "seen_by": ["source1"],
        "counts": [],
        "relationships": [],
    }

    result = create_context_data(response_data)

    assert result["Value"] == "1.2.3.4"
    assert result["Type"] == "ip"
    assert result["Verdict"] == "benign"
    assert result["VerdictCategory"] == ["legitimate"]
    assert result["EnrichedThreatObjectAssociation"] == []
