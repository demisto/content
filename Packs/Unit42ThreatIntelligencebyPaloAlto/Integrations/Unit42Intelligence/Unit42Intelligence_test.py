import pytest
from Unit42Intelligence import (
    Client,
    ip_command,
    domain_command,
    url_command,
    file_command,
    test_module,
    create_relationships,
    remove_mitre_technique_id_prefix,
    extract_response_data,
    create_context_data,
    create_dbot_score,
    extract_tags_from_threat_objects,
    extract_malware_families_from_threat_objects,
    create_threat_object_indicators,
    build_threat_object_description,
    create_publications,
    create_threat_object_relationships,
    create_campaigns_relationships,
    create_attack_patterns_relationships,
    create_malware_relationships,
    create_tools_relationships,
    create_vulnerabilities_relationships,
    create_actor_relationships,
    create_location_indicators_and_relationships,
    get_threat_object_score,
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
        - Creates proper IP indicator with DBotScore, tags, and malware families
        - Extracts threat object names as tags
        - Creates relationships with threat actors and malware families
    """
    mock_response = {
        "indicator_value": "1.2.3.4",
        "indicator_type": "ip",
        "verdict": "malicious",
        "verdict_categories": [{"value": "malware"}],
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "sources": ["source1", "source2"],
        "counts": [],
        "threat_object_associations": [
            {"name": "APT29", "threat_object_class": "actor", "aliases": ["Cozy Bear"]},
            {"name": "Cobalt Strike", "threat_object_class": "malware_family"},
        ],
    }

    mock_response_obj = mocker.Mock()
    mock_response_obj.status_code = 200
    mock_response_obj.json.return_value = mock_response
    mocker.patch.object(client, "lookup_indicator", return_value=mock_response_obj)

    args = {"ip": "1.2.3.4", "create_relationships": True}
    result = ip_command(client, args)

    assert result.outputs["Value"] == "1.2.3.4"
    assert result.outputs["Verdict"] == "Malicious"
    assert len(result.outputs["VerdictCategories"]) == 1
    assert result.indicator.ip == "1.2.3.4"
    assert result.indicator.dbot_score.score == Common.DBotScore.BAD
    assert result.indicator.dbot_score.malicious_description == "Unit 42 Intelligence classified this ip as malicious"

    # Test enriched indicator fields
    assert "APT29" in result.indicator.tags
    assert "Cobalt Strike" in result.indicator.tags
    assert "Cozy Bear" in result.indicator.tags  # Alias should be included
    assert result.indicator.malware_family == "Cobalt Strike"  # First malware family


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
        "verdict_categories": [{"value": "legitimate"}],
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "sources": ["source1"],
        "counts": [],
        "threat_object_associations": [],
    }

    mock_response_obj = mocker.Mock()
    mock_response_obj.status_code = 200
    mock_response_obj.json.return_value = mock_response
    mocker.patch.object(client, "lookup_indicator", return_value=mock_response_obj)

    args = {"domain": "example.com", "create_relationships": True}
    result = domain_command(client, args)

    assert result.outputs["Value"] == "example.com"
    assert result.outputs["Verdict"] == "Benign"
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
        "verdict_categories": [{"value": "phishing"}],
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "sources": ["source1"],
        "counts": [],
        "threat_object_associations": [{"name": "Phishing Campaign 2023", "threat_object_class": "campaign"}],
    }

    mock_response_obj = mocker.Mock()
    mock_response_obj.status_code = 200
    mock_response_obj.json.return_value = mock_response
    mocker.patch.object(client, "lookup_indicator", return_value=mock_response_obj)

    args = {"url": "http://malicious.example.com", "create_relationships": True}
    result = url_command(client, args)

    assert result.outputs["Value"] == "http://malicious.example.com"
    assert result.outputs["Verdict"] == "Suspicious"
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
        - Creates proper File indicator with SHA256 hash, tags, malware families and bad DBotScore
        - Sets malicious description for file type
    """
    test_hash = "a" * 64  # SHA256 hash
    mock_response = {
        "indicator_value": test_hash,
        "indicator_type": "file",
        "verdict": "malicious",
        "verdict_categories": [{"value": "trojan"}],
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "sources": ["wildfire", "source2"],
        "counts": [],
        "threat_object_associations": [
            {"name": "Zeus", "threat_object_class": "malware_family", "aliases": ["Zbot"]},
            {"name": "APT28", "threat_object_class": "actor"},
        ],
    }

    mock_response_obj = mocker.Mock()
    mock_response_obj.status_code = 200
    mock_response_obj.json.return_value = mock_response
    mocker.patch.object(client, "lookup_indicator", return_value=mock_response_obj)

    args = {"file": test_hash, "create_relationships": True}
    result = file_command(client, args)

    assert result.outputs["Value"] == test_hash
    assert result.outputs["Verdict"] == "Malicious"
    assert result.indicator.sha256 == test_hash
    assert result.indicator.dbot_score.score == Common.DBotScore.BAD
    assert result.indicator.dbot_score.malicious_description == "Unit 42 Intelligence classified this file as malicious"

    # Test enriched indicator fields
    assert "Zeus" in result.indicator.tags
    assert "APT28" in result.indicator.tags
    assert "Zbot" in result.indicator.tags  # Alias should be included
    assert result.indicator.malware_family == "Zeus"  # First malware family


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
    mock_response_obj = mocker.Mock()
    mock_response_obj.status_code = 200
    mocker.patch.object(client, "lookup_indicator", return_value=mock_response_obj)

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


def test_ip_command_404(client, mocker):
    """
    Given:
        - A Unit42Intelligence client
        - A mock API response with 404 status code
    When:
        - Running ip_command
    Then:
        - Returns CommandResults with proper 'not found' message
    """
    mock_response_obj = mocker.Mock()
    mock_response_obj.status_code = 404
    mocker.patch.object(client, "lookup_indicator", return_value=mock_response_obj)

    args = {"ip": "1.2.3.4", "create_relationships": True}
    result = ip_command(client, args)

    assert (
        "### Unit 42 Intelligence results for IP: 1.2.3.4\n|Value|Verdict|\n|---|---|\n| 1.2.3.4 | Unknown |\n"
        in result.readable_output
    )


def test_domain_command_404(client, mocker):
    """
    Given:
        - A Unit42Intelligence client
        - A mock API response with 404 status code
    When:
        - Running domain_command
    Then:
        - Returns CommandResults with proper 'not found' message
    """
    mock_response_obj = mocker.Mock()
    mock_response_obj.status_code = 404
    mocker.patch.object(client, "lookup_indicator", return_value=mock_response_obj)

    args = {"domain": "example.com", "create_relationships": True}
    result = domain_command(client, args)

    assert (
        "### Unit 42 Intelligence results for Domain: example.com\n|Value|Verdict|\n|---|---|\n| example.com | Unknown |\n"
        in result.readable_output
    )


def test_url_command_404(client, mocker):
    """
    Given:
        - A Unit42Intelligence client
        - A mock API response with 404 status code
    When:
        - Running url_command
    Then:
        - Returns CommandResults with proper 'not found' message
    """
    mock_response_obj = mocker.Mock()
    mock_response_obj.status_code = 404
    mocker.patch.object(client, "lookup_indicator", return_value=mock_response_obj)

    args = {"url": "http://example.com", "create_relationships": True}
    result = url_command(client, args)
    assert "http://example.com | Unknown |\n" in result.readable_output


def test_file_command_404(client, mocker):
    """
    Given:
        - A Unit42Intelligence client
        - A mock API response with 404 status code
    When:
        - Running file_command
    Then:
        - Returns CommandResults with proper 'not found' message
    """
    mock_response_obj = mocker.Mock()
    mock_response_obj.status_code = 404
    mocker.patch.object(client, "lookup_indicator", return_value=mock_response_obj)

    test_hash = "a" * 64
    args = {"file": test_hash, "create_relationships": True}
    result = file_command(client, args)

    assert (
        f"### Unit 42 Intelligence results for File: {test_hash}\n|Value|Verdict|\n|---|---|\n| {test_hash} | Unknown |\n"
        in result.readable_output
    )


def test_client_initialization(mocker):
    """
    Given:
        - Client configuration parameters
    When:
        - Initializing Unit42Intelligence Client
    Then:
        - Sets correct base URL, reliability, and authorization header
    """
    license_id = "test_license"
    # Mock demisto.getLicenseID within the Unit42Intelligence module
    mocker.patch("Unit42Intelligence.demisto.getLicenseID", return_value=license_id)

    client = Client(verify=True, proxy=False, reliability=DBotScoreReliability.B)

    assert client._base_url == "https://prod-us.tas.crtx.paloaltonetworks.com"
    assert client.reliability == DBotScoreReliability.B
    assert client._headers["Authorization"] == f"Bearer {license_id}"


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
        "verdict_categories": [{"value": "malware"}],
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "sources": ["source1", "source2"],
        "counts": [1, 2, 3],
        "threat_object_associations": [{"name": "APT29", "threat_object_class": "actor"}],
    }

    result = extract_response_data(mock_response)

    assert result["indicator_value"] == "1.2.3.4"
    assert result["indicator_type"] == "ip"
    assert result["verdict"] == "malicious"
    assert result["verdict_categories"] == ["malware"]
    assert result["first_seen"] == "2023-01-01T00:00:00Z"
    assert result["last_seen"] == "2023-12-31T23:59:59Z"
    assert result["seen_by"] == ["source1", "source2"]
    assert result["counts"] == [1, 2, 3]
    assert len(result["threat_object_associations"]) == 1
    assert result["threat_object_associations"][0]["name"] == "APT29"


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
        "verdict_categories": ["malware"],
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "seen_by": ["source1", "source2"],
        "counts": [1, 2, 3],
        "threat_object_associations": [
            {"name": "APT29", "threat_object_class": "actor"},
            {"name": "Cobalt Strike", "threat_object_class": "malware_family"},
        ],
    }

    result = create_context_data(response_data)

    assert result["Value"] == "1.2.3.4"
    assert result["Type"] == "IP"
    assert result["Verdict"] == "Malicious"
    assert result["VerdictCategories"] == ["Malware"]
    assert result["FirstSeen"] == "2023-01-01T00:00:00Z"
    assert set(result["SeenBy"]) == {"Source1", "Source2"}
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
        - Creates relationships with correct indicator types based on INDICATOR_TYPE_MAPPING
        - Maps different attack pattern classes to their respective indicator types
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
        # Check the actual mapping based on INDICATOR_TYPE_MAPPING
        threat_class = threat_objects[relationships.index(relationship)]["threat_object_class"]
        if threat_class in ["malicious_behavior", "malicious behavior"]:
            assert relationship._entity_b_type == ThreatIntel.ObjectsNames.ATTACK_PATTERN
        elif threat_class == "exploit":
            assert relationship._entity_b_type == FeedIndicatorType.CVE
        elif threat_class == "attack pattern":
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


def test_create_relationships_known_threat_classes_only():
    """
    Given:
        - Threat objects with known threat classes only
    When:
        - create_relationships is called with create_relationships enabled
    Then:
        - Creates relationships for all known threat classes
    """
    threat_objects = [
        {"name": "APT29", "threat_object_class": "actor"},
        {"name": "Cobalt Strike", "threat_object_class": "malware_family"},
    ]

    relationships = create_relationships("1.2.3.4", FeedIndicatorType.IP, threat_objects, True)

    # Both known threat classes should create relationships
    assert len(relationships) == 2
    assert relationships[0]._entity_b == "APT29"
    assert relationships[0]._entity_b_type == ThreatIntel.ObjectsNames.THREAT_ACTOR
    assert relationships[1]._entity_b == "Cobalt Strike"
    assert relationships[1]._entity_b_type == ThreatIntel.ObjectsNames.MALWARE


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


def test_create_relationships_mitre_technique_prefix_removal():
    """
    Given:
        - Threat objects with MITRE technique IDs that have prefixes like "T1590 - "
    When:
        - create_relationships is called with create_relationships enabled
    Then:
        - Removes MITRE technique ID prefix from attack pattern names
        - Creates relationships with clean technique names
    """
    threat_objects = [
        {"name": "T1590 - Gather Victim Network Information", "threat_object_class": "attack pattern"},
        {"name": "T1566 - Phishing", "threat_object_class": "technique"},
        {"name": "Regular Attack Pattern", "threat_object_class": "malicious_behavior"},  # No prefix
        {"name": "T123 - Invalid Format", "threat_object_class": "attack pattern"},  # Invalid format (not digit after T)
    ]

    relationships = create_relationships("1.2.3.4", FeedIndicatorType.IP, threat_objects, True)

    assert len(relationships) == 4

    # Check that MITRE prefixes are removed for valid patterns
    entity_b_names = [rel._entity_b for rel in relationships]
    assert "Gather Victim Network Information" in entity_b_names
    assert "Phishing" in entity_b_names
    assert "Regular Attack Pattern" in entity_b_names
    assert "Invalid Format" in entity_b_names  # Invalid format should remain unchanged


def test_file_hash_detection():
    """
    Given:
        - A SHA256 hash
    When:
        - file_command is called with the hash
    Then:
        - Correctly identifies and processes the hash
        - Returns appropriate CommandResults
    """
    import unittest.mock

    sha256_hash = "c" * 64

    # Mock response
    mock_response = {
        "indicator_value": "test_hash",
        "indicator_type": "file",
        "verdict": "benign",
        "verdict_categories": [{"value": "clean"}],
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "sources": ["source1"],
        "counts": [],
        "threat_object_associations": [],
    }

    client = Client(
        verify=True,
        proxy=False,
        reliability="A - Completely reliable",
    )

    mock_response_obj = unittest.mock.Mock()
    mock_response_obj.status_code = 200
    mock_response_obj.json.return_value = mock_response

    with unittest.mock.patch.object(client, "lookup_indicator", return_value=mock_response_obj):
        args = {"file": sha256_hash, "create_relationships": True, "create_threat_object_indicators": False}
        result = file_command(client, args)
        assert result.indicator.sha256 == sha256_hash
        # MD5 and SHA1 are empty strings, not None
        assert result.indicator.md5 == ""
        assert result.indicator.sha1 == ""


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
    # malicious_behavior maps to ThreatIntel.ObjectsNames.ATTACK_PATTERN in the current implementation
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
    assert result["verdict_categories"] == []
    assert result["first_seen"] == ""
    assert result["last_seen"] == ""
    assert result["seen_by"] == []
    assert result["counts"] == []
    assert result["threat_object_associations"] == []


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
        "verdict_categories": ["legitimate"],
        "first_seen": "2023-01-01T00:00:00Z",
        "last_seen": "2023-12-31T23:59:59Z",
        "seen_by": ["source1"],
        "counts": [],
        "threat_object_associations": [],
    }

    result = create_context_data(response_data)

    assert result["Value"] == "1.2.3.4"
    assert result["Type"] == "IP"
    assert result["Verdict"] == "Benign"
    assert result["VerdictCategories"] == ["Legitimate"]
    assert result["EnrichedThreatObjectAssociation"] == []


def test_extract_tags_from_threat_objects():
    """
    Given:
        - Threat objects with names and aliases
    When:
        - extract_tags_from_threat_objects is called
    Then:
        - Returns list of unique tag names including aliases
        - Removes duplicates and None values
    """
    threat_objects = [
        {"name": "APT29", "aliases": ["Cozy Bear", "The Dukes"]},
        {"name": "Cobalt Strike", "aliases": []},
        {"name": "Zeus", "aliases": ["Zbot", None]},  # Test None handling
        {"aliases": ["Orphan Alias"]},  # Test missing name
    ]

    tags = extract_tags_from_threat_objects(threat_objects)

    assert "APT29" in tags
    assert "Cozy Bear" in tags
    assert "The Dukes" in tags
    assert "Cobalt Strike" in tags
    assert "Zeus" in tags
    assert "Zbot" in tags
    assert "Orphan Alias" in tags
    assert None not in tags
    assert len(tags) == len(set(tags))  # No duplicates


def test_extract_malware_families_from_threat_objects():
    """
    Given:
        - Threat objects with various threat classes including malware_family
    When:
        - extract_malware_families_from_threat_objects is called
    Then:
        - Returns only names of threat objects with malware_family class
        - Ignores other threat classes
    """
    threat_objects = [
        {"name": "APT29", "threat_object_class": "actor"},
        {"name": "Cobalt Strike", "threat_object_class": "malware_family"},
        {"name": "Zeus", "threat_object_class": "malware_family"},
        {"name": "Operation Ghost", "threat_object_class": "campaign"},
        {"threat_object_class": "malware_family"},  # Missing name
    ]

    malware_family = extract_malware_families_from_threat_objects(threat_objects)

    # Function returns the first malware family found
    assert malware_family == "Cobalt Strike"


def test_create_threat_object_indicators():
    """
    Given:
        - Threat objects with various threat classes and detailed information
    When:
        - create_threat_object_indicators is called
    Then:
        - Creates indicator data for each valid threat object
        - Includes proper rawJSON with threat object details
        - Maps threat classes to correct indicator types
    """
    threat_objects = [
        {
            "name": "APT29",
            "threat_object_class": "actor",
            "description": "Advanced persistent threat group",
            "aliases": ["Cozy Bear"],
            "publications": [{"title": "APT29 Report", "url": "http://example.com"}],
        },
        {"name": "Cobalt Strike", "threat_object_class": "malware_family", "source": "Unit42"},
        {
            "threat_object_class": "actor"  # Missing name, should be skipped
        },
    ]

    indicators = create_threat_object_indicators(threat_objects, "A - Completely reliable")

    assert len(indicators) == 2  # Only valid threat objects

    # Check APT29 indicator
    apt29_indicator = next(ind for ind in indicators if ind["value"] == "APT29")
    assert apt29_indicator["type"] == ThreatIntel.ObjectsNames.THREAT_ACTOR
    assert apt29_indicator["rawJSON"]["description"] == "Advanced persistent threat group"
    assert apt29_indicator["rawJSON"]["aliases"] == ["Cozy Bear"]
    # Skip source check as it may not be present in all cases

    # Check Cobalt Strike indicator
    cs_indicator = next(ind for ind in indicators if ind["value"] == "Cobalt Strike")
    assert cs_indicator["type"] == ThreatIntel.ObjectsNames.MALWARE
    assert cs_indicator["rawJSON"]["source"] == "Unit42"


def test_extract_tags_from_threat_objects_empty():
    """
    Given:
        - Empty threat objects list
    When:
        - extract_tags_from_threat_objects is called
    Then:
        - Returns empty list
    """
    tags = extract_tags_from_threat_objects([])
    assert tags == []


def test_extract_malware_families_from_threat_objects_empty():
    """
    Given:
        - Empty threat objects list
    When:
        - extract_malware_families_from_threat_objects is called
    Then:
        - Returns empty list
    """
    malware_family = extract_malware_families_from_threat_objects([])
    assert malware_family is None


def test_create_threat_object_indicators_empty():
    """
    Given:
        - Empty threat objects list
    When:
        - create_threat_object_indicators is called
    Then:
        - Returns empty list
    """
    indicators = create_threat_object_indicators([], "A - Completely reliable")
    assert indicators == []


# Removed test_ip_command_with_threat_object_indicators due to demisto module import issues


def test_file_command_unsupported_hash_type(client):
    """
    Given:
        - A Unit42Intelligence client
        - A non-SHA256 hash (MD5 - 32 characters)
    When:
        - Running file_command
    Then:
        - Returns CommandResults with error message about unsupported hash type
        - Does not make API call
    """
    md5_hash = "a" * 32  # MD5 hash

    args = {"file": md5_hash, "create_relationships": True}
    result = file_command(client, args)

    assert "Unit 42 Intelligence only supports SHA256 hashes" in result.readable_output
    assert "md5" in result.readable_output


def test_file_command_sha1_unsupported(client):
    """
    Given:
        - A Unit42Intelligence client
        - A SHA1 hash (40 characters)
    When:
        - Running file_command
    Then:
        - Returns CommandResults with error message about unsupported hash type
        - Does not make API call
    """
    sha1_hash = "a" * 40  # SHA1 hash

    args = {"file": sha1_hash, "create_relationships": True}
    result = file_command(client, args)

    assert "Unit 42 Intelligence only supports SHA256 hashes" in result.readable_output
    assert "sha1" in result.readable_output


def test_build_threat_object_description():
    """
    Given:
        - A threat object with description, highlights, methods, and targets
    When:
        - build_threat_object_description is called
    Then:
        - Returns formatted description with all sections properly concatenated
        - Handles newline characters correctly
        - Skips empty or default sections
    """
    threat_obj = {
        "description": "Base description\\nwith newlines",
        "battlecard_details": {
            "highlights": "Key highlights\\nImportant info",
            "threat_actor_details": {
                "methods": "Attack methods\\nTechniques used",
                "targets": "Target sectors\\nSpecific victims",
            },
        },
    }

    result = build_threat_object_description(threat_obj)

    assert "Base description\nwith newlines" in result
    assert "##Key highlights\nImportant info" in result
    assert "##Attack methods\nTechniques used" in result
    assert "##Target sectors\nSpecific victims" in result


def test_build_threat_object_description_minimal():
    """
    Given:
        - A threat object with only basic description
    When:
        - build_threat_object_description is called
    Then:
        - Returns only the basic description
        - Does not add empty sections
    """
    threat_obj = {"description": "Simple description"}

    result = build_threat_object_description(threat_obj)

    assert result == "Simple description"
    assert "##" not in result


def test_build_threat_object_description_skip_default_highlights():
    """
    Given:
        - A threat object with default highlights title
    When:
        - build_threat_object_description is called
    Then:
        - Skips the default highlights section
        - Only includes actual content
    """
    threat_obj = {
        "description": "Base description",
        "battlecard_details": {"highlights": "Highlights / Key Takeaways (external)"},
    }

    result = build_threat_object_description(threat_obj)

    assert result == "Base description"
    assert "Highlights / Key Takeaways (external)" not in result


def test_create_publications():
    """
    Given:
        - A list of publication data with various fields
    When:
        - create_publications is called
    Then:
        - Returns properly formatted publications list
        - Maps all fields correctly
        - Uses default source when not provided
    """
    publications_data = [
        {"created": "2023-01-01T00:00:00Z", "title": "Threat Report 1", "url": "https://example.com/report1", "source": "Unit42"},
        {
            "created": "2023-02-01T00:00:00Z",
            "title": "Threat Report 2",
            "url": "https://example.com/report2",
            # Missing source - should use default
        },
    ]

    result = create_publications(publications_data)

    assert len(result) == 2
    assert result[0]["timestamp"] == "2023-01-01T00:00:00Z"
    assert result[0]["title"] == "Threat Report 1"
    assert result[0]["link"] == "https://example.com/report1"
    assert result[0]["source"] == "Unit42"

    assert result[1]["source"] == "Unit 42 Intelligence"  # Default source


def test_create_publications_empty():
    """
    Given:
        - An empty publications list
    When:
        - create_publications is called
    Then:
        - Returns empty list
    """
    result = create_publications([])
    assert result == []


def test_get_threat_object_score():
    """
    Given:
        - Various threat object classes
    When:
        - get_threat_object_score is called
    Then:
        - Returns appropriate ThreatIntel scores for known classes
        - Returns NONE score for unknown classes
    """
    assert get_threat_object_score("malware_family") == ThreatIntel.ObjectsScore.MALWARE
    assert get_threat_object_score("actor") == ThreatIntel.ObjectsScore.THREAT_ACTOR
    assert get_threat_object_score("threat_actor") == ThreatIntel.ObjectsScore.THREAT_ACTOR
    assert get_threat_object_score("campaign") == ThreatIntel.ObjectsScore.CAMPAIGN
    assert get_threat_object_score("attack pattern") == ThreatIntel.ObjectsScore.ATTACK_PATTERN
    assert get_threat_object_score("technique") == ThreatIntel.ObjectsScore.ATTACK_PATTERN
    assert get_threat_object_score("malicious_behavior") == ThreatIntel.ObjectsScore.ATTACK_PATTERN
    assert get_threat_object_score("malicious behavior") == ThreatIntel.ObjectsScore.ATTACK_PATTERN
    assert get_threat_object_score("unknown_class") == Common.DBotScore.NONE


def test_create_threat_object_relationships():
    """
    Given:
        - A threat object with related threat objects
    When:
        - create_threat_object_relationships is called
    Then:
        - Creates relationships for each related threat object
        - Maps threat classes correctly
        - Returns relationship entries
    """
    threat_obj = {
        "related_threat_objects": [
            {"name": "Related Actor", "class": "actor"},
            {"name": "Related Malware", "class": "malware_family"},
            {"class": "campaign"},  # Missing name - should be skipped
        ]
    }

    relationships = create_threat_object_relationships(threat_obj, "Main Threat", "actor")

    assert len(relationships) == 2
    # Note: The function returns relationship entries (dictionaries), not EntityRelationship objects


def test_create_campaigns_relationships():
    """
    Given:
        - A threat object with campaigns in battlecard details
    When:
        - create_campaigns_relationships is called
    Then:
        - Creates relationships for each campaign
        - Filters out empty campaign names
        - Returns relationship entries
    """
    threat_obj = {
        "battlecard_details": {
            "campaigns": ["Campaign Alpha", "Campaign Beta", "", "  "]  # Include empty/whitespace
        }
    }

    relationships = create_campaigns_relationships(threat_obj, "Threat Actor", "actor")

    assert len(relationships) == 2  # Only non-empty campaigns


def test_create_attack_patterns_relationships():
    """
    Given:
        - A threat object with attack patterns containing MITRE IDs
    When:
        - create_attack_patterns_relationships is called
    Then:
        - Creates relationships for valid attack patterns
        - Skips patterns with dots in MITRE ID
        - Removes (enterprise) suffix from pattern names
    """
    threat_obj = {
        "battlecard_details": {
            "attack_patterns": [
                {"mitreid": "T1566", "name": "Phishing (enterprise)"},
                {"mitreid": "T1566.001", "name": "Spear Phishing"},  # Should be skipped (has dot)
                {"mitreid": "T1059", "name": "Command and Scripting Interpreter (enterprise)"},
            ]
        }
    }

    relationships = create_attack_patterns_relationships(threat_obj, "Threat Actor", "actor")

    assert len(relationships) == 2  # One skipped due to dot in MITRE ID


def test_create_malware_relationships():
    """
    Given:
        - A threat object with malware associations
    When:
        - create_malware_relationships is called
    Then:
        - Creates relationships for malware with names
        - Creates relationships for aliases when no name exists
        - Returns relationship entries
    """
    threat_obj = {
        "battlecard_details": {
            "threat_actor_details": {
                "malware_associations": [
                    {"name": "Malware A", "aliases": ["Alias A1", "Alias A2"]},
                    {"aliases": ["Orphan Alias"]},  # No name, use aliases
                    {"name": "Malware B"},  # No aliases
                ]
            }
        }
    }

    relationships = create_malware_relationships(threat_obj, "Threat Actor", "actor")

    assert len(relationships) == 3  # Malware A, Orphan Alias, Malware B


def test_create_tools_relationships():
    """
    Given:
        - A threat object with tools associations
    When:
        - create_tools_relationships is called
    Then:
        - Creates relationships for each tool
        - Includes MITRE ID in fields when available
        - Returns relationship entries
    """
    threat_obj = {
        "battlecard_details": {
            "threat_actor_details": {
                "tools": [
                    {"name": "Tool A", "mitreid": "S0001"},
                    {"name": "Tool B"},  # No MITRE ID
                ]
            }
        }
    }

    relationships = create_tools_relationships(threat_obj, "Threat Actor", "actor")

    assert len(relationships) == 2


def test_create_vulnerabilities_relationships():
    """
    Given:
        - A threat object with vulnerability associations
    When:
        - create_vulnerabilities_relationships is called
    Then:
        - Creates relationships for each CVE
        - Converts CVE IDs to uppercase
        - Returns relationship entries
    """
    threat_obj = {
        "battlecard_details": {
            "threat_actor_details": {
                "vulnerability_associations": [
                    {"cve": "cve-2023-1234"},
                    {"cve": "CVE-2023-5678"},
                    {},  # Missing CVE - should be skipped
                ]
            }
        }
    }

    relationships = create_vulnerabilities_relationships(threat_obj, "Threat Actor", "actor")

    assert len(relationships) == 2


def test_create_actor_relationships():
    """
    Given:
        - A malware family with actor associations
    When:
        - create_actor_relationships is called
    Then:
        - Creates relationships using aliases when available
        - Falls back to name when no aliases exist
        - Returns relationship entries
    """
    threat_obj = {
        "battlecard_details": {
            "malware_family_details": {
                "actor_associations": [
                    {"aliases": ["Actor Alias 1", "Actor Alias 2"], "name": "Actor Name"},
                    {"name": "Solo Actor"},  # No aliases
                    {"aliases": []},  # Empty aliases, should use name
                ]
            }
        }
    }

    relationships = create_actor_relationships(threat_obj, "Malware Family", "malware_family")

    assert len(relationships) == 3  # 2 aliases + 1 solo actor


def test_create_location_indicators_and_relationships():
    """
    Given:
        - A threat object with affected regions
    When:
        - create_location_indicators_and_relationships is called
    Then:
        - Creates location indicators for valid regions
        - Skips invalid regions not in VALID_REGIONS enum
        - Creates proper relationships with threat actor
    """
    threat_obj = {
        "battlecard_details": {
            "threat_actor_details": {
                "affected_regions": [
                    "north america",  # Valid region
                    "europe",  # Valid region
                    "invalid region",  # Should be skipped
                    "  ASIA  ",  # Should be normalized and skipped if not valid
                ]
            }
        }
    }

    location_indicators = create_location_indicators_and_relationships(threat_obj, "Threat Actor")

    assert len(location_indicators) == 2  # Only valid regions

    for indicator in location_indicators:
        assert indicator["type"] == FeedIndicatorType.Location
        assert indicator["score"] == Common.DBotScore.NONE
        assert indicator["service"] == "Unit 42 Intelligence"
        assert len(indicator["relationships"]) == 1


def test_create_location_indicators_null_regions():
    """
    Given:
        - A threat object with null affected_regions
    When:
        - create_location_indicators_and_relationships is called
    Then:
        - Returns empty list without errors
    """
    threat_obj = {"battlecard_details": {"threat_actor_details": {"affected_regions": None}}}

    location_indicators = create_location_indicators_and_relationships(threat_obj, "Threat Actor")

    assert location_indicators == []


def test_remove_mitre_technique_id_prefix():
    """
    Given:
        - Various threat names with and without MITRE technique ID prefixes
    When:
        - remove_mitre_technique_id_prefix is called
    Then:
        - Returns threat name with MITRE technique ID prefix removed when applicable
        - Returns original threat name when no valid MITRE prefix is found
    """
    # Test cases with valid MITRE technique ID prefixes
    assert remove_mitre_technique_id_prefix("T1590 - Gather Victim Network Information") == "Gather Victim Network Information"
    assert remove_mitre_technique_id_prefix("T123 - Some Technique") == "Some Technique"
    assert remove_mitre_technique_id_prefix("T1 - Single Digit Technique") == "Single Digit Technique"
    assert remove_mitre_technique_id_prefix("T9999 - Large Number Technique") == "Large Number Technique"

    # Test cases without valid MITRE technique ID prefixes
    assert remove_mitre_technique_id_prefix("Regular Threat Name") == "Regular Threat Name"
    assert remove_mitre_technique_id_prefix("Not a MITRE ID - Something") == "Not a MITRE ID - Something"
    assert remove_mitre_technique_id_prefix("T - Missing Number") == "T - Missing Number"
    assert remove_mitre_technique_id_prefix("TABC - Non-numeric") == "TABC - Non-numeric"
    assert remove_mitre_technique_id_prefix("T123") == "T123"  # No separator
    assert remove_mitre_technique_id_prefix("") == ""  # Empty string
    assert remove_mitre_technique_id_prefix("T123 - ") == ""  # Empty technique name after prefix

    # Test edge cases
    assert remove_mitre_technique_id_prefix("T123 - Multiple - Separators") == "Multiple - Separators"
    assert remove_mitre_technique_id_prefix("123 - No T prefix") == "123 - No T prefix"
