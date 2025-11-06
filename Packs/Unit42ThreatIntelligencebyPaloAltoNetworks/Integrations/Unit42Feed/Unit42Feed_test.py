import pytest
from datetime import datetime, timedelta
from Unit42Feed import (
    Client,
    create_publications,
    get_threat_object_score,
    create_location_indicators_and_relationships,
    build_threat_object_description,
    test_module as unit42_test_module,
    main,
    INDICATOR_TYPE_MAPPING,
    VERDICT_TO_SCORE,
    VALID_REGIONS,
    DATE_FORMAT,
    API_LIMIT,
    INTEGRATION_NAME,
)
from CommonServerPython import *


def mock_demisto_params(mocker, create_relationships=True):
    """Helper function to mock demisto.params() with common parameters"""
    return mocker.patch(
        "Unit42Feed.demisto.params",
        return_value={"create_relationships": create_relationships, "feedReliability": DBotScoreReliability.A},
    )


@pytest.fixture
def client():
    """
    Given:
        - Client initialization parameters
    When:
        - Creating a Unit42Feed client
    Then:
        - Returns properly configured client instance
    """
    headers = {"Authorization": "Bearer test_token"}
    return Client(headers=headers, verify=False, proxy=False)


def test_client_initialization():
    """
    Given:
        - Client configuration parameters
    When:
        - Initializing Unit42Feed Client
    Then:
        - Sets correct base URL and headers
    """
    headers = {"Authorization": "Bearer test_token"}
    client = Client(headers=headers, verify=True, proxy=True)

    assert client._base_url == "https://prod-us.tas.crtx.paloaltonetworks.com"
    assert client._headers == headers
    assert client._verify is True


def test_client_get_indicators(client, mocker):
    """
    Given:
        - A Unit42Feed client
        - Mock API response with indicators data
    When:
        - Calling get_indicators with various parameters
    Then:
        - Makes correct API request with proper parameters
        - Returns response data
    """
    mock_response = {
        "data": [{"indicator_value": "1.2.3.4", "indicator_type": "ip", "verdict": "malicious"}],
        "metadata": {"next_page_token": "token123"},
    }

    mock_http_request = mocker.patch.object(client, "_http_request", return_value=mock_response)

    # Test with all parameters
    result = client.get_indicators(
        indicator_types=["ip", "domain"], limit=100, start_time="2023-01-01T00:00:00Z", next_page_token="page_token"
    )

    assert result == mock_response
    mock_http_request.assert_called_once_with(
        method="GET",
        url_suffix="/api/v1/feeds/indicators",
        params={
            "indicator_types": ["ip", "domain"],
            "limit": 100,
            "start_time": "2023-01-01T00:00:00Z",
            "page_token": "page_token",
        },
    )


def test_client_get_indicators_file_type_mapping(client, mocker):
    """
    Given:
        - A Unit42Feed client
        - File indicator type in request
    When:
        - Calling get_indicators with file type
    Then:
        - Maps file to filehash_sha256 in API request
    """
    mock_response = {"data": []}
    mock_http_request = mocker.patch.object(client, "_http_request", return_value=mock_response)

    client.get_indicators(indicator_types=["file"])

    mock_http_request.assert_called_once_with(
        method="GET", url_suffix="/api/v1/feeds/indicators", params={"indicator_types": ["filehash_sha256"], "limit": 5000}
    )


def test_client_get_threat_objects(client, mocker):
    """
    Given:
        - A Unit42Feed client
        - Mock API response with threat objects data
    When:
        - Calling get_threat_objects with parameters
    Then:
        - Makes correct API request
        - Returns response data
    """
    mock_response = {"data": [{"name": "APT29", "threat_object_class": "actor"}], "metadata": {"next_page_token": "token456"}}

    mock_http_request = mocker.patch.object(client, "_http_request", return_value=mock_response)

    result = client.get_threat_objects(limit=50, next_page_token="test_token")

    assert result == mock_response
    mock_http_request.assert_called_once_with(
        method="GET", url_suffix="/api/v1/feeds/threat_objects", params={"limit": 50, "page_token": "test_token"}
    )


def test_create_publications():
    """
    Given:
        - Publications data from threat object
    When:
        - Calling create_publications function
    Then:
        - Returns properly formatted publications list
        - Uses default source when not provided
    """
    publications_data = [
        {
            "created_at": "2023-01-01T00:00:00Z",
            "title": "Test Report",
            "url": "https://example.com/report",
            "source": "Custom Source",
        },
        {
            "created_at": "2023-02-01T00:00:00Z",
            "title": "Another Report",
            "url": "https://example.com/report2",
            # Missing source - should use default
        },
    ]

    result = create_publications(publications_data)

    assert len(result) == 2
    assert result[0]["link"] == "https://example.com/report"
    assert result[0]["title"] == "Test Report"
    assert result[0]["timestamp"] == "2023-01-01T00:00:00Z"
    assert result[0]["source"] == "Custom Source"

    assert result[1]["source"] == INTEGRATION_NAME  # Default source


def test_get_threat_object_score():
    """
    Given:
        - Various threat object classes
    When:
        - Calling get_threat_object_score function
    Then:
        - Returns correct ThreatIntel score for each class
        - Returns NONE for unknown classes
    """
    # Test malware family
    assert get_threat_object_score("malware_family") == ThreatIntel.ObjectsScore.MALWARE

    # Test threat actor
    assert get_threat_object_score("actor") == ThreatIntel.ObjectsScore.THREAT_ACTOR
    assert get_threat_object_score("threat_actor") == ThreatIntel.ObjectsScore.THREAT_ACTOR

    # Test campaign
    assert get_threat_object_score("campaign") == ThreatIntel.ObjectsScore.CAMPAIGN

    # Test attack patterns
    assert get_threat_object_score("attack pattern") == ThreatIntel.ObjectsScore.ATTACK_PATTERN
    assert get_threat_object_score("technique") == ThreatIntel.ObjectsScore.ATTACK_PATTERN
    assert get_threat_object_score("malicious_behavior") == ThreatIntel.ObjectsScore.ATTACK_PATTERN
    assert get_threat_object_score("malicious behavior") == ThreatIntel.ObjectsScore.ATTACK_PATTERN

    # Test unknown class
    assert get_threat_object_score("unknown_class") == Common.DBotScore.NONE


def test_build_threat_object_description():
    """
    Given:
        - Threat object data with various description fields
    When:
        - Calling build_threat_object_description function
    Then:
        - Builds comprehensive description with all sections
        - Handles missing fields gracefully
    """
    threat_obj = {
        "description": "Base description\\nwith newlines",
        "battlecard_details": {
            "highlights": "Key highlights\\nfor this threat",
            "threat_actor_details": {
                "methods": "Attack methods\\nused by actor",
                "targets": "Target information\\nfor this actor",
            },
        },
    }

    result = build_threat_object_description(threat_obj)

    assert "Base description\nwith newlines" in result
    assert "Key highlights\nfor this threat" in result
    assert "Attack methods\nused by actor" in result
    assert "Target information\nfor this actor" in result
    assert result.count("##") == 3  # Three sections added


def test_build_threat_object_description_minimal():
    """
    Given:
        - Threat object with only basic description
    When:
        - Calling build_threat_object_description function
    Then:
        - Returns only the basic description
        - Handles missing battlecard details
    """
    threat_obj = {"description": "Simple description"}

    result = build_threat_object_description(threat_obj)

    assert result == "Simple description"


def test_test_module_success(client, mocker):
    """
    Given:
        - A Unit42Feed client
        - Mock API response that succeeds
    When:
        - Running test_module function
    Then:
        - Returns 'ok' indicating successful connection
    """
    mock_response = {"data": [{"indicator_value": "test"}]}
    # Mock the _http_request method to avoid actual API calls
    mocker.patch.object(client, "_http_request", return_value=mock_response)

    result = unit42_test_module(client)

    assert result == "ok"


def test_test_module_empty_result(client, mocker):
    """
    Given:
        - A Unit42Feed client
        - Mock API response with no data
    When:
        - Running test_module function
    Then:
        - Returns ok
    """
    mock_response = {"data": []}
    # Mock the _http_request method to avoid actual API calls
    mocker.patch.object(client, "_http_request", return_value=mock_response)

    result = unit42_test_module(client)

    assert result == "ok"


def test_test_module_exception(client, mocker):
    """
    Given:
        - A Unit42Feed client
        - Mock API that raises exception
    When:
        - Running test_module function
    Then:
        - Raises an exception (since test_module doesn't catch exceptions)
    """
    # Mock the _http_request method to raise an exception
    mocker.patch.object(client, "_http_request", side_effect=Exception("API Error"))

    res = unit42_test_module(client)
    assert "Error: API Error" in res


def test_create_location_indicators_and_relationships():
    """
    Given:
        - Threat object with affected regions data
        - Threat actor name
    When:
        - Calling create_location_indicators_and_relationships function
    Then:
        - Creates location indicators for valid regions
        - Creates proper relationships with threat actor
        - Skips invalid regions
    """
    threat_obj = {
        "battlecard_details": {
            "threat_actor_details": {
                "affected_regions": [
                    "North America",
                    "europe",  # lowercase - should be standardized
                    "Invalid Region",  # not in VALID_REGIONS
                    "middle east",  # lowercase - should be standardized
                ]
            }
        }
    }
    threat_actor_name = "APT29"

    result = create_location_indicators_and_relationships(threat_obj, threat_actor_name)

    # Should create indicators for valid regions only
    assert len(result) == 3  # North America, Europe, Middle East

    # Check first location indicator
    location_indicator = result[0]
    assert location_indicator["type"] == FeedIndicatorType.Location
    assert location_indicator["score"] == Common.DBotScore.NONE
    assert location_indicator["service"] == INTEGRATION_NAME
    assert len(location_indicator["relationships"]) == 1

    # Check relationship
    relationship = location_indicator["relationships"][0]
    assert relationship["name"] == EntityRelationship.Relationships.TARGETS
    assert relationship["entityA"] == threat_actor_name
    assert relationship["entityAType"] == ThreatIntel.ObjectsNames.THREAT_ACTOR
    assert relationship["entityBType"] == FeedIndicatorType.Location


def test_create_location_indicators_null_regions():
    """
    Given:
        - Threat object with null affected_regions
    When:
        - Calling create_location_indicators_and_relationships function
    Then:
        - Returns empty list
        - Handles null gracefully
    """
    threat_obj = {"battlecard_details": {"threat_actor_details": {"affected_regions": None}}}

    result = create_location_indicators_and_relationships(threat_obj, "APT29")

    assert result == []


def test_create_vulnerabilities_relationships():
    """
    Given:
        - Threat object with vulnerability associations
        - Threat actor name and class
    When:
        - Calling create_vulnerabilities_relationships function
    Then:
        - Creates relationships for each CVE
        - Uses correct relationship type (EXPLOITS)
    """
    from Unit42Feed import create_vulnerabilities_relationships

    threat_obj = {
        "battlecard_details": {
            "threat_actor_details": {
                "vulnerability_associations": [
                    {"cve": "cve-2023-1234"},
                    {"cve": "CVE-2023-5678"},
                    {"other_field": "no_cve"},  # Should be skipped
                ]
            }
        }
    }

    result = create_vulnerabilities_relationships(threat_obj, "APT29", "actor")

    assert len(result) == 2

    # Check first relationship
    relationship = result[0]
    assert relationship["name"] == EntityRelationship.Relationships.EXPLOITS
    assert relationship["entityA"] == "APT29"
    assert relationship["entityB"] == "CVE-2023-1234"  # Should be uppercase
    assert relationship["entityBType"] == FeedIndicatorType.CVE


def test_create_relationships_and_tags():
    """
    Given:
        - Indicator value, type, and threat object associations
    When:
        - Calling create_relationships_and_tags function with relationships enabled
    Then:
        - Creates relationships based on threat object classes
        - Extracts threat object names as tags
        - Uses correct relationship types for different threat classes
    """
    from Unit42Feed import create_relationships_and_tags
    import unittest.mock

    threat_object_associations = [
        {"name": "APT29", "threat_object_class": "actor"},
        {"name": "Cobalt Strike", "threat_object_class": "malware_family"},
        {"name": "Operation Ghost", "threat_object_class": "campaign"},
        {"name": "Spear Phishing", "threat_object_class": "malicious_behavior"},
        {"name": "CVE-2023-1234", "threat_object_class": "exploit"},
        {"name": "", "threat_object_class": "actor"},  # Empty name - should be skipped
    ]

    with unittest.mock.patch("Unit42Feed.demisto.params") as mock_params:
        mock_params.return_value = {"create_relationships": True, "feedReliability": DBotScoreReliability.A}

        with unittest.mock.patch("Unit42Feed.argToBoolean", return_value=True):
            relationships, tags = create_relationships_and_tags("1.2.3.4", "ip", threat_object_associations)

    assert len(relationships) == 5  # Should skip empty name
    assert len(tags) == 5  # All valid names should be tags

    # Check tags
    assert "APT29" in tags
    assert "Cobalt Strike" in tags
    assert "Operation Ghost" in tags

    # Check relationship types
    relationship_names = [rel["name"] for rel in relationships]
    assert EntityRelationship.Relationships.USED_BY in relationship_names  # actor
    assert EntityRelationship.Relationships.PART_OF in relationship_names  # campaign
    assert EntityRelationship.Relationships.INDICATOR_OF in relationship_names  # malicious_behavior
    assert EntityRelationship.Relationships.EXPLOITS in relationship_names  # exploit


def test_map_indicator_basic():
    """
    Given:
        - Basic indicator data from API
    When:
        - Calling map_indicator function
    Then:
        - Returns properly formatted XSOAR indicator
        - Maps verdict to correct DBotScore
        - Sets correct indicator type
    """
    from Unit42Feed import map_indicator

    indicator_data = {
        "indicator_value": "1.2.3.4",
        "indicator_type": "ip",
        "verdict": "malicious",
        "updated_at": "2023-12-31T23:59:59Z",
        "first_seen": "2023-01-01T00:00:00Z",
        "source": "Unit42",
        "threat_object_associations": [],
    }

    result = map_indicator(indicator_data, feed_tags=["test_tag"], tlp_color="RED")

    assert result["value"] == "1.2.3.4"
    assert result["type"] == FeedIndicatorType.IP
    assert result["score"] == Common.DBotScore.BAD  # malicious verdict
    assert result["service"] == INTEGRATION_NAME
    assert result["fields"]["updateddate"] == "2023-12-31T23:59:59Z"
    assert result["fields"]["creationdate"] == "2023-01-01T00:00:00Z"
    assert result["fields"]["reportedby"] == "Unit42"
    assert "test_tag" in result["fields"]["tags"]
    assert result["fields"]["trafficlightprotocol"] == "RED"
    assert result["rawJSON"] == indicator_data


def test_map_indicator_file_type():
    """
    Given:
        - File indicator data with hash details
    When:
        - Calling map_indicator function
    Then:
        - Maps file hashes to correct fields
        - Sets file-specific fields
    """
    from Unit42Feed import map_indicator

    indicator_data = {
        "indicator_value": "a" * 64,  # SHA256 hash
        "indicator_type": "filehash_sha256",
        "verdict": "suspicious",
        "indicator_details": {
            "file_hashes": {
                "md5": "b" * 32,
                "sha1": "c" * 40,
                "sha256": "a" * 64,
                "ssdeep": "test_ssdeep",
                "imphash": "test_imphash",
                "pehash": "test_pehash",
            },
            "file_type": "exe",
            "file_size": 1024,
        },
        "threat_object_associations": [],
    }

    result = map_indicator(indicator_data)

    assert result["type"] == FeedIndicatorType.File
    assert result["score"] == Common.DBotScore.SUSPICIOUS
    assert result["fields"]["md5"] == "b" * 32
    assert result["fields"]["sha1"] == "c" * 40
    assert result["fields"]["sha256"] == "a" * 64
    assert result["fields"]["ssdeep"] == "test_ssdeep"
    assert result["fields"]["imphash"] == "test_imphash"
    assert result["fields"]["pehash"] == "test_pehash"
    assert result["fields"]["filetype"] == "exe"
    assert result["fields"]["fileextension"] == "exe"
    assert result["fields"]["size"] == 1024


def test_map_indicator_with_relationships():
    """
    Given:
        - Indicator data with threat object associations
    When:
        - Calling map_indicator function
    Then:
        - Creates relationships and tags from threat objects
    """
    from Unit42Feed import map_indicator
    import unittest.mock

    indicator_data = {
        "indicator_value": "malicious.com",
        "indicator_type": "domain",
        "verdict": "benign",
        "threat_object_associations": [
            {"name": "APT29", "threat_object_class": "actor"},
            {"name": "Cobalt Strike", "threat_object_class": "malware_family"},
        ],
    }

    with unittest.mock.patch("Unit42Feed.create_relationships_and_tags") as mock_create_rel:
        mock_create_rel.return_value = (
            [{"name": "test_relationship"}],  # relationships
            ["APT29", "Cobalt Strike"],  # tags
        )

        result = map_indicator(indicator_data)

    assert result["type"] == FeedIndicatorType.Domain
    assert result["score"] == Common.DBotScore.GOOD  # benign verdict
    assert len(result["relationships"]) == 1
    assert "APT29" in result["fields"]["tags"]
    assert "Cobalt Strike" in result["fields"]["tags"]


def test_map_threat_object_basic(mocker):
    """
    Given:
        - Basic threat object data from API
    When:
        - Calling map_threat_object function
    Then:
        - Returns list with properly formatted threat object
        - Sets correct threat object type and score
    """
    from Unit42Feed import map_threat_object

    mock_demisto_params(mocker)

    threat_object = {
        "name": "APT29",
        "threat_object_class": "actor",
        "last_hit": "2023-12-31T23:59:59Z",
        "sources": ["Unit42", "External"],
        "aliases": ["Cozy Bear", "The Dukes"],
        "publications": [],
        "related_threat_objects": [],
        "battlecard_details": {
            "industries": ["Finance", "Healthcare"],
            "threat_actor_details": {"primary_motivation": "espionage", "origin": "russia"},
        },
    }

    result = map_threat_object(threat_object, feed_tags=["test_tag"], tlp_color="AMBER")

    assert len(result) == 1  # Should return list with one threat object
    threat_obj = result[0]

    assert threat_obj["value"] == "APT29"
    assert threat_obj["type"] == ThreatIntel.ObjectsNames.THREAT_ACTOR
    assert threat_obj["score"] == ThreatIntel.ObjectsScore.THREAT_ACTOR
    assert threat_obj["service"] == INTEGRATION_NAME
    assert threat_obj["fields"]["lastseenbysource"] == "2023-12-31T23:59:59Z"
    assert threat_obj["fields"]["reportedby"] == ["Unit42", "External"]
    assert "Cozy Bear" in threat_obj["fields"]["aliases"]
    assert "The Dukes" in threat_obj["fields"]["aliases"]
    assert "Finance" in threat_obj["fields"]["industrysectors"]
    assert "Healthcare" in threat_obj["fields"]["industrysectors"]
    assert threat_obj["fields"]["primarymotivation"] == "Espionage"
    assert threat_obj["fields"]["geocountry"] == "RUSSIA"
    assert "test_tag" in threat_obj["fields"]["tags"]
    assert threat_obj["fields"]["trafficlightprotocol"] == "AMBER"


def test_map_threat_object_with_relationships(mocker):
    """
    Given:
        - Threat object data with relationships enabled
    When:
        - Calling map_threat_object function
    Then:
        - Creates relationships and location indicators
        - Includes all relationship types
    """
    from Unit42Feed import map_threat_object

    mock_demisto_params(mocker)

    threat_object = {
        "name": "APT29",
        "threat_object_class": "actor",
        "related_threat_objects": [{"name": "Cobalt Strike", "threat_object_class": "malware_family"}],
        "battlecard_details": {
            "campaigns": ["Operation Ghost"],
            "attack_patterns": [{"name": "Spear Phishing", "mitreid": "T1566"}],
            "threat_actor_details": {
                "malware_associations": [{"name": "Zeus"}],
                "tools": [{"name": "PowerShell"}],
                "vulnerability_associations": [{"cve": "CVE-2023-1234"}],
                "affected_regions": ["North America"],
            },
        },
        "publications": [],
    }

    # Mock demisto.params to enable relationships
    mocker.patch("Unit42Feed.demisto.params", return_value={"create_relationships": True})
    mocker.patch("Unit42Feed.argToBoolean", return_value=True)

    result = map_threat_object(threat_object)

    # Should include the main threat object plus location indicators
    assert len(result) >= 1

    # Find the main threat object (not a location indicator)
    main_threat_obj = next((obj for obj in result if obj["value"] == "APT29"), None)
    assert main_threat_obj is not None
    assert main_threat_obj["value"] == "APT29"
    assert len(main_threat_obj["relationships"]) > 0  # Should have relationships


def test_verdict_to_score_mapping():
    """
    Given:
        - Various verdict values
    When:
        - Using VERDICT_TO_SCORE mapping
    Then:
        - Maps verdicts to correct DBotScore values
    """
    assert VERDICT_TO_SCORE["malicious"] == Common.DBotScore.BAD
    assert VERDICT_TO_SCORE["suspicious"] == Common.DBotScore.SUSPICIOUS
    assert VERDICT_TO_SCORE["benign"] == Common.DBotScore.GOOD
    assert VERDICT_TO_SCORE["unknown"] == Common.DBotScore.NONE


def test_indicator_type_mapping():
    """
    Given:
        - Various indicator types from API
    When:
        - Using INDICATOR_TYPE_MAPPING
    Then:
        - Maps API types to correct XSOAR types
    """
    assert INDICATOR_TYPE_MAPPING["ip"] == FeedIndicatorType.IP
    assert INDICATOR_TYPE_MAPPING["domain"] == FeedIndicatorType.Domain
    assert INDICATOR_TYPE_MAPPING["url"] == FeedIndicatorType.URL
    assert INDICATOR_TYPE_MAPPING["file"] == FeedIndicatorType.File
    assert INDICATOR_TYPE_MAPPING["filehash_sha256"] == FeedIndicatorType.File
    assert INDICATOR_TYPE_MAPPING["malware_family"] == ThreatIntel.ObjectsNames.MALWARE
    assert INDICATOR_TYPE_MAPPING["actor"] == ThreatIntel.ObjectsNames.THREAT_ACTOR
    assert INDICATOR_TYPE_MAPPING["campaign"] == ThreatIntel.ObjectsNames.CAMPAIGN


def test_valid_regions_mapping():
    """
    Given:
        - Various region names
    When:
        - Using VALID_REGIONS mapping
    Then:
        - Maps lowercase regions to standardized names
    """
    assert VALID_REGIONS["north america"] == "North America"
    assert VALID_REGIONS["europe"] == "Europe"
    assert VALID_REGIONS["middle east"] == "Middle East"
    assert VALID_REGIONS["africa"] == "Africa"


def test_parse_indicators():
    """
    Given:
        - List of indicator data from API
    When:
        - Calling parse_indicators function
    Then:
        - Returns list of mapped indicators
        - Handles empty and invalid data gracefully
    """
    from Unit42Feed import parse_indicators

    indicators_data = [
        {"indicator_value": "1.2.3.4", "indicator_type": "ip", "verdict": "malicious"},
        {"indicator_value": "example.com", "indicator_type": "domain", "verdict": "benign"},
    ]

    result = parse_indicators(indicators_data, feed_tags=["test_tag"], tlp_color="GREEN")

    assert len(result) == 2
    assert result[0]["value"] == "1.2.3.4"
    assert result[0]["type"] == FeedIndicatorType.IP
    assert result[1]["value"] == "example.com"
    assert result[1]["type"] == FeedIndicatorType.Domain

    # Test with empty data
    empty_result = parse_indicators([])
    assert empty_result == []

    # Test with None data
    none_result = parse_indicators(None)
    assert none_result == []


def test_parse_threat_objects(mocker):
    """
    Given:
        - List of threat object data from API
    When:
        - Calling parse_threat_objects function
    Then:
        - Returns list of mapped threat objects
        - Handles empty and invalid data gracefully
    """
    from Unit42Feed import parse_threat_objects

    mock_demisto_params(mocker)

    threat_objects_data = [
        {"name": "APT29", "threat_object_class": "actor", "publications": []},
        {"name": "Cobalt Strike", "threat_object_class": "malware_family", "publications": []},
    ]

    result = parse_threat_objects(threat_objects_data, feed_tags=["test_tag"], tlp_color="AMBER")

    assert len(result) >= 2  # Could be more due to location indicators

    # Find the main threat objects (not location indicators)
    main_objects = [
        obj for obj in result if obj["type"] in [ThreatIntel.ObjectsNames.THREAT_ACTOR, ThreatIntel.ObjectsNames.MALWARE]
    ]

    assert len(main_objects) == 2
    assert any(obj["value"] == "APT29" for obj in main_objects)
    assert any(obj["value"] == "Cobalt Strike" for obj in main_objects)

    # Test with empty data
    empty_result = parse_threat_objects([])
    assert empty_result == []

    # Test with None data
    none_result = parse_threat_objects(None)
    assert none_result == []


def test_fetch_indicators_basic(client, mocker):
    """
    Given:
        - Unit42Feed client and parameters
        - Mock API responses for indicators
    When:
        - Calling fetch_indicators function
    Then:
        - Fetches indicators from API
        - Parses and returns indicator list
        - Handles pagination correctly
    """
    from Unit42Feed import fetch_indicators

    # Mock API responses
    mock_indicators_response = {
        "data": [{"indicator_value": "1.2.3.4", "indicator_type": "ip", "verdict": "malicious"}],
        "metadata": {"next_page_token": None},
    }

    mock_threat_objects_response = {
        "data": [{"name": "APT29", "threat_object_class": "actor", "publications": []}],
        "metadata": {"next_page_token": None},
    }

    mocker.patch.object(client, "get_indicators", return_value=mock_indicators_response)
    mocker.patch.object(client, "get_threat_objects", return_value=mock_threat_objects_response)

    # Mock demisto functions
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={})
    mock_demisto_params(mocker)

    params = {
        "feed_types": ["Indicators", "Threat Objects"],
        "indicator_types": ["ip", "domain"],
        "feed_tags": ["test_tag"],
        "trafficlightprotocol": "RED",
    }

    current_time = datetime.now()
    result = fetch_indicators(client, params, current_time)

    assert len(result) >= 2  # At least one indicator and one threat object

    # Check that we have both indicators and threat objects
    indicator_types = [item["type"] for item in result]
    assert FeedIndicatorType.IP in indicator_types
    assert ThreatIntel.ObjectsNames.THREAT_ACTOR in indicator_types


def test_fetch_indicators_pagination(client, mocker):
    """
    Given:
        - Unit42Feed client with paginated API responses
    When:
        - Calling fetch_indicators function
    Then:
        - Handles pagination correctly
        - Fetches multiple pages until limit or no more pages
    """
    from Unit42Feed import fetch_indicators

    # Mock paginated responses
    first_response = {
        "data": [{"indicator_value": "1.2.3.4", "indicator_type": "ip", "verdict": "malicious"}],
        "metadata": {"next_page_token": "page2"},
    }

    second_response = {
        "data": [{"indicator_value": "5.6.7.8", "indicator_type": "ip", "verdict": "benign"}],
        "metadata": {"next_page_token": None},
    }

    mock_get_indicators = mocker.patch.object(client, "get_indicators")
    mock_get_indicators.side_effect = [first_response, second_response]

    mocker.patch.object(client, "get_threat_objects", return_value={"data": [], "metadata": {}})
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={})

    params = {"feed_types": ["Indicators"], "indicator_types": ["ip"], "feed_tags": [], "tlp_color": None}

    current_time = datetime.now()
    result = fetch_indicators(client, params, current_time)

    # Should have indicators from both pages
    ip_indicators = [item for item in result if item["type"] == FeedIndicatorType.IP]
    assert len(ip_indicators) == 2
    assert any(item["value"] == "1.2.3.4" for item in ip_indicators)
    assert any(item["value"] == "5.6.7.8" for item in ip_indicators)


def test_get_indicators_command(client, mocker):
    """
    Given:
        - Unit42Feed client and command arguments
    When:
        - Calling get_indicators_command function
    Then:
        - Returns CommandResults with indicators
        - Creates proper human readable output
    """
    from Unit42Feed import get_indicators_command

    mock_response = {
        "data": [{"indicator_value": "1.2.3.4", "indicator_type": "ip", "verdict": "malicious"}],
        "metadata": {"next_page_token": "token123"},
    }

    mocker.patch.object(client, "get_indicators", return_value=mock_response)

    args = {"limit": "5", "indicator_types": ["ip", "domain"], "next_page_token": "test_token"}

    result = get_indicators_command(client, args, feed_tags=["test_tag"], tlp_color="AMBER")

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Unit42.Indicator"
    assert result.outputs_key_field == "value"
    assert len(result.outputs) == 1
    assert result.outputs[0]["value"] == "1.2.3.4"
    assert "Unit 42 Indicators:" in result.readable_output
    assert result.raw_response == mock_response


def test_get_threat_objects_command(client, mocker):
    """
    Given:
        - Unit42Feed client and command arguments
    When:
        - Calling get_threat_objects_command function
    Then:
        - Returns CommandResults with threat objects
        - Creates proper human readable output
    """
    from Unit42Feed import get_threat_objects_command

    mock_response = {
        "data": [{"name": "APT29", "threat_object_class": "actor", "publications": []}],
        "metadata": {"next_page_token": "token456"},
    }

    mocker.patch.object(client, "get_threat_objects", return_value=mock_response)
    mock_demisto_params(mocker)

    args = {"limit": "10", "next_page_token": "test_token"}

    result = get_threat_objects_command(client, args, feed_tags=["test_tag"], tlp_color="GREEN")

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "Unit42.ThreatObject"
    assert result.outputs_key_field == "value"
    assert len(result.outputs) >= 1  # Could include location indicators
    assert "Unit 42 Threat Objects:" in result.readable_output
    assert result.raw_response == mock_response


def test_date_format_constant():
    """
    Given:
        - DATE_FORMAT constant
    When:
        - Using the constant for date formatting
    Then:
        - Formats dates correctly
    """
    test_date = datetime(2023, 12, 31, 23, 59, 59)
    formatted_date = test_date.strftime(DATE_FORMAT)

    assert formatted_date == "2023-12-31T23:59:59Z"


def test_api_limit_constant():
    """
    Given:
        - API_LIMIT constant
    When:
        - Using the constant for API requests
    Then:
        - Has expected value for pagination
    """
    assert API_LIMIT == 5000
    assert isinstance(API_LIMIT, int)
    assert API_LIMIT > 0


def test_fetch_indicators_with_last_run(client, mocker):
    """
    Given:
        - Unit42Feed client with existing last run data
    When:
        - Calling fetch_indicators function
    Then:
        - Uses last run time for start_time parameter
        - Falls back to default if no last run
    """
    from Unit42Feed import fetch_indicators

    mock_response = {"data": [], "metadata": {}}
    mock_get_indicators = mocker.patch.object(client, "get_indicators", return_value=mock_response)
    mocker.patch.object(client, "get_threat_objects", return_value=mock_response)

    # Test with existing last run
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={"last_successful_run": "2023-06-01T12:00:00Z"})

    params = {"feed_types": ["Indicators"], "indicator_types": ["ip"], "feed_tags": [], "tlp_color": None}

    current_time = datetime(2023, 6, 2, 12, 0, 0)
    fetch_indicators(client, params, current_time)

    # Should use the last run time
    mock_get_indicators.assert_called_once()
    call_args = mock_get_indicators.call_args[1]
    assert call_args["start_time"] == "2023-06-01T12:00:00Z"


def test_fetch_indicators_default_start_time(client, mocker):
    """
    Given:
        - Unit42Feed client with no last run data
    When:
        - Calling fetch_indicators function
    Then:
        - Uses default start time (24 hours ago)
    """
    from Unit42Feed import fetch_indicators

    mock_response = {"data": [], "metadata": {}}
    mock_get_indicators = mocker.patch.object(client, "get_indicators", return_value=mock_response)
    mocker.patch.object(client, "get_threat_objects", return_value=mock_response)

    # Test with no last run
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={})

    params = {"feed_types": ["Indicators"], "indicator_types": ["ip"], "feed_tags": [], "tlp_color": None}

    current_time = datetime(2023, 6, 2, 12, 0, 0)
    fetch_indicators(client, params, current_time)

    # Should use default time (24 hours ago)
    mock_get_indicators.assert_called_once()
    call_args = mock_get_indicators.call_args[1]
    expected_default = (current_time - timedelta(hours=24)).strftime(DATE_FORMAT)
    assert call_args["start_time"] == expected_default


def test_main_function_test_module(mocker):
    """
    Given:
        - Main function with test-module command
    When:
        - Calling main function
    Then:
        - Executes test_module and returns results
    """
    # Mock demisto functions
    mock_params = {"insecure": False, "proxy": False, "feedFetchInterval": "720"}
    mocker.patch("Unit42Feed.demisto.params", return_value=mock_params)
    mocker.patch("Unit42Feed.demisto.command", return_value="test-module")
    mocker.patch("Unit42Feed.demisto.getLicenseID", return_value="test_license")
    mock_return_results = mocker.patch("Unit42Feed.return_results")

    # Mock Client and test_module
    mock_client = mocker.Mock()
    mocker.patch("Unit42Feed.Client", return_value=mock_client)
    mocker.patch("Unit42Feed.test_module", return_value="ok")

    main()

    mock_return_results.assert_called_once_with("ok")


def test_main_function_fetch_indicators(mocker):
    """
    Given:
        - Main function with fetch-indicators command
    When:
        - Calling main function
    Then:
        - Executes fetch_indicators and creates indicators
    """
    # Mock demisto functions
    mock_params = {"insecure": False, "proxy": False, "feedFetchInterval": "720"}
    mocker.patch("Unit42Feed.demisto.params", return_value=mock_params)
    mocker.patch("Unit42Feed.demisto.command", return_value="fetch-indicators")
    mocker.patch("Unit42Feed.demisto.getLicenseID", return_value="test_license")
    mock_create_indicators = mocker.patch("Unit42Feed.demisto.createIndicators")
    mock_set_last_run = mocker.patch("Unit42Feed.demisto.setLastRun")
    mock_info = mocker.patch("Unit42Feed.demisto.info")

    # Mock Client and fetch_indicators
    mock_client = mocker.Mock()
    mocker.patch("Unit42Feed.Client", return_value=mock_client)
    mock_indicators = [{"value": "1.2.3.4", "type": "IP"}]
    mocker.patch("Unit42Feed.fetch_indicators", return_value=mock_indicators)
    mocker.patch("Unit42Feed.datetime")

    # Mock batch function
    mocker.patch("Unit42Feed.batch", return_value=[mock_indicators])

    main()

    mock_create_indicators.assert_called_once()
    mock_set_last_run.assert_called_once()
    mock_info.assert_called_once()


def test_main_function_get_indicators_command(mocker):
    """
    Given:
        - Main function with unit42-get-indicators command
    When:
        - Calling main function
    Then:
        - Executes get_indicators_command and returns results
    """
    # Mock demisto functions
    mock_params = {"insecure": False, "proxy": False, "feedFetchInterval": "720"}
    mocker.patch("Unit42Feed.demisto.params", return_value=mock_params)
    mocker.patch("Unit42Feed.demisto.command", return_value="unit42-get-indicators")
    mocker.patch("Unit42Feed.demisto.args", return_value={"limit": "10"})
    mocker.patch("Unit42Feed.demisto.getLicenseID", return_value="test_license")
    mock_return_results = mocker.patch("Unit42Feed.return_results")

    # Mock Client and command
    mock_client = mocker.Mock()
    mocker.patch("Unit42Feed.Client", return_value=mock_client)
    mock_command_results = mocker.Mock()
    mocker.patch("Unit42Feed.get_indicators_command", return_value=mock_command_results)

    main()

    mock_return_results.assert_called_once_with(mock_command_results)


def test_main_function_get_threat_objects_command(mocker):
    """
    Given:
        - Main function with unit42-get-threat-objects command
    When:
        - Calling main function
    Then:
        - Executes get_threat_objects_command and returns results
    """
    # Mock demisto functions
    mock_params = {"insecure": False, "proxy": False, "feedFetchInterval": "720"}
    mocker.patch("Unit42Feed.demisto.params", return_value=mock_params)
    mocker.patch("Unit42Feed.demisto.command", return_value="unit42-get-threat-objects")
    mocker.patch("Unit42Feed.demisto.args", return_value={"limit": "5"})
    mocker.patch("Unit42Feed.demisto.getLicenseID", return_value="test_license")
    mock_return_results = mocker.patch("Unit42Feed.return_results")

    # Mock Client and command
    mock_client = mocker.Mock()
    mocker.patch("Unit42Feed.Client", return_value=mock_client)
    mock_command_results = mocker.Mock()
    mocker.patch("Unit42Feed.get_threat_objects_command", return_value=mock_command_results)

    main()

    mock_return_results.assert_called_once_with(mock_command_results)


def test_main_function_invalid_fetch_interval(mocker):
    """
    Given:
        - Main function with invalid feedFetchInterval (less than 720 minutes)
    When:
        - Calling main function
    Then:
        - Returns error about minimum fetch interval
    """
    # Mock demisto functions
    mock_params = {
        "insecure": False,
        "proxy": False,
        "feedFetchInterval": "600",  # Less than 720 minutes
    }
    mocker.patch("Unit42Feed.demisto.params", return_value=mock_params)
    mock_return_error = mocker.patch("Unit42Feed.return_error")

    main()

    mock_return_error.assert_called_once_with("Feed Fetch Interval parameter must be set to at least 12 hours.")


def test_main_function_exception_handling(mocker):
    """
    Given:
        - Main function that encounters an exception
    When:
        - Calling main function
    Then:
        - Handles exception and returns error message
    """
    # Mock demisto functions
    mock_params = {"insecure": False, "proxy": False, "feedFetchInterval": "720"}
    mocker.patch("Unit42Feed.demisto.params", return_value=mock_params)
    mocker.patch("Unit42Feed.demisto.command", return_value="test-module")
    mocker.patch("Unit42Feed.demisto.getLicenseID", return_value="test_license")
    mock_return_error = mocker.patch("Unit42Feed.return_error")

    # Mock Client to raise exception
    mocker.patch("Unit42Feed.Client", side_effect=Exception("Test error"))

    main()

    mock_return_error.assert_called_once()
    error_call = mock_return_error.call_args[0][0]
    assert "Failed to execute test-module command" in error_call
    assert "Test error" in error_call
