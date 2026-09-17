import pytest
from datetime import datetime, timedelta
from Unit42Feed import (
    Client,
    create_publications,
    get_threat_object_score,
    create_location_indicators_and_relationships,
    build_threat_object_description,
    test_module as unit42_test_module,
    unit42_error_handler,
    main,
    fetch_indicator_type,
    fetch_threat_objects_with_limit,
    INDICATOR_TYPE_MAPPING,
    VERDICT_TO_SCORE,
    VALID_REGIONS,
    DATE_FORMAT,
    API_LIMIT,
    INTEGRATION_NAME,
    RETRY_COUNT,
    STATUS_CODES_TO_RETRY,
    THREAT_OBJECTS_TYPE,
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
        error_handler=unit42_error_handler,
        retries=RETRY_COUNT,
        status_list_to_retry=STATUS_CODES_TO_RETRY,
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
        method="GET",
        url_suffix="/api/v1/feeds/indicators",
        error_handler=unit42_error_handler,
        retries=RETRY_COUNT,
        status_list_to_retry=STATUS_CODES_TO_RETRY,
        params={"indicator_types": ["filehash_sha256"], "limit": 5000},
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
        method="GET",
        url_suffix="/api/v1/feeds/threat_objects",
        error_handler=unit42_error_handler,
        retries=RETRY_COUNT,
        status_list_to_retry=STATUS_CODES_TO_RETRY,
        params={"limit": 50, "page_token": "test_token"},
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
    # Set a valid fetch interval so the guard passes and the connection logic runs
    mocker.patch("Unit42Feed.demisto.params", return_value={"feedFetchInterval": "60"})
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
    # Set a valid fetch interval so the guard passes and the connection logic runs
    mocker.patch("Unit42Feed.demisto.params", return_value={"feedFetchInterval": "60"})
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
    # Set a valid fetch interval so the guard passes and the connection logic runs
    mocker.patch("Unit42Feed.demisto.params", return_value={"feedFetchInterval": "60"})
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
    assert INDICATOR_TYPE_MAPPING["malicious_tool"] == ThreatIntel.ObjectsNames.TOOL
    assert INDICATOR_TYPE_MAPPING["attack_pattern"] == ThreatIntel.ObjectsNames.ATTACK_PATTERN
    assert INDICATOR_TYPE_MAPPING["vulnerability"] == FeedIndicatorType.CVE
    assert INDICATOR_TYPE_MAPPING["grayware"] == ThreatIntel.ObjectsNames.MALWARE
    assert "generic" not in INDICATOR_TYPE_MAPPING


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
        - Pushes both indicators and threat objects to the server immediately
        - Returns the total count fetched
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

    mock_create_indicators = mocker.patch("Unit42Feed.demisto.createIndicators")

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
    result, next_run = fetch_indicators(client, params, current_time)

    assert result >= 2  # At least one indicator and one threat object
    # Nothing left to resume, so only the last successful run time is stored. Threat objects were
    # fetched and completed this run (fresh run, none stored before), so the 24h window is reset:
    # last_threat_objects_fetch is written as the current fetch time.
    assert next_run == {
        "last_successful_run": current_time.strftime(DATE_FORMAT),
        "last_threat_objects_fetch": current_time.strftime(DATE_FORMAT),
    }

    # Check that both indicators and threat objects were pushed to the server
    pushed_items = [item for call in mock_create_indicators.call_args_list for item in call[0][0]]
    pushed_types = [item["type"] for item in pushed_items]
    assert FeedIndicatorType.IP in pushed_types
    assert ThreatIntel.ObjectsNames.THREAT_ACTOR in pushed_types


def test_fetch_indicators_pagination(client, mocker):
    """
    Given:
        - Unit42Feed client with paginated API responses
    When:
        - Calling fetch_indicators function
    Then:
        - Handles pagination correctly
        - Fetches multiple pages until limit or no more pages
        - Pushes indicators from both pages to the server
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
    mock_create_indicators = mocker.patch("Unit42Feed.demisto.createIndicators")

    params = {"feed_types": ["Indicators"], "indicator_types": ["ip"], "feed_tags": [], "tlp_color": None}

    current_time = datetime.now()
    result, next_run = fetch_indicators(client, params, current_time)

    assert result == 2
    assert next_run == {"last_successful_run": current_time.strftime(DATE_FORMAT)}

    # Should have indicators from both pages, pushed to the server
    pushed_items = [item for call in mock_create_indicators.call_args_list for item in call[0][0]]
    ip_indicators = [item for item in pushed_items if item["type"] == FeedIndicatorType.IP]
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
    mock_params = {"insecure": False, "proxy": False, "feedFetchInterval": "60"}
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
        - Executes fetch_indicators, which pushes indicators to the server internally
        - main() itself no longer accumulates or re-batches indicators
    """
    # Mock demisto functions
    mock_params = {"insecure": False, "proxy": False, "feedFetchInterval": "60"}
    mocker.patch("Unit42Feed.demisto.params", return_value=mock_params)
    mocker.patch("Unit42Feed.demisto.command", return_value="fetch-indicators")
    mocker.patch("Unit42Feed.demisto.getLicenseID", return_value="test_license")
    mock_set_last_run = mocker.patch("Unit42Feed.demisto.setLastRun")
    mock_info = mocker.patch("Unit42Feed.demisto.info")

    # Mock Client and fetch_indicators (fetch_indicators now returns a count and pushes internally)
    mock_client = mocker.Mock()
    mocker.patch("Unit42Feed.Client", return_value=mock_client)
    next_run = {"last_successful_run": "2023-06-02T12:00:00Z"}
    mock_fetch_indicators = mocker.patch("Unit42Feed.fetch_indicators", return_value=(1, next_run))
    mocker.patch("Unit42Feed.datetime")

    main()

    mock_fetch_indicators.assert_called_once()
    # main() stores whatever next run state fetch_indicators produced
    mock_set_last_run.assert_called_once_with(next_run)
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
    mock_params = {"insecure": False, "proxy": False, "feedFetchInterval": "60"}
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
    mock_params = {"insecure": False, "proxy": False, "feedFetchInterval": "60"}
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
    mock_params = {"insecure": False, "proxy": False, "feedFetchInterval": "60"}
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


def test_unit42_error_handler_with_request_id(mocker):
    """
    Given:
        - A mock requests.Response object with a status code, URL, and an X-Request-ID header.
    When:
        - Calling unit42_error_handler.
    Then:
        - demisto.return_error is called with a formatted error message including the X-Request-ID.
    """
    mock_response = mocker.Mock()
    mock_response.status_code = 500
    mock_response.url = "https://example.com/api"
    mock_response.text = "Internal Server Error"
    mock_response.headers = {"X-Request-ID": "test-request-id-123"}

    mocker.patch.object(demisto, "debug")
    mock_return_error = mocker.patch("Unit42Feed.return_error")

    unit42_error_handler(mock_response)

    expected_error_msg = (
        "Error in API request [Status: 500]\n" "[X-Request-ID: test-request-id-123]\n" "Response text - Internal Server Error"
    )
    mock_return_error.assert_called_once_with(expected_error_msg)
    demisto.debug.assert_called_once_with(
        f"{INTEGRATION_NAME} API Error - X-Request-ID: test-request-id-123, Status: 500, URL: https://example.com/api"
    )


def test_fetch_indicator_type_with_limit(client, mocker):
    """
    Given:
        - Client and limit parameter
    When:
        - Calling fetch_indicator_type with limit smaller than API response
    Then:
        - Fetches full pages without truncation, so the count may overshoot the limit
        - Pushes every parsed indicator from each fetched page to the server
        - Makes correct API calls with page_limit
    """
    # Mock responses - first page has 100 items, second page has 50
    first_response = {
        "data": [{"indicator_value": f"1.2.3.{i}", "indicator_type": "ip", "verdict": "malicious"} for i in range(100)],
        "metadata": {"next_page_token": "page2"},
    }

    second_response = {
        "data": [{"indicator_value": f"5.6.7.{i}", "indicator_type": "ip", "verdict": "malicious"} for i in range(50)],
        "metadata": {"next_page_token": None},
    }

    mock_get_indicators = mocker.patch.object(client, "get_indicators")
    mock_get_indicators.side_effect = [first_response, second_response]
    mock_create_indicators = mocker.patch("Unit42Feed.demisto.createIndicators")

    # Fetch with limit of 120: first page pushes 100 (total 100 < 120 -> fetch again),
    # second page pushes its full 50 (total 150), overshooting the limit by one page
    result, next_page_token = fetch_indicator_type(
        client=client, indicator_types=["IP"], limit=120, start_time="2023-01-01T00:00:00Z", feed_tags=[], tlp_color=None
    )

    assert result == 150
    assert next_page_token is None  # Last page reported no further pages
    assert mock_get_indicators.call_count == 2

    pushed_items = [item for call in mock_create_indicators.call_args_list for item in call[0][0]]
    assert len(pushed_items) == 150

    # Check first call had limit of 100 (min of API_LIMIT and remaining)
    first_call_args = mock_get_indicators.call_args_list[0][1]
    assert first_call_args["limit"] <= API_LIMIT

    # Check second call requested only the remaining 20 (page_limit), even though the
    # mocked page returns 50 and the full page is still pushed
    second_call_args = mock_get_indicators.call_args_list[1][1]
    assert second_call_args["limit"] == 20


def test_fetch_indicator_type_stops_at_limit(client, mocker):
    """
    Given:
        - Client with API returning more data than limit
    When:
        - Calling fetch_indicator_type with small limit
    Then:
        - Pushes the full first page without truncation, so the count overshoots the limit
        - Stops fetching further pages once the limit is met or exceeded
        - Returns the page token so the surplus page's successor can be resumed
    """
    # Mock response with 100 items
    mock_response = {
        "data": [{"indicator_value": f"1.2.3.{i}", "indicator_type": "ip", "verdict": "malicious"} for i in range(100)],
        "metadata": {"next_page_token": "page2"},
    }

    mock_get_indicators = mocker.patch.object(client, "get_indicators", return_value=mock_response)
    mocker.patch("Unit42Feed.demisto.createIndicators")

    # Fetch with limit of 50: the full 100-item page is pushed (total 100), then the
    # while-guard sees 100 >= 50 and stops before fetching another page
    result, next_page_token = fetch_indicator_type(
        client=client, indicator_types=["IP"], limit=50, start_time="2023-01-01T00:00:00Z", feed_tags=[], tlp_color=None
    )

    assert result == 100
    # Limit was hit while more pages exist, so the token is returned for the next fetch
    assert next_page_token == "page2"
    assert mock_get_indicators.call_count == 1  # Should only make one call


def test_fetch_indicator_type_no_data(client, mocker):
    """
    Given:
        - Client with API returning no data
    When:
        - Calling fetch_indicator_type
    Then:
        - Returns a count of zero
        - Handles gracefully
    """
    mock_response = {"data": [], "metadata": {}}
    mocker.patch.object(client, "get_indicators", return_value=mock_response)
    mock_create_indicators = mocker.patch("Unit42Feed.demisto.createIndicators")

    result, next_page_token = fetch_indicator_type(
        client=client, indicator_types=["IP"], limit=100, start_time="2023-01-01T00:00:00Z", feed_tags=[], tlp_color=None
    )

    assert result == 0
    assert next_page_token is None
    mock_create_indicators.assert_not_called()


def test_fetch_threat_objects_with_limit(client, mocker):
    """
    Given:
        - Client and limit parameter
    When:
        - Calling fetch_threat_objects_with_limit
    Then:
        - Counts consumed API objects (len(data)) and fetches full pages without truncation
        - Pushes every parsed threat object from each page, overshooting the limit by one page
        - Handles pagination correctly
    """
    mock_demisto_params(mocker)

    # Mock responses. These threat objects have no regions, so each maps to exactly one
    # indicator (no location expansion); len(data) therefore equals the pushed count.
    first_response = {
        "data": [{"name": f"APT{i}", "threat_object_class": "actor", "publications": []} for i in range(100)],
        "metadata": {"next_page_token": "page2"},
    }

    second_response = {
        "data": [{"name": f"Malware{i}", "threat_object_class": "malware_family", "publications": []} for i in range(50)],
        "metadata": {"next_page_token": None},
    }

    mock_get_threat_objects = mocker.patch.object(client, "get_threat_objects")
    mock_get_threat_objects.side_effect = [first_response, second_response]
    mock_create_indicators = mocker.patch("Unit42Feed.demisto.createIndicators")

    # Fetch with limit of 120: first page consumes 100 API objects (total 100 < 120 ->
    # fetch again), second page consumes its full 50 (total 150), overshooting the limit
    result, next_page_token = fetch_threat_objects_with_limit(client=client, limit=120, feed_tags=[], tlp_color=None)

    assert result == 150
    assert next_page_token is None
    assert mock_get_threat_objects.call_count == 2

    pushed_items = [item for call in mock_create_indicators.call_args_list for item in call[0][0]]
    assert len(pushed_items) == 150


def test_fetch_indicators_limit_validation(client, mocker):
    """
    Given:
        - Client with various limit values
    When:
        - Calling fetch_indicators with different limits
    Then:
        - Validates and caps limit at TOTAL_INDICATOR_LIMIT
        - Uses DEFAULT_LIMIT when limit is invalid
    """
    from Unit42Feed import fetch_indicators

    mock_demisto_params(mocker)
    mock_response = {"data": [], "metadata": {}}
    mocker.patch.object(client, "get_indicators", return_value=mock_response)
    mocker.patch.object(client, "get_threat_objects", return_value=mock_response)
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={})

    current_time = datetime.now()

    # Test with a very large limit: the empty API response means nothing is fetched and the
    # cycle completes cleanly, proving the (large) limit is accepted rather than rejected.
    params_high = {
        "limit": "150000",  # Above TOTAL_INDICATOR_LIMIT, still a valid positive limit
        "feed_types": ["Indicators"],
        "indicator_types": ["IP"],
        "feedTags": [],
        "tlp_color": None,
    }

    total_high, next_run_high = fetch_indicators(client, params_high, current_time)
    assert total_high == 0
    assert next_run_high == {"last_successful_run": current_time.strftime(DATE_FORMAT)}

    # Test with zero limit: guarded and replaced by TOTAL_INDICATOR_LIMIT, so the fetch still
    # runs (does not short-circuit to zero budget) and completes the cycle normally.
    params_zero = {
        "limit": "0",
        "feed_types": ["Indicators"],
        "indicator_types": ["IP"],
        "feedTags": [],
        "tlp_color": None,
    }

    total_zero, next_run_zero = fetch_indicators(client, params_zero, current_time)
    assert total_zero == 0
    assert next_run_zero == {"last_successful_run": current_time.strftime(DATE_FORMAT)}


def test_fetch_indicators_threat_objects_first_then_single_combined_indicator_query(client, mocker):
    """
    Given:
        - Client with all indicator types configured and Threat Objects enabled
    When:
        - Calling fetch_indicators
    Then:
        - Threat Objects are fetched first (before any indicators)
        - All configured indicator types are fetched together in ONE combined get_indicators
          call that carries the full list of types, rather than one call per type
    """
    from Unit42Feed import fetch_indicators

    mock_demisto_params(mocker)

    # Track the order of API calls and the types passed to the combined indicator query.
    call_order = []
    indicator_types_calls = []

    def track_get_indicators(*args, **kwargs):
        indicator_types = kwargs.get("indicator_types", [])
        indicator_types_calls.append(indicator_types)
        call_order.append("Indicators")
        return {
            "data": [{"indicator_value": "test", "indicator_type": "ip", "verdict": "malicious"}],
            "metadata": {"next_page_token": None},
        }

    def track_get_threat_objects(*args, **kwargs):
        call_order.append("ThreatObjects")
        return {
            "data": [{"name": "APT29", "threat_object_class": "actor", "publications": []}],
            "metadata": {"next_page_token": None},
        }

    mock_get_indicators = mocker.patch.object(client, "get_indicators", side_effect=track_get_indicators)
    mocker.patch.object(client, "get_threat_objects", side_effect=track_get_threat_objects)
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={})

    configured_types = ["File", "URL", "Domain", "IP"]
    params = {
        "limit": "10",
        "feed_types": ["Indicators", "Threat Objects"],
        "indicator_types": configured_types,
        "feedTags": [],
        "tlp_color": None,
    }

    current_time = datetime.now()
    fetch_indicators(client, params, current_time)

    # Threat objects are fetched before indicators.
    assert call_order[0] == "ThreatObjects"
    assert "Indicators" in call_order
    assert call_order.index("ThreatObjects") < call_order.index("Indicators")

    # Indicators are fetched in ONE combined query carrying the full type list, not per-type.
    assert mock_get_indicators.call_count == 1
    assert indicator_types_calls[0] == configured_types


def test_fetch_indicator_type_pagination(client, mocker):
    """
    Given:
        - Client with paginated API responses
        - Limit requiring multiple pages
    When:
        - Calling fetch_indicator_type
    Then:
        - Fetches multiple pages until the limit is met or exceeded
        - Pushes each page in full, so the final page overshoots the limit
        - Calculates correct page_limit for each request
    """
    # Create responses for pagination
    responses = []
    for page in range(3):
        responses.append(
            {
                "data": [
                    {"indicator_value": f"1.2.{page}.{i}", "indicator_type": "ip", "verdict": "malicious"} for i in range(100)
                ],
                "metadata": {"next_page_token": f"page{page+2}" if page < 2 else None},
            }
        )

    mock_get_indicators = mocker.patch.object(client, "get_indicators")
    mock_get_indicators.side_effect = responses
    mocker.patch("Unit42Feed.demisto.createIndicators")

    # Fetch with limit of 250: pages push 100 + 100 (total 200 < 250 -> fetch again) then
    # the third page pushes its full 100, reaching 300 and overshooting the limit
    result, next_page_token = fetch_indicator_type(
        client=client, indicator_types=["IP"], limit=250, start_time="2023-01-01T00:00:00Z", feed_tags=[], tlp_color=None
    )

    assert result == 300
    assert next_page_token is None
    assert mock_get_indicators.call_count == 3

    # Verify the third call requested only 50 (remaining), even though the full 100-item
    # page is still pushed
    third_call_args = mock_get_indicators.call_args_list[2][1]
    assert third_call_args["limit"] == 50


def test_fetch_threat_objects_with_limit_stops_early(client, mocker):
    """
    Given:
        - Client with API returning fewer results than limit
    When:
        - Calling fetch_threat_objects_with_limit
    Then:
        - Stops when no more data available
        - Returns all available data (less than limit)
    """
    mock_demisto_params(mocker)

    mock_response = {
        "data": [{"name": f"APT{i}", "threat_object_class": "actor", "publications": []} for i in range(25)],
        "metadata": {"next_page_token": None},
    }

    mock_get_threat_objects = mocker.patch.object(client, "get_threat_objects", return_value=mock_response)
    mocker.patch("Unit42Feed.demisto.createIndicators")

    # Request limit of 100, but only 25 available
    result, next_page_token = fetch_threat_objects_with_limit(client=client, limit=100, feed_tags=[], tlp_color=None)

    assert result == 25
    assert next_page_token is None
    assert mock_get_threat_objects.call_count == 1


def test_create_vulnerabilities_relationships_unknown_threat_class(mocker):
    """
    Given:
        - A threat object with an unknown threat_object_class (e.g. 'generic')
    When:
        - create_vulnerabilities_relationships is called
    Then:
        - Returns empty list without raising a KeyError
    """
    from Unit42Feed import create_vulnerabilities_relationships

    result = create_vulnerabilities_relationships({}, "SomeName", "generic")
    assert result == []


def test_create_actor_relationships_unknown_threat_class(mocker):
    """
    Given:
        - A threat object with an unknown threat_object_class (e.g. 'generic')
    When:
        - create_actor_relationships is called
    Then:
        - Returns empty list without raising a KeyError
    """
    from Unit42Feed import create_actor_relationships

    result = create_actor_relationships({}, "SomeName", "generic")
    assert result == []


def test_create_tools_relationships_unknown_threat_class(mocker):
    """
    Given:
        - A threat object with an unknown threat_object_class (e.g. 'generic')
    When:
        - create_tools_relationships is called
    Then:
        - Returns empty list without raising a KeyError
    """
    from Unit42Feed import create_tools_relationships

    result = create_tools_relationships({}, "SomeName", "generic")
    assert result == []


def test_create_malware_relationships_unknown_threat_class(mocker):
    """
    Given:
        - A threat object with an unknown threat_object_class (e.g. 'generic')
    When:
        - create_malware_relationships is called
    Then:
        - Returns empty list without raising a KeyError
    """
    from Unit42Feed import create_malware_relationships

    result = create_malware_relationships({}, "SomeName", "generic")
    assert result == []


def test_create_attack_patterns_relationships_unknown_threat_class(mocker):
    """
    Given:
        - A threat object with an unknown threat_object_class (e.g. 'generic')
    When:
        - create_attack_patterns_relationships is called
    Then:
        - Returns empty list without raising a KeyError
    """
    from Unit42Feed import create_attack_patterns_relationships

    result = create_attack_patterns_relationships({}, "SomeName", "generic")
    assert result == []


def test_create_campaigns_relationships_unknown_threat_class(mocker):
    """
    Given:
        - A threat object with an unknown threat_object_class (e.g. 'generic')
    When:
        - create_campaigns_relationships is called
    Then:
        - Returns empty list without raising a KeyError
    """
    from Unit42Feed import create_campaigns_relationships

    result = create_campaigns_relationships({}, "SomeName", "generic")
    assert result == []


def test_parse_threat_objects_unknown_threat_class(mocker):
    """
    Given:
        - A threat object with an unknown threat_object_class (e.g. 'malicious_tool')
          that was previously causing a KeyError crash
    When:
        - parse_threat_objects is called
    Then:
        - Does not raise a KeyError
        - Returns the threat object mapped to the correct XSOAR type (Tool)
    """
    from Unit42Feed import parse_threat_objects

    mock_demisto_params(mocker)

    threat_objects_data = [
        {"name": "ScreenConnect", "threat_object_class": "malicious_tool", "publications": []},
    ]

    result = parse_threat_objects(threat_objects_data)

    main_objects = [obj for obj in result if obj["type"] == ThreatIntel.ObjectsNames.TOOL]
    assert len(main_objects) == 1
    assert main_objects[0]["value"] == "ScreenConnect"


def test_fetch_indicator_type_resumes_from_page_token(client, mocker):
    """
    Given:
        - A page token from a previous fetch that stopped at the limit
    When:
        - Calling fetch_indicator_type with that next_page_token
    Then:
        - The first API call is made with the given page token instead of starting from scratch
    """
    mock_response = {
        "data": [{"indicator_value": "1.2.3.4", "indicator_type": "ip", "verdict": "malicious"}],
        "metadata": {"next_page_token": None},
    }
    mock_get_indicators = mocker.patch.object(client, "get_indicators", return_value=mock_response)
    mocker.patch("Unit42Feed.demisto.createIndicators")

    result, next_page_token = fetch_indicator_type(
        client=client,
        indicator_types=["IP"],
        limit=100,
        start_time="2023-01-01T00:00:00Z",
        feed_tags=[],
        tlp_color=None,
        next_page_token="resume_token",
    )

    assert result == 1
    assert next_page_token is None
    assert mock_get_indicators.call_args_list[0][1]["next_page_token"] == "resume_token"


def test_fetch_threat_objects_resumes_from_page_token(client, mocker):
    """
    Given:
        - A page token from a previous threat objects fetch that stopped at the limit
    When:
        - Calling fetch_threat_objects_with_limit with that next_page_token
    Then:
        - The first API call is made with the given page token
    """
    mock_demisto_params(mocker)

    mock_response = {
        "data": [{"name": "APT29", "threat_object_class": "actor", "publications": []}],
        "metadata": {"next_page_token": None},
    }
    mock_get_threat_objects = mocker.patch.object(client, "get_threat_objects", return_value=mock_response)
    mocker.patch("Unit42Feed.demisto.createIndicators")

    result, next_page_token = fetch_threat_objects_with_limit(
        client=client, limit=100, feed_tags=[], tlp_color=None, next_page_token="resume_token"
    )

    assert result == 1
    assert next_page_token is None
    assert mock_get_threat_objects.call_args_list[0][1]["next_page_token"] == "resume_token"


def test_fetch_threat_objects_returns_token_when_limit_hit(client, mocker):
    """
    Given:
        - An API returning more threat objects than the requested limit, with more pages available
    When:
        - Calling fetch_threat_objects_with_limit
    Then:
        - Pushes the full first page without truncation, so the count overshoots the limit
        - Stops fetching further pages once the limit is met or exceeded
        - Returns the page token to resume from
    """
    mock_demisto_params(mocker)

    mock_response = {
        "data": [{"name": f"APT{i}", "threat_object_class": "actor", "publications": []} for i in range(100)],
        "metadata": {"next_page_token": "page2"},
    }
    mocker.patch.object(client, "get_threat_objects", return_value=mock_response)
    mocker.patch("Unit42Feed.demisto.createIndicators")

    # Limit of 50: the full 100-object page is consumed (total 100), then the while-guard
    # sees 100 >= 50 and stops before fetching another page
    result, next_page_token = fetch_threat_objects_with_limit(client=client, limit=50, feed_tags=[], tlp_color=None)

    assert result == 100
    assert next_page_token == "page2"


def test_fetch_indicator_type_invalid_response_clears_token(client, mocker):
    """
    Given:
        - A first page with a next page token, followed by an invalid (None) response
    When:
        - Calling fetch_indicator_type
    Then:
        - The stale token from the first page is cleared, so no pending work is reported
    """
    first_response = {
        "data": [{"indicator_value": "1.2.3.4", "indicator_type": "ip", "verdict": "malicious"}],
        "metadata": {"next_page_token": "page2"},
    }

    mock_get_indicators = mocker.patch.object(client, "get_indicators")
    mock_get_indicators.side_effect = [first_response, None]
    mocker.patch("Unit42Feed.demisto.createIndicators")

    result, next_page_token = fetch_indicator_type(
        client=client, indicator_types=["IP"], limit=100, start_time="2023-01-01T00:00:00Z", feed_tags=[], tlp_color=None
    )

    assert result == 1
    assert next_page_token is None


def test_fetch_indicator_type_empty_page_clears_token(client, mocker):
    """
    Given:
        - A first page with a next page token, followed by a page with no data
    When:
        - Calling fetch_indicator_type
    Then:
        - The stale token from the first page is cleared, so no pending work is reported
    """
    first_response = {
        "data": [{"indicator_value": "1.2.3.4", "indicator_type": "ip", "verdict": "malicious"}],
        "metadata": {"next_page_token": "page2"},
    }
    second_response = {"data": [], "metadata": {"next_page_token": "page3"}}

    mock_get_indicators = mocker.patch.object(client, "get_indicators")
    mock_get_indicators.side_effect = [first_response, second_response]
    mocker.patch("Unit42Feed.demisto.createIndicators")

    result, next_page_token = fetch_indicator_type(
        client=client, indicator_types=["IP"], limit=100, start_time="2023-01-01T00:00:00Z", feed_tags=[], tlp_color=None
    )

    assert result == 1
    assert next_page_token is None


def test_fetch_indicators_stores_pending_when_limit_hit(client, mocker):
    """
    Given:
        - An API with more indicators available than the configured total limit
    When:
        - Calling fetch_indicators
    Then:
        - The full first page is pushed without truncation, so the count overshoots the limit
        - The next run holds the indicators page token under the pending dict and the
          original start time
        - No last_successful_run is stored, so the same time window is resumed
    """
    from Unit42Feed import fetch_indicators

    mock_demisto_params(mocker)

    mock_response = {
        "data": [{"indicator_value": f"1.2.3.{i}", "indicator_type": "ip", "verdict": "malicious"} for i in range(100)],
        "metadata": {"next_page_token": "page2"},
    }
    mocker.patch.object(client, "get_indicators", return_value=mock_response)
    mocker.patch("Unit42Feed.demisto.createIndicators")
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={"last_successful_run": "2023-06-01T12:00:00Z"})

    params = {"limit": "50", "feed_types": ["Indicators"], "indicator_types": ["IP"], "feedTags": [], "tlp_color": None}

    current_time = datetime(2023, 6, 2, 12, 0, 0)
    total_fetched, next_run = fetch_indicators(client, params, current_time)

    # Limit of 50 vs a 100-item page: the full page is pushed (total 100) before the guard stops
    assert total_fetched == 100
    assert next_run == {
        "start_time": "2023-06-01T12:00:00Z",
        "cycle_start_time": "2023-06-02T12:00:00Z",
        "page_tokens": {"indicators": "page2"},
    }
    assert "last_successful_run" not in next_run


def test_fetch_indicators_resumes_pending(client, mocker):
    """
    Given:
        - A last run holding a pending indicators token and the start time of the interrupted fetch
    When:
        - Calling fetch_indicators
    Then:
        - Only the pending indicators feed is fetched, resumed from its page token
        - Threat objects (which had no pending token) are skipped
        - The stored start time is reused instead of last_successful_run
    """
    from Unit42Feed import fetch_indicators

    mock_demisto_params(mocker)

    mock_response = {
        "data": [{"indicator_value": "1.2.3.4", "indicator_type": "ip", "verdict": "malicious"}],
        "metadata": {"next_page_token": None},
    }
    mock_get_indicators = mocker.patch.object(client, "get_indicators", return_value=mock_response)
    mock_get_threat_objects = mocker.patch.object(client, "get_threat_objects")
    mocker.patch("Unit42Feed.demisto.createIndicators")
    mocker.patch(
        "Unit42Feed.demisto.getLastRun",
        return_value={
            "start_time": "2023-06-01T12:00:00Z",
            "cycle_start_time": "2023-06-02T12:00:00Z",
            "page_tokens": {"indicators": "page2"},
        },
    )

    params = {
        "limit": "50",
        "feed_types": ["Indicators", "Threat Objects"],
        "indicator_types": ["IP", "Domain"],
        "feedTags": [],
        "tlp_color": None,
    }

    current_time = datetime(2023, 6, 2, 12, 0, 0)
    total_fetched, next_run = fetch_indicators(client, params, current_time)

    assert total_fetched == 1

    # Only the pending indicators feed was fetched - threat objects had no pending token.
    assert mock_get_indicators.call_count == 1
    mock_get_threat_objects.assert_not_called()

    call_kwargs = mock_get_indicators.call_args[1]
    assert call_kwargs["next_page_token"] == "page2"
    assert call_kwargs["start_time"] == "2023-06-01T12:00:00Z"

    # Everything pending was consumed, so the cycle completes normally.
    assert next_run == {"last_successful_run": "2023-06-02T12:00:00Z"}


def test_fetch_indicators_pending_without_start_time(client, mocker):
    """
    Given:
        - A last run with a pending cycle in progress but no stored start time
    When:
        - Calling fetch_indicators
    Then:
        - Falls back to the default start time (24 hours ago)
    """
    from Unit42Feed import fetch_indicators

    mock_demisto_params(mocker)

    mock_response = {"data": [], "metadata": {}}
    mock_get_indicators = mocker.patch.object(client, "get_indicators", return_value=mock_response)
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={"page_tokens": {"indicators": "page2"}})

    params = {"feed_types": ["Indicators"], "indicator_types": ["IP"], "feedTags": [], "tlp_color": None}

    current_time = datetime(2023, 6, 2, 12, 0, 0)
    fetch_indicators(client, params, current_time)

    expected_default = (current_time - timedelta(hours=24)).strftime(DATE_FORMAT)
    assert mock_get_indicators.call_args[1]["start_time"] == expected_default


def test_fetch_indicators_stores_pending_threat_objects(client, mocker):
    """
    Given:
        - Threat objects with more pages available than the configured limit allows
    When:
        - Calling fetch_indicators
    Then:
        - The threat objects page token is stored as pending under the "threat_objects" key
    """
    from Unit42Feed import fetch_indicators

    mock_demisto_params(mocker)

    mock_response = {
        "data": [{"name": f"APT{i}", "threat_object_class": "actor", "publications": []} for i in range(100)],
        "metadata": {"next_page_token": "page2"},
    }
    mocker.patch.object(client, "get_threat_objects", return_value=mock_response)
    mocker.patch("Unit42Feed.demisto.createIndicators")
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={})

    params = {"limit": "50", "feed_types": ["Threat Objects"], "indicator_types": [], "feedTags": [], "tlp_color": None}

    current_time = datetime(2023, 6, 2, 12, 0, 0)
    _, next_run = fetch_indicators(client, params, current_time)

    assert next_run["page_tokens"] == {"threat_objects": "page2"}


def test_fetch_indicators_threat_objects_consume_budget_indicators_resumed_next_run(client, mocker):
    """
    Given:
        - Both Threat Objects and Indicators are enabled with a small shared total limit
        - Threat objects alone return a full page that meets/exceeds the whole budget, with
          more pages still available
    When:
        - Calling fetch_indicators (run 1), then feeding its next run back in (run 2)
    Then:
        - Run 1: threat objects consume the entire budget, so indicators are NOT queried this
          run, and only the threat objects token is stored as pending.
        - Run 2: threat objects had a pending token (indicators did not), so only threat
          objects resume from that token; indicators remain skipped because the cycle is in
          progress and they never had a token.
    """
    from Unit42Feed import fetch_indicators

    mock_demisto_params(mocker)

    threat_objects_page = {
        "data": [{"name": f"APT{i}", "threat_object_class": "actor", "publications": []} for i in range(100)],
        "metadata": {"next_page_token": "to_page2"},
    }
    mock_get_threat_objects = mocker.patch.object(client, "get_threat_objects", return_value=threat_objects_page)
    mock_get_indicators = mocker.patch.object(client, "get_indicators")
    mocker.patch("Unit42Feed.demisto.createIndicators")
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={})

    params = {
        "limit": "50",
        "feed_types": ["Threat Objects", "Indicators"],
        "indicator_types": ["IP"],
        "feedTags": [],
        "tlp_color": None,
    }

    current_time = datetime(2023, 6, 2, 12, 0, 0)

    # --- Run 1: threat objects consume the whole budget; indicators skipped this run ---
    total_run1, next_run_1 = fetch_indicators(client, params, current_time)

    assert total_run1 == 100  # full threat objects page pushed, exhausting the budget
    mock_get_indicators.assert_not_called()  # no budget left for indicators
    assert next_run_1["page_tokens"] == {"threat_objects": "to_page2"}
    assert "indicators" not in next_run_1["page_tokens"]
    assert "last_successful_run" not in next_run_1

    # --- Run 2: only threat objects (which had a token) resume; indicators still skipped ---
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value=next_run_1)
    total_run2, _ = fetch_indicators(client, params, current_time)

    assert total_run2 == 100
    # Threat objects resumed from the pending token produced in run 1.
    assert mock_get_threat_objects.call_args_list[-1][1]["next_page_token"] == "to_page2"
    # Indicators never had a pending token, so with a cycle in progress they stay skipped.
    mock_get_indicators.assert_not_called()


def test_fetch_indicators_initializes_cycle_start_time_on_first_pending_run(client, mocker):
    """
    Given:
        - A last run holding only last_successful_run (no pending cycle in progress)
        - An API with more indicators available than the configured maximum per fetch
    When:
        - Calling fetch_indicators
    Then:
        - The current fetch time is stored as the cycle start time, marking the start of the cycle
        - The original start time is preserved so the same time window is resumed
        - No last_successful_run is stored while the cycle is still in progress
    """
    from Unit42Feed import fetch_indicators

    mock_demisto_params(mocker)

    mock_response = {
        "data": [{"indicator_value": f"1.2.3.{i}", "indicator_type": "ip", "verdict": "malicious"} for i in range(100)],
        "metadata": {"next_page_token": "page2"},
    }
    mocker.patch.object(client, "get_indicators", return_value=mock_response)
    mocker.patch("Unit42Feed.demisto.createIndicators")
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={"last_successful_run": "2023-06-01T12:00:00Z"})

    params = {"limit": "50", "feed_types": ["Indicators"], "indicator_types": ["IP"], "feedTags": [], "tlp_color": None}

    current_time = datetime(2023, 6, 2, 12, 0, 0)
    _, next_run = fetch_indicators(client, params, current_time)

    assert next_run["cycle_start_time"] == current_time.strftime(DATE_FORMAT)
    assert next_run["start_time"] == "2023-06-01T12:00:00Z"
    assert next_run["page_tokens"] == {"indicators": "page2"}
    assert "last_successful_run" not in next_run


def test_fetch_indicators_carries_cycle_start_time_across_multiple_resumed_runs(client, mocker):
    """
    Given:
        - A fetch cycle that keeps hitting the maximum indicators per fetch limit
    When:
        - Calling fetch_indicators repeatedly, feeding the previous next run back in as the last run
    Then:
        - The cycle start time stays pinned to the run that initiated the cycle
        - The start time stays pinned to the original time window on every resumed run
        - No last_successful_run is stored while the cycle is still in progress
    """
    from Unit42Feed import fetch_indicators

    mock_demisto_params(mocker)

    mock_response = {
        "data": [{"indicator_value": f"1.2.3.{i}", "indicator_type": "ip", "verdict": "malicious"} for i in range(100)],
        "metadata": {"next_page_token": "page2"},
    }
    mocker.patch.object(client, "get_indicators", return_value=mock_response)
    mocker.patch("Unit42Feed.demisto.createIndicators")
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={"last_successful_run": "2023-06-01T12:00:00Z"})

    params = {"limit": "50", "feed_types": ["Indicators"], "indicator_types": ["IP"], "feedTags": [], "tlp_color": None}

    # The run that initiates the pending cycle
    current_time = datetime(2023, 6, 2, 12, 0, 0)
    _, next_run = fetch_indicators(client, params, current_time)

    expected_cycle_start_time = current_time.strftime(DATE_FORMAT)
    assert next_run["cycle_start_time"] == expected_cycle_start_time

    # Three more interrupted runs, each resuming the pending cycle
    for hours in range(1, 4):
        mocker.patch("Unit42Feed.demisto.getLastRun", return_value=next_run)
        _, next_run = fetch_indicators(client, params, current_time + timedelta(hours=hours))

        assert next_run["cycle_start_time"] == expected_cycle_start_time
        assert next_run["start_time"] == "2023-06-01T12:00:00Z"
        assert next_run["page_tokens"] == {"indicators": "page2"}
        assert "last_successful_run" not in next_run


def test_fetch_indicators_stores_original_cycle_start_time_when_pending_exhausted(client, mocker):
    """
    Given:
        - A last run holding pending units and the cycle start time of the interrupted fetch
        - An API that returns no further pages, so the pending cycle completes
    When:
        - Calling fetch_indicators
    Then:
        - The stored last_successful_run is the original cycle start time, not the current fetch time
        - This guarantees the next full cycle re-queries the window covered by the resumed runs,
          so indicators that arrived while the cycle was in progress are not missed
    """
    from Unit42Feed import fetch_indicators

    mock_demisto_params(mocker)

    mock_response = {
        "data": [{"indicator_value": "1.2.3.4", "indicator_type": "ip", "verdict": "malicious"}],
        "metadata": {"next_page_token": None},
    }
    mocker.patch.object(client, "get_indicators", return_value=mock_response)
    mocker.patch("Unit42Feed.demisto.createIndicators")
    mocker.patch(
        "Unit42Feed.demisto.getLastRun",
        return_value={
            "start_time": "2023-06-01T12:00:00Z",
            "cycle_start_time": "2023-06-02T12:00:00Z",
            "page_tokens": {"indicators": "page2"},
        },
    )

    params = {"limit": "50", "feed_types": ["Indicators"], "indicator_types": ["IP"], "feedTags": [], "tlp_color": None}

    # Deliberately distinct from the cycle start time, so the two cannot be confused
    current_time = datetime(2023, 6, 3, 18, 0, 0)
    _, next_run = fetch_indicators(client, params, current_time)

    assert next_run == {"last_successful_run": "2023-06-02T12:00:00Z"}
    assert next_run["last_successful_run"] != current_time.strftime(DATE_FORMAT)


def test_fetch_indicators_upgrade_path_last_run_without_cycle_start_time(client, mocker):
    """
    Given:
        - A last run written before the cycle start time was introduced (holds only last_successful_run)
        - An API with more indicators available than the configured maximum per fetch
    When:
        - Calling fetch_indicators
    Then:
        - The stored start time is preserved, so no time window is skipped
        - A fresh cycle start time is created from the current fetch time, without raising a KeyError
    """
    from Unit42Feed import fetch_indicators

    mock_demisto_params(mocker)

    mock_response = {
        "data": [{"indicator_value": f"1.2.3.{i}", "indicator_type": "ip", "verdict": "malicious"} for i in range(100)],
        "metadata": {"next_page_token": "page2"},
    }
    mock_get_indicators = mocker.patch.object(client, "get_indicators", return_value=mock_response)
    mocker.patch("Unit42Feed.demisto.createIndicators")
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={"last_successful_run": "2023-06-01T12:00:00Z"})

    params = {"limit": "50", "feed_types": ["Indicators"], "indicator_types": ["IP"], "feedTags": [], "tlp_color": None}

    current_time = datetime(2023, 6, 2, 12, 0, 0)
    _, next_run = fetch_indicators(client, params, current_time)

    assert mock_get_indicators.call_args[1]["start_time"] == "2023-06-01T12:00:00Z"
    assert next_run["start_time"] == "2023-06-01T12:00:00Z"
    assert next_run["cycle_start_time"] == current_time.strftime(DATE_FORMAT)
    assert next_run["page_tokens"] == {"indicators": "page2"}


def test_fetch_indicators_upgrade_path_no_pending_units(client, mocker):
    """
    Given:
        - A last run written before the cycle start time was introduced (holds only last_successful_run)
        - An API that returns everything within the configured limit
    When:
        - Calling fetch_indicators
    Then:
        - The query uses the stored last successful run as the start time
        - The next run advances to the current fetch time, so the feed does not stall on the old window
    """
    from Unit42Feed import fetch_indicators

    mock_demisto_params(mocker)

    mock_response = {
        "data": [{"indicator_value": "1.2.3.4", "indicator_type": "ip", "verdict": "malicious"}],
        "metadata": {"next_page_token": None},
    }
    mock_get_indicators = mocker.patch.object(client, "get_indicators", return_value=mock_response)
    mocker.patch("Unit42Feed.demisto.createIndicators")
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={"last_successful_run": "2023-06-01T12:00:00Z"})

    params = {"limit": "50", "feed_types": ["Indicators"], "indicator_types": ["IP"], "feedTags": [], "tlp_color": None}

    current_time = datetime(2023, 6, 2, 12, 0, 0)
    _, next_run = fetch_indicators(client, params, current_time)

    assert mock_get_indicators.call_args[1]["start_time"] == "2023-06-01T12:00:00Z"
    assert next_run == {"last_successful_run": current_time.strftime(DATE_FORMAT)}


def test_fetch_indicators_normal_run_stores_current_time_as_last_successful_run(client, mocker):
    """
    Given:
        - An empty last run (a first fetch, with no pending cycle)
        - An API that returns everything within the configured limit for every type
    When:
        - Calling fetch_indicators
    Then:
        - The next run holds only the current fetch time as the last successful run
        - Neither pending nor cycle_start_time leak into the next run
    """
    from Unit42Feed import fetch_indicators

    mock_demisto_params(mocker)

    mock_response = {
        "data": [{"indicator_value": "1.2.3.4", "indicator_type": "ip", "verdict": "malicious"}],
        "metadata": {"next_page_token": None},
    }
    mocker.patch.object(client, "get_indicators", return_value=mock_response)
    mocker.patch("Unit42Feed.demisto.createIndicators")
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={})

    params = {
        "limit": "50",
        "feed_types": ["Indicators"],
        "indicator_types": ["IP", "Domain"],
        "feedTags": [],
        "tlp_color": None,
    }

    current_time = datetime(2023, 6, 2, 12, 0, 0)
    _, next_run = fetch_indicators(client, params, current_time)

    assert next_run == {"last_successful_run": current_time.strftime(DATE_FORMAT)}
    assert "page_tokens" not in next_run
    assert "cycle_start_time" not in next_run


def test_fetch_indicators_resume_across_runs_skips_no_indicators(client, mocker):
    """
    Given:
        - A single indicator type (IP) with limit=50 and a feed of three pages, each larger
          than the limit: page A (100 items, next_page_token="tokenB"),
          page B (100 items, next_page_token="tokenC"), page C (40 items, next_page_token=None).
        - Every indicator across all three pages has a unique value (240 unique values total).
    When:
        - Running fetch_indicators three times, feeding each run's next_run back in as the
          getLastRun of the following run (simulating the real resume-across-runs behavior).
    Then:
        - Run 1 pushes the FULL overshooting page A (not a truncated 50 items) and stores a
          pending unit resuming from "tokenB".
        - Run 2 resumes from "tokenB", pushes the full page B, and resumes from "tokenC".
        - Run 3 resumes from "tokenC", pushes page C, sees a null token, and completes the
          cycle (next_run holds last_successful_run, no pending).
        - The UNION of every indicator value pushed across runs 1+2+3 equals the full set of
          240 unique values, with NO value missing and NO value duplicated.
    """
    from Unit42Feed import fetch_indicators

    mock_demisto_params(mocker)

    # Build three pages of IP indicators with globally unique values.
    def make_page(start: int, count: int, next_token: str | None) -> dict:
        return {
            "data": [
                {"indicator_value": f"1.2.3.{i}", "indicator_type": "ip", "verdict": "malicious"}
                for i in range(start, start + count)
            ],
            "metadata": {"next_page_token": next_token},
        }

    page_a = make_page(0, 100, "tokenB")
    page_b = make_page(100, 100, "tokenC")
    page_c = make_page(200, 40, None)
    all_expected_values = {f"1.2.3.{i}" for i in range(240)}

    # get_indicators returns page A, then page B, then page C on successive calls.
    mock_get_indicators = mocker.patch.object(client, "get_indicators", side_effect=[page_a, page_b, page_c])

    # Capture every indicator value handed to createIndicators across all runs, tracking
    # duplicates explicitly so the assertion can distinguish "missing" from "duplicated".
    pushed_values: list[str] = []

    def capture_created(indicators_batch):
        pushed_values.extend(indicator["value"] for indicator in indicators_batch)

    mocker.patch("Unit42Feed.demisto.createIndicators", side_effect=capture_created)

    params = {"limit": "50", "feed_types": ["Indicators"], "indicator_types": ["IP"], "feedTags": [], "tlp_color": None}
    current_time = datetime(2023, 6, 2, 12, 0, 0)

    # --- Run 1: fresh cycle, page A overshoots limit -> resume from "tokenB" ---
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={"last_successful_run": "2023-06-01T12:00:00Z"})
    values_before_run1 = len(pushed_values)
    total_run1, next_run_1 = fetch_indicators(client, params, current_time)
    run1_values = pushed_values[values_before_run1:]

    # The full 100-item page A was pushed (overshoot), not truncated to 50.
    assert total_run1 == 100
    assert len(run1_values) == 100
    assert next_run_1.get("page_tokens") == {"indicators": "tokenB"}
    # Run 1 started the cycle: it queried with no resume token.
    assert mock_get_indicators.call_args_list[0][1]["next_page_token"] is None

    # --- Run 2: resume from "tokenB", page B overshoots -> resume from "tokenC" ---
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value=next_run_1)
    values_before_run2 = len(pushed_values)
    total_run2, next_run_2 = fetch_indicators(client, params, current_time)
    run2_values = pushed_values[values_before_run2:]

    assert total_run2 == 100
    assert len(run2_values) == 100
    # Run 2 resumed from the token page A returned, and produced the next token.
    assert mock_get_indicators.call_args_list[1][1]["next_page_token"] == "tokenB"
    assert next_run_2.get("page_tokens") == {"indicators": "tokenC"}

    # --- Run 3: resume from "tokenC", page C ends the cycle (null token) ---
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value=next_run_2)
    values_before_run3 = len(pushed_values)
    total_run3, next_run_3 = fetch_indicators(client, params, current_time)
    run3_values = pushed_values[values_before_run3:]

    assert total_run3 == 40
    assert len(run3_values) == 40
    # Run 3 resumed from the token page B returned.
    assert mock_get_indicators.call_args_list[2][1]["next_page_token"] == "tokenC"
    # Cycle completed: next run is a last_successful_run shape with nothing left pending.
    assert "page_tokens" not in next_run_3
    assert next_run_3 == {"last_successful_run": current_time.strftime(DATE_FORMAT)}

    # --- The crucial anti-regression property: exact coverage, no gap, no duplicate ---
    union_of_pushed = set(pushed_values)
    # Nothing was skipped across the run boundary (would fail if truncation returns).
    assert union_of_pushed == all_expected_values
    assert all_expected_values - union_of_pushed == set(), "indicator values were skipped across the resume boundary"
    # And nothing was pushed twice: 240 unique values from exactly 240 pushes.
    assert len(pushed_values) == 240
    assert len(union_of_pushed) == 240


def test_fetch_indicators_threat_objects_skipped_within_24h(client, mocker):
    """
    Given:
        - A fresh run (no pending cycle in progress) with both Threat Objects and Indicators enabled.
        - getLastRun stores last_threat_objects_fetch = 1 hour before the current fetch time,
          well within the THREAT_OBJECTS_FETCH_INTERVAL_HOURS (24h) window.
    When:
        - Calling fetch_indicators.
    Then:
        - Threat objects are NOT fetched (the 24h gate blocks them).
        - Indicators ARE fetched.
        - The next run carries the SAME last_threat_objects_fetch value forward unchanged.
    """
    from Unit42Feed import fetch_indicators

    mock_demisto_params(mocker)

    mock_indicators_response = {
        "data": [{"indicator_value": "1.2.3.4", "indicator_type": "ip", "verdict": "malicious"}],
        "metadata": {"next_page_token": None},
    }
    mock_get_indicators = mocker.patch.object(client, "get_indicators", return_value=mock_indicators_response)
    mock_get_threat_objects = mocker.patch.object(client, "get_threat_objects")
    mocker.patch("Unit42Feed.demisto.createIndicators")

    current_time = datetime(2023, 6, 2, 12, 0, 0)
    last_to_fetch = (current_time - timedelta(hours=1)).strftime(DATE_FORMAT)
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={"last_threat_objects_fetch": last_to_fetch})

    params = {
        "feed_types": [THREAT_OBJECTS_TYPE, "Indicators"],
        "indicator_types": ["IP"],
        "feedTags": [],
        "tlp_color": None,
    }

    _, next_run = fetch_indicators(client, params, current_time)

    # Threat objects are within the 24h window, so they are skipped entirely.
    mock_get_threat_objects.assert_not_called()
    # Indicators are still fetched normally.
    mock_get_indicators.assert_called_once()
    # The stored window is carried forward unchanged (not reset to the current time).
    assert next_run["last_threat_objects_fetch"] == last_to_fetch
    assert next_run == {
        "last_successful_run": current_time.strftime(DATE_FORMAT),
        "last_threat_objects_fetch": last_to_fetch,
    }


def test_fetch_indicators_threat_objects_fetched_after_24h(client, mocker):
    """
    Given:
        - A fresh run with both Threat Objects and Indicators enabled.
        - getLastRun stores last_threat_objects_fetch = 25 hours before the current fetch time,
          past the THREAT_OBJECTS_FETCH_INTERVAL_HOURS (24h) window.
        - The threat objects mock returns a completing page (no next page token).
    When:
        - Calling fetch_indicators.
    Then:
        - Threat objects ARE fetched (the 24h window has elapsed).
        - The next run resets last_threat_objects_fetch to the current fetch time.
    """
    from Unit42Feed import fetch_indicators

    mock_demisto_params(mocker)

    mock_indicators_response = {
        "data": [{"indicator_value": "1.2.3.4", "indicator_type": "ip", "verdict": "malicious"}],
        "metadata": {"next_page_token": None},
    }
    mock_threat_objects_response = {
        "data": [{"name": "APT29", "threat_object_class": "actor", "publications": []}],
        "metadata": {"next_page_token": None},
    }
    mocker.patch.object(client, "get_indicators", return_value=mock_indicators_response)
    mock_get_threat_objects = mocker.patch.object(client, "get_threat_objects", return_value=mock_threat_objects_response)
    mocker.patch("Unit42Feed.demisto.createIndicators")

    current_time = datetime(2023, 6, 2, 12, 0, 0)
    last_to_fetch = (current_time - timedelta(hours=25)).strftime(DATE_FORMAT)
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={"last_threat_objects_fetch": last_to_fetch})

    params = {
        "feed_types": [THREAT_OBJECTS_TYPE, "Indicators"],
        "indicator_types": ["IP"],
        "feedTags": [],
        "tlp_color": None,
    }

    _, next_run = fetch_indicators(client, params, current_time)

    # The 24h window has elapsed, so threat objects are fetched.
    mock_get_threat_objects.assert_called_once()
    # Threat objects completed this run, so the window resets to the current fetch time.
    assert next_run["last_threat_objects_fetch"] == current_time.strftime(DATE_FORMAT)


def test_fetch_indicators_threat_objects_first_fetch_when_never_fetched(client, mocker):
    """
    Given:
        - A fresh run with both Threat Objects and Indicators enabled.
        - getLastRun has NO last_threat_objects_fetch (only a last_successful_run is stored).
        - The threat objects mock returns a completing page (no next page token).
    When:
        - Calling fetch_indicators.
    Then:
        - Threat objects ARE fetched (they are due when they have never been fetched before).
        - The next run records last_threat_objects_fetch as the current fetch time.
    """
    from Unit42Feed import fetch_indicators

    mock_demisto_params(mocker)

    mock_indicators_response = {
        "data": [{"indicator_value": "1.2.3.4", "indicator_type": "ip", "verdict": "malicious"}],
        "metadata": {"next_page_token": None},
    }
    mock_threat_objects_response = {
        "data": [{"name": "APT29", "threat_object_class": "actor", "publications": []}],
        "metadata": {"next_page_token": None},
    }
    mocker.patch.object(client, "get_indicators", return_value=mock_indicators_response)
    mock_get_threat_objects = mocker.patch.object(client, "get_threat_objects", return_value=mock_threat_objects_response)
    mocker.patch("Unit42Feed.demisto.createIndicators")

    current_time = datetime(2023, 6, 2, 12, 0, 0)
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={"last_successful_run": "2023-06-01T12:00:00Z"})

    params = {
        "feed_types": [THREAT_OBJECTS_TYPE, "Indicators"],
        "indicator_types": ["IP"],
        "feedTags": [],
        "tlp_color": None,
    }

    _, next_run = fetch_indicators(client, params, current_time)

    # Never fetched before -> due now, so threat objects are fetched.
    mock_get_threat_objects.assert_called_once()
    # First completion records the window as the current fetch time.
    assert next_run["last_threat_objects_fetch"] == current_time.strftime(DATE_FORMAT)


def test_fetch_indicators_threat_objects_pending_resumes_ignoring_24h_gate(client, mocker):
    """
    Given:
        - A resumed cycle (cycle in progress) whose getLastRun holds a pending threat_objects
          token ("to2"), plus start_time and cycle_start_time.
        - last_threat_objects_fetch is RECENT (1 hour before the current fetch time, well within
          the 24h window that would normally block a fresh threat-objects fetch).
        - The threat objects mock returns a completing page (no next page token) this run.
    When:
        - Calling fetch_indicators.
    Then:
        - Threat objects ARE fetched despite being within the 24h window, because an interrupted
          fetch always resumes immediately - resumed from the pending token "to2".
        - The cycle completes and next_run records last_threat_objects_fetch as the current time,
          since the threat objects finished this run.
    """
    from Unit42Feed import fetch_indicators

    mock_demisto_params(mocker)

    mock_threat_objects_response = {
        "data": [{"name": "APT29", "threat_object_class": "actor", "publications": []}],
        "metadata": {"next_page_token": None},
    }
    mock_get_threat_objects = mocker.patch.object(client, "get_threat_objects", return_value=mock_threat_objects_response)
    mock_get_indicators = mocker.patch.object(client, "get_indicators")
    mocker.patch("Unit42Feed.demisto.createIndicators")

    current_time = datetime(2023, 6, 2, 12, 0, 0)
    recent_to_fetch = (current_time - timedelta(hours=1)).strftime(DATE_FORMAT)
    mocker.patch(
        "Unit42Feed.demisto.getLastRun",
        return_value={
            "start_time": "2023-06-01T12:00:00Z",
            "cycle_start_time": "2023-06-02T12:00:00Z",
            "page_tokens": {"threat_objects": "to2"},
            "last_threat_objects_fetch": recent_to_fetch,
        },
    )

    params = {
        "feed_types": [THREAT_OBJECTS_TYPE, "Indicators"],
        "indicator_types": ["IP"],
        "feedTags": [],
        "tlp_color": None,
    }

    _, next_run = fetch_indicators(client, params, current_time)

    # The mid-cycle resume ignores the 24h gate: threat objects are fetched from the pending token.
    mock_get_threat_objects.assert_called_once()
    assert mock_get_threat_objects.call_args[1]["next_page_token"] == "to2"
    # Indicators never had a pending token, so with a cycle in progress they stay skipped.
    mock_get_indicators.assert_not_called()
    # Threat objects completed this run, so the window resets to the current time and the
    # cycle completes (no pending left).
    assert "page_tokens" not in next_run
    assert next_run["last_threat_objects_fetch"] == current_time.strftime(DATE_FORMAT)


def test_fetch_indicators_threat_objects_incomplete_does_not_reset_window(client, mocker):
    """
    Given:
        - A fresh run with Threat Objects due (getLastRun has NO last_threat_objects_fetch).
        - The threat objects mock returns a page WITH a next page token (an incomplete fetch).
    When:
        - Calling fetch_indicators.
    Then:
        - The next run stores the threat objects page token under pending.
        - last_threat_objects_fetch is NOT updated to the current time and is absent entirely,
          because the window only resets when a threat-objects fetch COMPLETES.
    """
    from Unit42Feed import fetch_indicators

    mock_demisto_params(mocker)

    mock_threat_objects_response = {
        "data": [{"name": f"APT{i}", "threat_object_class": "actor", "publications": []} for i in range(100)],
        "metadata": {"next_page_token": "to_page2"},
    }
    mocker.patch.object(client, "get_threat_objects", return_value=mock_threat_objects_response)
    mocker.patch("Unit42Feed.demisto.createIndicators")
    mocker.patch("Unit42Feed.demisto.getLastRun", return_value={})

    params = {
        "limit": "50",
        "feed_types": [THREAT_OBJECTS_TYPE],
        "indicator_types": [],
        "feedTags": [],
        "tlp_color": None,
    }

    current_time = datetime(2023, 6, 2, 12, 0, 0)
    _, next_run = fetch_indicators(client, params, current_time)

    # The interrupted fetch stores its resume token.
    assert next_run["page_tokens"] == {"threat_objects": "to_page2"}
    # The window does NOT reset on an incomplete fetch, and it was never previously set,
    # so the key is absent from the next run.
    assert "last_threat_objects_fetch" not in next_run


def test_fetch_threat_objects_counts_api_objects_not_expanded_indicators(client, mocker):
    """
    Given:
        - A single page of 3 actor threat objects that is under the limit (limit=10) in
          API-object count, but where each object carries 2 valid affected_regions, so
          each expands into 1 threat object + 2 location indicators = 3 indicators
          (9 pushed indicators total for 3 API objects), with no next page token.
    When:
        - Calling fetch_threat_objects_with_limit.
    Then:
        - The full page is pushed without truncation (9 indicators reach createIndicators),
          confirming expansion actually occurred.
        - The returned total_fetched equals the API object count, NOT the expanded indicator count.
        - next_page_token is None (the fetch cycle completed).
    """
    mock_demisto_params(mocker)

    # Each actor has 2 valid regions -> map_threat_object returns 3 indicators per object
    # (1 threat object + 2 location indicators) when relationships are enabled.
    single_page = {
        "data": [
            {
                "name": f"APT{i}",
                "threat_object_class": "actor",
                "publications": [],
                "battlecard_details": {
                    "threat_actor_details": {
                        "affected_regions": ["North America", "Europe"],
                    }
                },
            }
            for i in range(3)
        ],
        "metadata": {"next_page_token": None},
    }

    mock_get_threat_objects = mocker.patch.object(client, "get_threat_objects", return_value=single_page)
    mock_create_indicators = mocker.patch("Unit42Feed.demisto.createIndicators")

    result, next_page_token = fetch_threat_objects_with_limit(client=client, limit=10, feed_tags=[], tlp_color=None)

    # Verify expansion actually happened: 3 API objects x 3 indicators each = 9 pushed.
    # Without this, the counter assertion below would prove nothing.
    pushed_items = [item for call in mock_create_indicators.call_args_list for item in call[0][0]]
    assert len(pushed_items) == 9

    # total_fetched counts consumed API objects (len(data) == 3), not the 9 derived indicators that were pushed.
    assert result == 3
    assert next_page_token is None
    assert mock_get_threat_objects.call_count == 1
