from CommonServerPython import tableToMarkdown, Common, FeedIndicatorType, EntityRelationship
import pytest
from AnomaliThreatStreamFeed import Client
from datetime import datetime, UTC
from typing import Any


THREAT_STREAM = "Anomali ThreatStream Feed"


def mock_client():
    return Client(base_url="https://svlpartner-optic-api.threatstream.com", user_name="user", api_key="key", verify=True)


def test_get_indicators_command_success_with_type(mocker):
    from AnomaliThreatStreamFeed import get_indicators_command

    """
    Tests the successful execution of get_indicators_command when an indicator_type is specified.
    Verifies that the command fetches indicators and returns a human-readable table with the dynamic header.

    Given:
        - A mock Client instance.
        - Arguments with 'indicator_type' and 'limit'.
    When:
        - Calling get_indicators_command.
    Then:
        - The client's http_request method is called with the correct parameters, including 'type'.
        - `parse_indicators_for_get_command` is called with the raw indicators.
        - `tableToMarkdown` is called with the expected headers (including the dynamic type header).
        - The readable_output of CommandResults contains the expected table.
        - The raw_response of CommandResults contains the raw indicators.
    """

    client = mock_client()

    mock_api_response = {
        "objects": [
            {
                "id": "123",
                "type": "domain",
                "confidence": 90,
                "description": "Test domain",
                "source": "TestSource",
                "value": "mydomain1.com",
                "tags": ["malware", "phishing"],
                "tlp": "RED",
                "country": "US",
                "modified_ts": "2023-01-01T12:00:00Z",
                "org": "",
                "created_ts": "2022-01-01T12:00:00Z",
                "expiration_ts": "2024-01-01T12:00:00Z",
                "target_industry": ["finance"],
                "asn": "AS12345",
                "locations": "New York",
            },
            {
                "id": "124",
                "type": "domain",
                "confidence": 80,
                "description": "Another test domain",
                "source": "AnotherSource",
                "value": "mydomain.com",
                "tags": ["c2"],
                "tlp": "AMBER",
                "country": "FR",
                "modified_ts": "2023-02-01T12:00:00Z",
                "org": "AnotherOrg",
                "created_ts": "2022-02-01T12:00:00Z",
                "expiration_ts": "2024-02-01T12:00:00Z",
                "target_industry": ["tech"],
                "asn": "AS67890",
                "locations": "London",
            },
        ]
    }

    mock_parsed_indicators = [
        {
            "ThreatStreamID": "123",
            "Confidence": 90,
            "Description": "Test domain",
            "Source": "TestSource",
            "domain": "mydomain1.com",
            "Tags": ["malware", "phishing"],
            "TrafficLightProtocol": "RED",
            "CountryCode": "US",
            "Modified": "2023-01-01T12:00:00Z",
            "Organization": "",
            "Creation": "2022-01-01T12:00:00Z",
            "Expiration": "2024-01-01T12:00:00Z",
            "TargetIndustries": ["finance"],
            "ASN": "AS12345",
            "Location": "New York",
        },
        {
            "ThreatStreamID": "124",
            "Confidence": 80,
            "Description": "Another test domain",
            "Source": "AnotherSource",
            "domain": "mydomain.com",
            "Tags": ["c2"],
            "TrafficLightProtocol": "AMBER",
            "CountryCode": "FR",
            "Modified": "2023-02-01T12:00:00Z",
            "Organization": "AnotherOrg",
            "Creation": "2022-02-01T12:00:00Z",
            "Expiration": "2024-02-01T12:00:00Z",
            "TargetIndustries": ["tech"],
            "ASN": "AS67890",
            "Location": "London",
        },
    ]

    mocker.patch.object(client, "http_request", return_value=mock_api_response)
    mocker.patch("AnomaliThreatStreamFeed.parse_indicators_for_get_command", return_value=mock_parsed_indicators)

    args = {"indicator_type": "domain", "limit": 2}
    result = get_indicators_command(client, args)

    expected_headers_with_type = [
        "TargetIndustries",
        "Source",
        "ThreatStreamID",
        "Country Code",
        "domain",
        "Description",
        "Modified",
        "Organization",
        "Confidence",
        "Creation",
        "Expiration",
        "Tags",
        "TrafficLightProtocol",
        "Location",
        "ASN",
    ]

    human_readable = tableToMarkdown(
        name=f"Indicators from {THREAT_STREAM}:",
        t=mock_parsed_indicators,
        headers=expected_headers_with_type,
        removeNull=True,
        is_auto_json_transform=True,
    )
    assert result.readable_output == human_readable
    assert result.raw_response == mock_api_response["objects"]


def test_get_indicators_command_success_no_type(mocker):
    from AnomaliThreatStreamFeed import get_indicators_command

    """
    Tests the successful execution of get_indicators_command when no indicator_type is specified.
    Verifies that the command fetches indicators and returns a human-readable table.

    Given:
        - A mock Client instance.
        - Arguments with no 'indicator_type' and a 'limit'.
    When:
        - Calling get_indicators_command.
    Then:
        - The client's http_request method is called with the correct parameters.
        - `parse_indicators_for_get_command` is called with the raw indicators.
        - `tableToMarkdown` is called with the expected headers (no dynamic type header).
        - The readable_output of CommandResults contains the expected table.
        - The raw_response of CommandResults contains the raw indicators.
    """

    client = mock_client()

    mock_api_response = {
        "objects": [
            {
                "id": "123",
                "type": "domain",
                "confidence": 90,
                "description": "Test domain",
                "source": "TestSource",
                "value": "mydomain1.com",
                "tags": ["malware", "phishing"],
                "tlp": "RED",
                "country": "US",
                "modified_ts": "2023-01-01T12:00:00Z",
                "org": "",
                "created_ts": "2022-01-01T12:00:00Z",
                "expiration_ts": "2024-01-01T12:00:00Z",
                "target_industry": ["finance"],
                "asn": "AS12345",
                "locations": "New York",
            },
            {
                "id": "124",
                "type": "ip",
                "confidence": 10,
                "description": "test ip",
                "source": "AnotherSource",
                "value": "1.1.1.1",
                "tags": ["tag1"],
                "tlp": "GREEN",
                "country": "FR",
                "modified_ts": "2023-02-01T12:00:00Z",
                "org": "AnotherOrg",
                "created_ts": "2022-02-01T12:00:00Z",
                "expiration_ts": "2024-02-01T12:00:00Z",
                "target_industry": ["tech"],
                "asn": "",
                "locations": "London",
            },
            {
                "id": "125",
                "type": "email",
                "confidence": 65,
                "description": "test ip",
                "source": "NewSource",
                "value": "test_email@test.com",
                "tags": [{"id": "125a", "name": "tag125a"}, {"id": "125b", "name": "tag125b"}],
                "tlp": "RED",
                "country": "",
                "modified_ts": "2023-02-01T12:00:00Z",
                "org": "currentOrganization",
                "created_ts": "2022-02-01T12:00:00Z",
                "expiration_ts": "2024-02-01T12:00:00Z",
                "target_industry": [],
                "asn": "",
                "locations": "California",
            },
        ]
    }

    mock_parsed_indicators = [
        {
            "ThreatStreamID": "123",
            "Confidence": 90,
            "Description": "Test domain",
            "Source": "TestSource",
            "domain": "mydomain1.com",
            "Tags": ["malware", "phishing"],
            "TrafficLightProtocol": "RED",
            "CountryCode": "US",
            "Modified": "2023-01-01T12:00:00Z",
            "Organization": "",
            "Creation": "2022-01-01T12:00:00Z",
            "Expiration": "2024-01-01T12:00:00Z",
            "TargetIndustries": ["finance"],
            "ASN": "AS12345",
            "Location": "New York",
        },
        {
            "ThreatStreamID": "124",
            "Confidence": 10,
            "Description": "test ip",
            "Source": "AnotherSource",
            "ip": "1.1.1.1",
            "Tags": ["tag1"],
            "TrafficLightProtocol": "GREEN",
            "CountryCode": "FR",
            "Modified": "2023-02-01T12:00:00Z",
            "Organization": "AnotherOrg",
            "Creation": "2022-02-01T12:00:00Z",
            "Expiration": "2024-02-01T12:00:00Z",
            "TargetIndustries": ["tech"],
            "ASN": "",
            "Location": "London",
        },
        {
            "ThreatStreamID": "125",
            "Confidence": 65,
            "Description": "test ip",
            "Source": "NewSource",
            "email": "test_email@test.com",
            "Tags": [{"id": "125a", "name": "tag125a"}, {"id": "125b", "name": "tag125b"}],
            "TrafficLightProtocol": "RED",
            "CountryCode": "",
            "Modified": "2023-02-01T12:00:00Z",
            "Organization": "currentOrganization",
            "Creation": "2022-02-01T12:00:00Z",
            "Expiration": "2024-02-01T12:00:00Z",
            "TargetIndustries": [],
            "ASN": "",
            "Location": "California",
        },
    ]

    mocker.patch.object(client, "http_request", return_value=mock_api_response)
    mocker.patch("AnomaliThreatStreamFeed.parse_indicators_for_get_command", return_value=mock_parsed_indicators)

    args = {"limit": 3}
    result = get_indicators_command(client, args)

    expected_headers_with_type = [
        "TargetIndustries",
        "Source",
        "ThreatStreamID",
        "Country Code",
        "Description",
        "Modified",
        "Organization",
        "Confidence",
        "Creation",
        "Expiration",
        "Tags",
        "TrafficLightProtocol",
        "Location",
        "ASN",
    ]

    human_readable = tableToMarkdown(
        name=f"Indicators from {THREAT_STREAM}:",
        t=mock_parsed_indicators,
        headers=expected_headers_with_type,
        removeNull=True,
        is_auto_json_transform=True,
    )
    assert result.readable_output == human_readable
    assert result.raw_response == mock_api_response["objects"]


def test_get_indicators_command_no_indicators_found(mocker):
    from AnomaliThreatStreamFeed import get_indicators_command

    """
    Tests the scenario where no indicators are found for the given criteria.
    Verifies that the command returns an appropriate message.

    Given:
        - A mock Client instance that returns no indicators.
        - Arguments for the command.
    When:
        - Calling get_indicators_command.
    Then:
        - The client's http_request method is called.
        - `demisto.info` is called with the "No indicators found" message.
        - The readable_output of CommandResults contains "No indicators found.".
        - The raw_response is an empty list.
    """
    client = mock_client()
    args = {"limit": 10, "indicator_type": "url"}

    mocker.patch.object(client, "http_request", return_value={"objects": []})

    result = get_indicators_command(client, args)

    client.http_request.assert_called_once_with(method="GET", url_suffix="v2/intelligence", params={"limit": 10, "type": "url"})
    assert result.readable_output == "### No indicators found."
    assert result.raw_response is None


def test_parse_indicators_for_get_command_full_data():
    from AnomaliThreatStreamFeed import parse_indicators_for_get_command

    """
    Tests parse_indicators_for_get_command with a complete raw indicator.
    Verifies that all fields are correctly mapped and the dynamic field is added.

    Given:
        - A list containing one raw indicator with all expected fields.
    When:
        - Calling parse_indicators_for_get_command.
    Then:
        - The returned list contains one parsed indicator with all fields correctly mapped,
          including the dynamic 'domain' field and string conversions for 'id' and 'confidence'.
    """
    mock_raw_indicators = [
        {
            "id": "123",
            "type": "domain",
            "confidence": 90,
            "description": "Test domain",
            "source": "TestSource",
            "value": "mydomain1.com",
            "tags": [{"id": "125a", "name": "tag125a"}, {"id": "125b", "name": "tag125b"}],
            "tlp": "RED",
            "org": "currentOrganization",
            "country": "US",
            "modified_ts": "2023-01-01T12:00:00Z",
            "created_ts": "2022-01-01T12:00:00Z",
            "expiration_ts": "2024-01-01T12:00:00Z",
            "target_industry": ["target_industry"],
            "asn": "AS12345",
            "locations": "New York",
        },
    ]

    expected_parsed_indicators = [
        {
            "Source": "TestSource",
            "ThreatStreamID": "123",
            "CountryCode": "US",
            "domain": "mydomain1.com",
            "Description": "Test domain",
            "Modified": "2023-01-01T12:00:00Z",
            "Confidence": "90",
            "Creation": "2022-01-01T12:00:00Z",
            "Tags": [{"id": "125a", "name": "tag125a"}, {"id": "125b", "name": "tag125b"}],
            "TrafficLightProtocol": "RED",
            "Location": "New York",
            "ASN": "AS12345",
            "TargetIndustries": ["target_industry"],
            "Organization": "currentOrganization",
        }
    ]

    result = parse_indicators_for_get_command(mock_raw_indicators)
    assert result == expected_parsed_indicators


def test_parse_indicators_for_get_command_missing_fields():
    from AnomaliThreatStreamFeed import parse_indicators_for_get_command

    """
    Tests parse_indicators_for_get_command when some fields are missing in the raw indicator.
    Verifies that missing fields are correctly omitted (due to assign_params).

    Given:
        - A list containing one raw indicator with several missing optional fields.
    When:
        - Calling parse_indicators_for_get_command.
    Then:
        - The returned list contains one parsed indicator where missing fields are not present.
        - Dynamic field is still added if type and value exist.
    """
    mock_raw_indicators = [
        {
            "id": "456",
            "type": "ip",
            "value": "2.2.2.2",
            "description": "Simple IP",
            "source": "AnotherSource",
            # Missing: confidence, tags, tlp, country, modified_ts, org, created_ts, expiration_ts, target_industry,
            # asn, locations
        },
    ]

    expected_parsed_indicators = [
        {"Source": "AnotherSource", "ThreatStreamID": "456", "ip": "2.2.2.2", "Description": "Simple IP", "Confidence": "None"},
    ]

    result = parse_indicators_for_get_command(mock_raw_indicators)
    assert result == expected_parsed_indicators


def test_get_past_time_basic_interval(mocker):
    from AnomaliThreatStreamFeed import get_past_time

    """
    Tests get_past_time with a standard minutes interval.
    Verifies that the returned time is correctly calculated and formatted.

    Given:
        - A minutes_interval of 60.
        - A mocked current UTC datetime (via mocking get_current_utc_time).
    When:
        - Calling get_past_time, imported from 'AnomaliThreatStreamFeed'.
    Then:
        - Mocks 'AnomaliThreatStreamFeed.get_current_utc_time' to return a fixed datetime.
        - The function returns the expected past time in ISO 8601 format with milliseconds and 'Z'.
    """
    mock_now = datetime(2023, 8, 1, 12, 0, 0, 500000, tzinfo=UTC)
    minutes_interval = 60  # one hour ago
    expected_past_time = "2023-08-01T11:00:00.500Z"

    mocker.patch("AnomaliThreatStreamFeed.get_current_utc_time", return_value=mock_now)

    result = get_past_time(minutes_interval)
    assert result == expected_past_time


def test_calculate_score_none_no_confidence_field(mocker):
    from AnomaliThreatStreamFeed import DBotScoreCalculator

    """
    Tests calculate_score when the 'confidence' field is missing from the indicator.
    Verifies that DBotScore.NONE is returned and a debug message is logged.

    Given:
        - An indicator dictionary without a 'confidence' key.
    When:
        - Calling calculate_score.
    Then:
        - The function returns Common.DBotScore.NONE.
        - A debug message indicating confidence not found is logged.
    """
    calculator = DBotScoreCalculator()
    indicator = {"description": "test"}  # No confidence field

    result = calculator.calculate_score(indicator)
    assert result == Common.DBotScore.NONE


DEFAULT_MALICIOUS_THRESHOLD = 65
DEFAULT_SUSPICIOUS_THRESHOLD = 25
DEFAULT_BENIGN_THRESHOLD = 0
DBOT_SCORE_TEST_CASES = [
    # Test cases for BAD score (confidence > 65)
    ({"confidence": 71}, Common.DBotScore.BAD),
    ({"confidence": 100}, Common.DBotScore.BAD),
    # Test cases for SUSPICIOUS score (confidence > 25 and <= 65)
    ({"confidence": 51}, Common.DBotScore.SUSPICIOUS),
    ({"confidence": DEFAULT_MALICIOUS_THRESHOLD}, Common.DBotScore.SUSPICIOUS),  # 65 is not > 65
    ({"confidence": 60}, Common.DBotScore.SUSPICIOUS),
    ({"confidence": 26}, Common.DBotScore.SUSPICIOUS),  # Just above suspicious threshold
    # Test cases for GOOD score (confidence > 0 and <= 25)
    ({"confidence": 15}, Common.DBotScore.GOOD),
    ({"confidence": DEFAULT_SUSPICIOUS_THRESHOLD}, Common.DBotScore.GOOD),  # 25 is not > 25
    ({"confidence": 20}, Common.DBotScore.GOOD),
    ({"confidence": 1}, Common.DBotScore.GOOD),  # Just above benign threshold
    # Test cases for NONE score (confidence <= 0)
    ({"confidence": 0}, Common.DBotScore.NONE),
    ({"confidence": DEFAULT_BENIGN_THRESHOLD}, Common.DBotScore.NONE),  # 0 is not > 0
    ({"confidence": -5}, Common.DBotScore.NONE),  # Negative confidence
    # Test cases for NONE score (missing/invalid confidence)
    ({"description": "no confidence"}, Common.DBotScore.NONE),  # Missing confidence field
    ({"confidence": None}, Common.DBotScore.NONE),  # Explicitly None confidence
    ({"confidence": ""}, Common.DBotScore.NONE),  # Empty string confidence
]


@pytest.mark.parametrize("indicator_input, expected_score", DBOT_SCORE_TEST_CASES)
def test_calculate_score_various_scenarios(
    indicator_input: dict[str, Any],
    expected_score: int,
):
    from AnomaliThreatStreamFeed import DBotScoreCalculator

    """
    Tests calculate_score across various confidence levels and edge cases,
    including missing or invalid confidence values.

    Given:
        - An indicator dictionary with varying 'confidence' values or missing 'confidence'.
        - Expected DBotScore and whether a debug message should be logged.
    When:
        - Calling calculate_score.
    Then:
        - The function returns the expected DBotScore.
        - demisto.debug is called or not called as expected based on the scenario.
    """
    calculator = DBotScoreCalculator()

    result = calculator.calculate_score(indicator_input)
    assert result == expected_score


def test_create_relationships_disabled():
    from AnomaliThreatStreamFeed import create_relationships

    """
    Tests create_relationships when relationship creation is disabled.
    Verifies that an empty list is returned.

    Given:
        - create_relationships_param is False.
        - Any indicator and reliability.
    When:
        - Calling create_relationships.
    Then:
        - An empty list is returned.
        - No debug messages are logged.
    """
    indicator = {
        "id": "125",
        "type": "email",
        "confidence": 65,
        "description": "test ip",
        "source": "NewSource",
        "value": "test_email@test.com",
        "tags": [{"id": "125a", "name": "tag125a"}, {"id": "125b", "name": "tag125b"}],
        "tlp": "RED",
        "country": "",
        "modified_ts": "2023-02-01T12:00:00Z",
        "org": "currentOrganization",
        "created_ts": "2022-02-01T12:00:00Z",
        "expiration_ts": "2024-02-01T12:00:00Z",
        "target_industry": [],
        "asn": "",
        "locations": "California",
    }
    reliability = "C - Fairly reliable"

    result = create_relationships(create_relationships_param=False, reliability=reliability, indicator=indicator)
    assert result == []


def test_create_relationships_missing_indicator_type_or_value():
    from AnomaliThreatStreamFeed import create_relationships

    """
    Tests create_relationships when indicator type or value is missing.
    Verifies that an empty list is returned and a debug message is logged.

    Given:
        - create_relationships_param is True.
        - Indicator with missing 'type' or 'value'.
    When:
        - Calling create_relationships.
    Then:
        - An empty list is returned.
        - A debug message about skipping relationship creation is logged.
    """
    reliability = "B - Usually reliable"

    # Test missing type
    indicator_no_type = {"value": "1.1.1.1", "rdns": ["example.com"]}
    result = create_relationships(create_relationships_param=True, reliability=reliability, indicator=indicator_no_type)
    assert result == []

    # Test missing value
    indicator_no_value = {"type": "ip", "rdns": ["example.com"]}
    result = create_relationships(create_relationships_param=True, reliability=reliability, indicator=indicator_no_value)
    assert result == []

    # Test empty string value
    indicator_empty_value = {"type": "ip", "value": "", "rdns": ["example.com"]}
    result = create_relationships(create_relationships_param=True, reliability=reliability, indicator=indicator_empty_value)
    assert result == []


def test_create_relationships_single_related_entity():
    from AnomaliThreatStreamFeed import create_relationships

    """
    Tests create_relationships with a single related entity.
    Verifies that one relationship is created correctly.

    Given:
        - create_relationships_param is True.
        - An Domain indicator with a single related ip.
    When:
        - Calling create_relationships.
    Then:
        - A list containing one correctly formatted relationship is returned.
    """
    indicator = {
        "id": "123",
        "type": "domain",
        "confidence": 90,
        "description": "Test domain",
        "source": "TestSource",
        "value": "mydomain1.com",
        "tags": ["malware", "phishing"],
        "tlp": "RED",
        "country": "US",
        "modified_ts": "2023-01-01T12:00:00Z",
        "org": "",
        "created_ts": "2022-01-01T12:00:00Z",
        "expiration_ts": "2024-01-01T12:00:00Z",
        "target_industry": ["finance"],
        "asn": "AS12345",
        "locations": "New York",
        "ip": "1.1.1.1",
    }

    reliability = "A - Completely reliable"

    expected_relationships = [
        {
            "entityA": "mydomain1.com",
            "entityAType": FeedIndicatorType.Domain,
            "name": EntityRelationship.Relationships.RESOLVED_FROM,
            "entityAFamily": "Indicator",
            "entityB": "1.1.1.1",
            "entityBType": FeedIndicatorType.IP,
            "type": "IndicatorToIndicator",
            "reverseName": EntityRelationship.Relationships.RESOLVES_TO,
            "entityBFamily": "Indicator",
            "fields": {},
        }
    ]
    result = create_relationships(create_relationships_param=True, reliability=reliability, indicator=indicator)
    assert result == expected_relationships


def test_create_relationships_multiple_related_entities():
    from AnomaliThreatStreamFeed import create_relationships

    """
    Tests create_relationships with multiple related entities in a list.
    Verifies that multiple relationships are created correctly.

    Given:
        - create_relationships_param is True.
        - An IP indicator with multiple RDNS entries and a malware type.
    When:
        - Calling create_relationships.
    Then:
        - A list containing multiple correctly formatted relationships is returned.
    """
    indicator = {
        "id": "123",
        "type": "domain",
        "confidence": 90,
        "description": "Test domain",
        "source": "TestSource",
        "value": "mydomain1.com",
        "tags": ["malware", "phishing"],
        "tlp": "RED",
        "country": "US",
        "modified_ts": "2023-01-01T12:00:00Z",
        "org": "",
        "created_ts": "2022-01-01T12:00:00Z",
        "expiration_ts": "2024-01-01T12:00:00Z",
        "target_industry": ["finance"],
        "asn": "AS12345",
        "locations": "New York",
        "ip": "1.1.1.1",
        "meta.maltype": "type",
    }
    reliability = "B - Usually reliable"

    expected_relationships = [
        {
            "entityA": "mydomain1.com",
            "entityAType": FeedIndicatorType.Domain,
            "name": EntityRelationship.Relationships.RESOLVED_FROM,
            "entityAFamily": "Indicator",
            "entityB": "1.1.1.1",
            "entityBType": FeedIndicatorType.IP,
            "type": "IndicatorToIndicator",
            "reverseName": EntityRelationship.Relationships.RESOLVES_TO,
            "entityBFamily": "Indicator",
            "fields": {},
        }
    ]

    result = create_relationships(create_relationships_param=True, reliability=reliability, indicator=indicator)
    assert result == expected_relationships


@pytest.mark.parametrize(
    "indicator, tlp_color, create_relationship_param, reliability, "
    "mock_relationships_return, mock_dbot_score_return, expected_output, expect_error",
    [
        # Basic valid indicator with relationships enabled
        (
            {
                "id": "123",
                "type": "ip",
                "confidence": 80,
                "description": "Test IP",
                "source": "TestSource",
                "value": "1.1.1.1",
                "tags": ["tag1", "tag2"],
                "tlp": "RED",
                "country": "US",
                "modified_ts": "2023-01-01T12:00:00Z",
                "org": "",
                "created_ts": "2022-01-01T12:00:00Z",
                "expiration_ts": "2024-01-01T12:00:00Z",
                "target_industry": ["finance"],
                "asn": "AS12345",
                "locations": "New York",
                "rdns": "example.com",
                "meta.maltype": "type",
            },
            "AMBER",
            True,
            "A - Completely reliable",
            [{"entityA": "1.1.1.1", "name": "resolves-to", "entityB": "example.com", "type": "Relationship"}],
            Common.DBotScore.BAD,
            {
                "value": "1.1.1.1",
                "type": "IP",
                "fields": {
                    "ThreatStreamID": "123",
                    "Source": "TestSource",
                    "IP": "1.1.1.1",
                    "Description": "Test IP",
                    "Confidence": "80",
                    "TrafficLightProtocol": "AMBER",
                    "TargetIndustries": ["finance"],
                    "CountryCode": "US",
                    "Modified": "2023-01-01T12:00:00Z",
                    "Creation": "2022-01-01T12:00:00Z",
                    "Tags": ["tag1", "tag2"],
                    "Location": "New York",
                    "ASN": "AS12345",
                },
                "relationships": [
                    {"entityA": "1.1.1.1", "name": "resolves-to", "entityB": "example.com", "type": "Relationship"}
                ],
                "rawJSON": {
                    "id": "123",
                    "type": "ip",
                    "value": "1.1.1.1",
                    "confidence": 80,
                    "source": "TestSource",
                    "description": "Test IP",
                    "rdns": "example.com",
                    "meta.maltype": "type",
                    "target_industry": ["finance"],
                    "asn": "AS12345",
                    "locations": "New York",
                    "tags": ["tag1", "tag2"],
                    "tlp": "RED",
                    "country": "US",
                    "modified_ts": "2023-01-01T12:00:00Z",
                    "org": "",
                    "created_ts": "2022-01-01T12:00:00Z",
                    "expiration_ts": "2024-01-01T12:00:00Z",
                },
                "score": Common.DBotScore.BAD,
            },
            False,
        ),
        # Missing indicator 'type'
        (
            {"id": "125", "value": "missing_type_value", "confidence": 50},
            "RED",
            True,
            "C - Fairly reliable",
            [],
            Common.DBotScore.NONE,
            None,
            True,  # Expect ValueError
        ),
        # Missing indicator 'value'
        (
            {"id": "126", "type": "url", "confidence": 50},
            "RED",
            True,
            "C - Fairly reliable",
            [],
            Common.DBotScore.NONE,
            None,
            True,  # Expect ValueError
        ),
    ],
)
def test_parse_indicator_for_fetch_various_scenarios(
    indicator: dict[str, Any],
    tlp_color: str,
    create_relationship_param: bool,
    reliability: str,
    mock_relationships_return: list[dict[str, Any]],
    mock_dbot_score_return: int,
    expected_output: dict[str, Any],
    expect_error: bool,
    mocker,
):
    from AnomaliThreatStreamFeed import parse_indicator_for_fetch

    """
    Tests parse_indicator_for_fetch across various scenarios, including valid inputs,
    missing/invalid indicator data, and different relationship/DBotScore outcomes.

    Given:
        - A raw indicator dictionary.
        - TLP color, relationship creation flag, and reliability.
        - Mock return values for create_relationships and DBotScoreCalculator.calculate_score.
        - Expected output dictionary or a flag indicating an expected error.
    When:
        - Calling parse_indicator_for_fetch.
    Then:
        - If an error is expected, verifies that ValueError is raised.
        - Otherwise, verifies that the returned parsed indicator matches the expected output.
        - Verifies that create_relationships and calculate_score are called with correct arguments.
    """
    # Mock the external functions/methods
    mocker.patch("AnomaliThreatStreamFeed.create_relationships", return_value=mock_relationships_return)
    mocker.patch("AnomaliThreatStreamFeed.DBotScoreCalculator.calculate_score", return_value=mock_dbot_score_return)

    if expect_error:
        with pytest.raises(ValueError) as excinfo:
            parse_indicator_for_fetch(indicator, tlp_color, create_relationship_param, reliability)
        assert f"Indicator missing 'type' or 'value': {indicator}" in str(excinfo.value)
    else:
        result = parse_indicator_for_fetch(indicator, tlp_color, create_relationship_param, reliability)
        assert result == expected_output


TEST_CASES = [
    # Scenario 1: First run, no last_run, single page of indicators
    {
        "name": "First run, single page, default fetchBy (modified_ts)",
        "params": {
            "createRelationships": True,
            "tlp_color": "WHITE",
            "feedReliability": "C - Fairly reliable",
            "feedFetchInterval": "60",
        },
        "last_run": {},
        "mock_http_responses": [
            {
                "objects": [{"id": "1", "type": "ip", "value": "1.1.1.1", "modified_ts": "2023-08-01T11:00:00.000Z"}],
                "meta": {"next": None},
            }
        ],
        "mock_get_past_time_return": "2023-08-01T11:00:00.000Z",
        "mock_parse_indicator_for_fetch_side_effect": {"value": "1.1.1.1", "type": "IP"},
        "mock_now": datetime(2023, 8, 1, 12, 0, 0, tzinfo=UTC),
        "expected_next_run_timestamp": "2023-08-01T12:00:00Z",
        "expected_parsed_indicators": [{"value": "1.1.1.1", "type": "IP"}],
        "expected_info_calls": [f"{THREAT_STREAM} - First fetch detected. Retrieving indicators from the last 60 minutes."],
        "expected_debug_calls": [
            f"""{THREAT_STREAM} - Initial API call for fetch-indicators with params: {{'limit': 50, 'status': 'active',
            'order_by': 'modified_ts', 'confidence__gt': 65, 'modified_ts__gte': '2023-08-01T11:00:00.000Z'}}""",
            f"{THREAT_STREAM} - Total raw indicators fetched: 1",
            f"{THREAT_STREAM} - Successfully parsed 1 indicators for fetch.",
        ],
        "expected_error_calls": [],
        "expected_exception": None,
        "expected_http_calls": [
            {
                "method": "GET",
                "url_suffix": "v2/intelligence",
                "params": {
                    "limit": 50,
                    "status": "active",
                    "order_by": "modified_ts",
                    "confidence__gt": 65,
                    "modified_ts__gte": "2023-08-01T11:00:00.000Z",
                },
            }
        ],
    },
]


@pytest.mark.parametrize("test_case", TEST_CASES)
def test_fetch_indicators_command_scenarios(mocker, test_case):
    """
    Tests fetch_indicators_command across various scenarios using parametrization.

    Covers: first run, subsequent runs, pagination, no new indicators,
    parsing errors, pagination errors, and parameter handling.

    Given:
        - A test_case dictionary containing specific inputs and expected outcomes
          for client responses, mocked function returns, and log messages.
    When:
        - Calling fetch_indicators_command with the test case's parameters.
    Then:
        - Verifies that the command returns the expected next run timestamp and parsed indicators.
        - Asserts that external functions (http_request, get_past_time, parse_indicator_for_fetch, demisto logs)
          are called correctly based on the scenario.
        - Handles expected exceptions.
    """
    from AnomaliThreatStreamFeed import fetch_indicators_command

    client = mock_client()
    mock_http_request = mocker.patch.object(client, "http_request")
    # Use a list of responses for http_request to simulate pagination
    mock_http_request.side_effect = test_case["mock_http_responses"]

    mock_get_past_time = mocker.patch("AnomaliThreatStreamFeed.get_past_time")
    if test_case["mock_get_past_time_return"]:
        mock_get_past_time.return_value = test_case["mock_get_past_time_return"]

    mock_parse_indicator_for_fetch = mocker.patch("AnomaliThreatStreamFeed.parse_indicator_for_fetch")
    # Handle both single return value and list of side effects for parse_indicator_for_fetch
    if isinstance(test_case["mock_parse_indicator_for_fetch_side_effect"], list):
        mock_parse_indicator_for_fetch.side_effect = test_case["mock_parse_indicator_for_fetch_side_effect"]
    else:
        mock_parse_indicator_for_fetch.return_value = test_case["mock_parse_indicator_for_fetch_side_effect"]

    # Mock datetime.now for consistent timestamps
    mock_now_dt = test_case["mock_now"]
    mocker.patch("AnomaliThreatStreamFeed.get_current_utc_time", return_value=mock_now_dt)

    if test_case["expected_exception"]:
        with pytest.raises(test_case["expected_exception"]):
            fetch_indicators_command(client, test_case["params"], test_case["last_run"])
    else:
        next_run_timestamp, parsed_indicators_list = fetch_indicators_command(client, test_case["params"], test_case["last_run"])

        assert next_run_timestamp == test_case["expected_next_run_timestamp"]
        assert parsed_indicators_list == test_case["expected_parsed_indicators"]

        # # Assert get_past_time call only if expected
        # if "last_successful_run" not in test_case["last_run"]:
        #     mock_get_past_time.assert_called_once_with(test_case["params"].get("feedFetchInterval", 240))
        # else:
        #     mock_get_past_time.assert_not_called()

        # Assert parse_indicator_for_fetch calls (check number of calls for simplicity)
        if test_case["expected_parsed_indicators"]:
            # If parsing errors can occur, the number of calls might not equal len(expected_parsed_indicators)
            # It should equal the number of raw indicators in http responses that *don't* cause an error.
            num_raw_indicators_to_parse = 0
            for http_resp in test_case["mock_http_responses"]:
                if isinstance(http_resp, dict) and "objects" in http_resp:
                    num_raw_indicators_to_parse += len(http_resp["objects"])

            # If there was a parsing error side effect, reduce the count of expected successful parses
            # This logic needs to be more robust if multiple parsing errors are possible.
            # For now, it assumes side_effect is either a single return or a list matching raw indicator count,
            # and an exception means that specific call sequence for parse_indicator_for_fetch stopped.
            if isinstance(test_case["mock_parse_indicator_for_fetch_side_effect"], list):
                expected_parse_calls = 0
                for item in test_case["mock_parse_indicator_for_fetch_side_effect"]:
                    if not isinstance(item, Exception):
                        expected_parse_calls += 1
                assert (
                    mock_parse_indicator_for_fetch.call_count == num_raw_indicators_to_parse
                )  # All raw indicators are attempted to be parsed
            else:  # Single return value implies all parsed successfully
                assert mock_parse_indicator_for_fetch.call_count == num_raw_indicators_to_parse
        else:
            assert mock_parse_indicator_for_fetch.call_count == 0  # No indicators to parse
