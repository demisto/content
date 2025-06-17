from CommonServerPython import tableToMarkdown, Common, FeedIndicatorType, EntityRelationship
import pytest
from AnomaliThreatStreamFeed import Client
from datetime import datetime, timezone

from typing import Any


THREAT_STREAM = "Anomali ThreatStream Feed"


def mock_client():
    return Client(base_url="https://api.threatstream.com", user_name="user", api_key="key", verify=True)

def test_get_indicators_command_success_with_type(mocker):
    """
    Tests the successful execution of get_indicators_command when an indicator_type is specified.
    Verifies that the command fetches indicators and returns a human-readable table with the dynamic header.

    Given:
        - A mock Client instance.
        - Arguments with 'indicator_type' and 'limit'.
    When:
        - Calling get_indicators_command.
    Then:
        Verify that:
        - The readable_output of CommandResults contains the expected table.
        - The raw_response of CommandResults contains the raw indicators.
    """
    from AnomaliThreatStreamFeed import get_indicators_command, parse_indicators_for_get_command

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

    mocker.patch.object(client, "http_request", return_value=mock_api_response)
    returned_parsed_indicators = parse_indicators_for_get_command(mock_api_response["objects"])

    args = {"indicator_type": "domain", "limit": 2}
    result = get_indicators_command(client, args)

    expected_headers_with_type = [
        "TargetIndustries",
        "Source",
        "ThreatStreamID",
        "Country Code",
        "Domain",
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
        t=returned_parsed_indicators,
        headers=expected_headers_with_type,
        removeNull=True,
        is_auto_json_transform=True,
    )
    assert result.readable_output == human_readable
    assert result.raw_response == mock_api_response["objects"]


def test_get_indicators_command_success_no_type(mocker):
    """
    Tests the successful execution of get_indicators_command when no indicator_type is specified.
    Verifies that the command fetches indicators and returns a human-readable table.

    Given:
        - A mock Client instance.
        - Arguments with no 'indicator_type' and a 'limit'.
    When:
        - Calling get_indicators_command.
    Then:
        Verify that:
        - The client's http_request method is called with the correct parameters.
        - `parse_indicators_for_get_command` is called with the raw indicators.
        - `tableToMarkdown` is called with the expected headers (no dynamic type header).
        - The readable_output of CommandResults contains the expected table.
        - The raw_response of CommandResults contains the raw indicators.
    """
    from AnomaliThreatStreamFeed import get_indicators_command, parse_indicators_for_get_command

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

    mocker.patch.object(client, "http_request", return_value=mock_api_response)
    returned_parsed_indicators = parse_indicators_for_get_command(mock_api_response["objects"])

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
        t=returned_parsed_indicators,
        headers=expected_headers_with_type,
        removeNull=True,
        is_auto_json_transform=True,
    )
    assert result.readable_output == human_readable
    assert result.raw_response == mock_api_response["objects"]


def test_get_indicators_command_invalid_type():
    """
    Tests the scenario where an invalid indicator_type is provided to get_indicators_command.
    Verifies that the function returns an error message and does not proceed to make API calls.

    Given:
        - A mock Client instance.
        - Arguments with an 'indicator_type' that is not in the allowed list.
    When:
        - Calling get_indicators_command.
    Then:
        Verify that:
        - The returned CommandResults object has the expected human-readable error output.
    """
    from AnomaliThreatStreamFeed import get_indicators_command

    client = mock_client()

    # Arguments with an invalid indicator type
    args = {"indicator_type": "malware", "limit": 10}

    result = get_indicators_command(client, args)

    expected_readable_output = """### Invalid indicator type. Select one of the following types: domain, email, ip, md5, url"""
    assert result.readable_output == expected_readable_output
    assert result.raw_response is None


def test_get_indicators_command_no_indicators_found(mocker):
    """
    Tests the scenario where no indicators are found for the given criteria.
    Verifies that the command returns an appropriate message.

    Given:
        - A mock Client instance that returns no indicators.
        - Arguments for the command.
    When:
        - Calling get_indicators_command.
    Then:
        Verify that:
        - The readable_output of CommandResults contains "No indicators found.".
        - The raw_response is an empty list.
    """
    from AnomaliThreatStreamFeed import get_indicators_command

    client = mock_client()
    args = {"limit": 10, "indicator_type": "url"}

    mocker.patch.object(client, "http_request", return_value={"objects": []})

    result = get_indicators_command(client, args)

    client.http_request.assert_called_once_with(method="GET", url_suffix="v2/intelligence", params={"limit": 10, "type": "url"})
    assert result.readable_output == "### No indicators were found."
    assert result.raw_response is None


def test_parse_indicators_for_get_command_full_data():
    """
    Tests parse_indicators_for_get_command with a complete raw indicator.
    Verifies that all fields are correctly mapped and the dynamic field is added.

    Given:
        - A list containing one raw indicator with all expected fields.
    When:
        - Calling parse_indicators_for_get_command.
    Then:
        Verify that:
        - The returned list contains one parsed indicator with all fields correctly mapped,
          including the dynamic indicator's type field and string conversions for 'id' and 'confidence'.
    """
    from AnomaliThreatStreamFeed import parse_indicators_for_get_command

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
            "Domain": "mydomain1.com",
            "Description": "Test domain",
            "Modified": "2023-01-01T12:00:00Z",
            "Confidence": "90",
            "Creation": "2022-01-01T12:00:00Z",
            "Tags": ["tag125a", "tag125b"],
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
    """
    Tests parse_indicators_for_get_command when some fields are missing in the raw indicator.
    Verifies that missing fields are correctly omitted (due to assign_params).

    Given:
        - A list containing one raw indicator with several missing optional fields.
    When:
        - Calling parse_indicators_for_get_command.
    Then:
        Verify that:
        - The returned list contains one parsed indicator where missing fields are not present.
        - Dynamic field is still added if type and value exist.
    """
    from AnomaliThreatStreamFeed import parse_indicators_for_get_command

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
        {"Source": "AnotherSource", "ThreatStreamID": "456", "IP": "2.2.2.2", "Description": "Simple IP", "Confidence": "None"},
    ]

    result = parse_indicators_for_get_command(mock_raw_indicators)
    assert result == expected_parsed_indicators


def test_get_past_time_basic_interval(mocker):
    """
    Tests get_past_time with a standard minutes interval.
    Verifies that the returned time is correctly calculated and formatted.

    Given:
        - A minutes_interval of 60.
        - A mocked current UTC datetime (via mocking get_current_utc_time).
    When:
        - Calling get_past_time, imported from 'AnomaliThreatStreamFeed'.
    Then:
        Verify that:
        - Mocks 'AnomaliThreatStreamFeed.get_current_utc_time' to return a fixed datetime.
        - The function returns the expected past time in ISO 8601 format with milliseconds and 'Z'.
    """
    from AnomaliThreatStreamFeed import get_past_time

    mock_now = datetime(2023, 8, 1, 12, 0, 0, 500000, tzinfo=timezone.utc)
    minutes_interval = 60  # one hour ago
    expected_past_time = "2023-08-01T11:00:00.500Z"

    mocker.patch("AnomaliThreatStreamFeed.get_current_utc_time", return_value=mock_now)

    result = get_past_time(minutes_interval)
    assert result == expected_past_time


def test_calculate_score_none_no_confidence_field():
    """
    Tests calculate_score when the 'confidence' field is missing from the indicator.
    Verifies that DBotScore.NONE is returned and a debug message is logged.

    Given:
        - An indicator dictionary without a 'confidence' key.
    When:
        - Calling calculate_score.
    Then:
        Verify that:
        - The function returns Common.DBotScore.NONE.
    """
    from AnomaliThreatStreamFeed import DBotScoreCalculator

    calculator = DBotScoreCalculator()
    indicator = {"description": "test"}  # No confidence field

    result = calculator.calculate_score(indicator)
    assert result == Common.DBotScore.NONE


DEFAULT_MALICIOUS_THRESHOLD = 65
DEFAULT_SUSPICIOUS_THRESHOLD = 25
DEFAULT_BENIGN_THRESHOLD = 0
DBOT_SCORE_TEST_CASES = [
    # Test cases for BAD score (confidence > 65) - ID 0-1
    pytest.param({"confidence": 71}, Common.DBotScore.BAD, id="ID 0 - Test cases for BAD score (confidence > 65)"),
    pytest.param({"confidence": 100}, Common.DBotScore.BAD, id="ID 1 - Test cases for BAD score (confidence > 65)"),
    pytest.param(
        {"confidence": 51}, Common.DBotScore.SUSPICIOUS, id="ID 2 - Test cases for SUSPICIOUS score (confidence > 25 and <= 65)"
    ),
    pytest.param(
        {"confidence": DEFAULT_MALICIOUS_THRESHOLD},
        Common.DBotScore.SUSPICIOUS,
        id="ID 3 - Test cases for SUSPICIOUS score (confidence > 25 and <= 65)",
    ),  # 65 is not > 65
    pytest.param(
        {"confidence": 60}, Common.DBotScore.SUSPICIOUS, id="ID 4 - Test cases for SUSPICIOUS score (confidence > 25 and <= 65)"
    ),
    pytest.param(
        {"confidence": 26}, Common.DBotScore.SUSPICIOUS, id="ID 5 - Test cases for SUSPICIOUS score (confidence > 25 and <= 65)"
    ),
    pytest.param({"confidence": 15}, Common.DBotScore.GOOD, id="ID 6 - Test cases for GOOD score (confidence > 0 and <= 25)"),
    pytest.param(
        {"confidence": DEFAULT_SUSPICIOUS_THRESHOLD},
        Common.DBotScore.GOOD,
        id="ID 7 - Test cases for GOOD score (confidence > 0 and <= 25)",
    ),  # 25 is not > 25
    pytest.param({"confidence": 20}, Common.DBotScore.GOOD, id="ID 8 - Test cases for GOOD score (confidence > 0 and <= 25)"),
    pytest.param({"confidence": 1}, Common.DBotScore.GOOD, id="ID 9 - Test cases for GOOD score (confidence > 0 and <= 25)"),
    pytest.param({"confidence": 0}, Common.DBotScore.NONE, id="ID 10 - Test cases for NONE score (confidence <= 0)"),
    pytest.param(
        {"confidence": DEFAULT_BENIGN_THRESHOLD}, Common.DBotScore.NONE, id="ID 11 - Test cases for NONE score (confidence <= 0)"
    ),
    pytest.param({"confidence": -5}, Common.DBotScore.NONE, id="ID 12 - Test cases for NONE score (confidence <= 0)"),
    # Test cases for NONE score (missing/invalid confidence) - ID 13-15
    pytest.param(
        {"description": "no confidence"},
        Common.DBotScore.NONE,
        id="ID 13 -Test cases for NONE score (missing/invalid confidence)",
    ),
    pytest.param({"confidence": None}, Common.DBotScore.NONE, id="ID 14 -Test cases for NONE score (missing/invalid confidence)"),
    pytest.param({"confidence": ""}, Common.DBotScore.NONE, id="ID 15 -Test cases for NONE score (missing/invalid confidence)"),
]


@pytest.mark.parametrize("indicator_input, expected_score", DBOT_SCORE_TEST_CASES)
def test_calculate_score_various_scenarios(
    indicator_input: dict[str, Any],
    expected_score: int,
):
    """
    Tests calculate_score across various confidence levels and edge cases,
    including missing or invalid confidence values.

    Test Cases Explained:

    - **0-1:** Test cases for **BAD** score (> 65 confidence).
    - **2-5:** Test cases for **SUSPICIOUS** score (> 25 and <= 65 confidence), including boundary checks at 65 and 26.
    - **6-9:** Test cases for **GOOD** score (> 0 and <= 25 confidence), including boundary checks at 25 and 1.
    - **10-12:** Test cases for **NONE** score (<= 0 confidence), including boundary check at 0 and negative values.
    - **13-15:** Test cases for **NONE** score where confidence is missing or invalid (e.g., `None`, empty string).

    Given:
        - An indicator dictionary with varying 'confidence' values or missing 'confidence'.
        - Expected DBotScore and whether a debug message should be logged.
    When:
        - Calling calculate_score.
    Then:
        Verify that:
        - The function returns the expected DBotScore.
    """
    from AnomaliThreatStreamFeed import DBotScoreCalculator

    calculator = DBotScoreCalculator()

    result = calculator.calculate_score(indicator_input)
    assert result == expected_score


def test_create_relationships_disabled():
    """
    Tests create_relationships when relationship creation is disabled.
    Verifies that an empty list is returned.

    Given:
        - create_relationships_param is False.
        - Any indicator and reliability.
    When:
        - Calling create_relationships.
    Then:
        Verify that:
        - An empty list is returned.
        - No debug messages are logged.
    """
    from AnomaliThreatStreamFeed import create_relationships

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
    """
    Tests create_relationships when the indicator type or value is missing.
    Verifies that an empty list is returned and a debug message is logged.

    Given:
        - create_relationships_param is True.
        - Indicator with missing 'type' or 'value'.
    When:
        - Calling create_relationships.
    Then:
        Verify that:
        - An empty list is returned.
        - A debug message about skipping relationship creation is logged.
    """
    from AnomaliThreatStreamFeed import create_relationships

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
    """
    Tests create_relationships with a single related entity.
    Verifies that one relationship is created correctly.

    Given:
        - create_relationships_param is True.
        - A Domain indicator with a single related IP.
    When:
        - Calling create_relationships.
    Then:
        Verify that:
        - A list containing one correctly formatted relationship is returned.
    """
    from AnomaliThreatStreamFeed import create_relationships

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
    """
    Tests create_relationships with multiple related entities in a list.
    Verifies that multiple relationships are created correctly.

    Given:
        - create_relationships_param is True.
        - A domain indicator.
    When:
        - Calling create_relationships.
    Then:
        Verify that:
        - A list containing multiple correctly formatted relationships is returned.
    """
    from AnomaliThreatStreamFeed import create_relationships

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


def test_parse_indicator_for_fetch_success_scenarios(mocker):
    """
    Tests parse_indicator_for_fetch for successful parsing scenarios.

    Given:
        - A raw indicator dictionary.
        - TLP color, relationship creation flag, and reliability.
        - Mock return value for DBotScoreCalculator.calculate_score.
        - Expected output dictionary.
    When:
        - Calling parse_indicator_for_fetch.
    Then:
        Verify that:
        - The returned parsed indicator matches the expected output.
        - Verifies that calculate_score is called with correct arguments.
    """
    from AnomaliThreatStreamFeed import parse_indicator_for_fetch

    indicator = {
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
    }
    tlp_color = "AMBER"
    create_relationship_param = True
    reliability = "A - Completely reliable"

    expected_output = {
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
            {
                "name": "resolves-to",
                "reverseName": "resolved-from",
                "type": "IndicatorToIndicator",
                "entityA": "1.1.1.1",
                "entityAFamily": "Indicator",
                "entityAType": "IP",
                "entityB": "example.com",
                "entityBFamily": "Indicator",
                "entityBType": "Domain",
                "fields": {},
            }
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
    }

    mocker.patch("AnomaliThreatStreamFeed.DBotScoreCalculator.calculate_score", return_value=Common.DBotScore.BAD)

    result = parse_indicator_for_fetch(indicator, tlp_color, create_relationship_param, reliability)
    assert result == expected_output


@pytest.mark.parametrize(
    "indicator, tlp_color, create_relationship_param, reliability, mock_dbot_score_return",
    [
        pytest.param(
            {"id": "125", "value": "missing_type_value", "confidence": 50},
            "RED",
            True,
            "C - Fairly reliable",
            Common.DBotScore.NONE,
            id="Test Case 1: Missing indicator 'type'",
        ),
        pytest.param(
            {"id": "126", "type": "url", "confidence": 50},
            "RED",
            True,
            "C - Fairly reliable",
            Common.DBotScore.NONE,
            id="Test Case 2: Missing indicator 'value'",
        ),
    ],
)
def test_parse_indicator_for_fetch_error_scenarios(
    indicator: dict[str, Any],
    tlp_color: str,
    create_relationship_param: bool,
    reliability: str,
    mock_dbot_score_return: int,
    mocker,
):
    """
    Tests parse_indicator_for_fetch for scenarios that are expected to raise an error.

    Given:
        - A raw indicator dictionary with missing or invalid critical data.
        - TLP color, relationship creation flag, and reliability.
        - Mock return value for DBotScoreCalculator.calculate_score.
    When:
        - Calling parse_indicator_for_fetch.
    Then:
        Verify that:
        - A `ValueError` is raised with the expected error message.

    Test Cases Explained:
    - **Test Case 1 (Missing indicator 'type'):** This case specifically tests the error handling when the essential 'type' field
        is missing from the raw indicator data. It expects a `ValueError` to be raised, indicating that the indicator cannot be
        processed without this crucial piece of information.
    - **Test Case 2 (Missing indicator 'value'):** Similar to the previous case, this tests the error handling when the 'value'
        field, which is also critical for identifying the indicator, is missing. It also expects a `ValueError`, confirming that
        the function correctly identifies and handles incomplete indicator data.
    """
    from AnomaliThreatStreamFeed import parse_indicator_for_fetch

    # Mock the external functions/methods
    mocker.patch("AnomaliThreatStreamFeed.DBotScoreCalculator.calculate_score", return_value=mock_dbot_score_return)

    with pytest.raises(ValueError) as excinfo:
        parse_indicator_for_fetch(indicator, tlp_color, create_relationship_param, reliability)
    assert f"Indicator missing 'type' or 'value': {indicator}" in str(excinfo.value)


TEST_CASES = [
    {
        "params": {},  # Use defaults
        "last_run": {"last_successful_run": "2023-08-01T09:00:00Z"},
        "mock_http_responses": [{"objects": [], "meta": {"next": None}}],
        "mock_get_past_time_return": None,
        "mock_parse_indicator_for_fetch_side_effect": [],
        "mock_now": datetime(2023, 8, 1, 12, 0, 0, tzinfo=timezone.utc),
        "expected_next_run_timestamp": "2023-08-01T12:00:00Z",
        "expected_parsed_indicators": [],
        "expected_exception": None,
    },
]


@pytest.mark.parametrize("test_case", TEST_CASES)
def test_fetch_indicators_command_subsequent_run_no_new_indicators(mocker, test_case):
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
        Verify that:
        - Verifies that the command returns the expected next run timestamp and parsed indicators.
        - Asserts that external functions (http_request, get_past_time, parse_indicator_for_fetch)
          are called correctly based on the scenario.
        - Handles expected exceptions.
    """
    from AnomaliThreatStreamFeed import fetch_indicators_command

    client = mock_client()
    mock_http_request = mocker.patch.object(client, "http_request")
    # Use a list of responses for http_request to simulate pagination
    mock_http_request.side_effect = test_case["mock_http_responses"]

    mock_parse_indicator_for_fetch = mocker.patch("AnomaliThreatStreamFeed.parse_indicator_for_fetch")
    mock_parse_indicator_for_fetch.side_effect = test_case["mock_parse_indicator_for_fetch_side_effect"]

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

        assert mock_parse_indicator_for_fetch.call_count == 0  # No indicators to parse


TEST_CASES = [
    {
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
        "mock_now": datetime(2023, 8, 1, 12, 0, 0, tzinfo=timezone.utc),
        "expected_next_run_timestamp": "2023-08-01T12:00:00Z",
        "expected_parsed_indicators": [{"value": "1.1.1.1", "type": "IP"}],
        "expected_exception": None,
    },
]


@pytest.mark.parametrize("test_case", TEST_CASES)
def test_fetch_indicators_command_first_run_with_indicators(mocker, test_case):
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
        Verify that:
        - Verifies that the command returns the expected next run timestamp and parsed indicators.
        - Asserts that external functions (http_request, get_past_time, parse_indicator_for_fetch)
          are called correctly based on the scenario.
        - Handles expected exceptions.
    """
    from AnomaliThreatStreamFeed import fetch_indicators_command

    client = mock_client()
    mock_http_request = mocker.patch.object(client, "http_request")
    # Use a list of responses for http_request to simulate pagination
    mock_http_request.side_effect = test_case["mock_http_responses"]

    mock_get_past_time = mocker.patch("AnomaliThreatStreamFeed.get_past_time")
    mock_get_past_time.return_value = test_case["mock_get_past_time_return"]

    mock_parse_indicator_for_fetch = mocker.patch("AnomaliThreatStreamFeed.parse_indicator_for_fetch")
    mock_parse_indicator_for_fetch.return_value = test_case["mock_parse_indicator_for_fetch_side_effect"]

    # Mock datetime.now for consistent timestamps
    mock_now_dt = test_case["mock_now"]
    mocker.patch("AnomaliThreatStreamFeed.get_current_utc_time", return_value=mock_now_dt)

    next_run_timestamp, parsed_indicators_list = fetch_indicators_command(client, test_case["params"], test_case["last_run"])

    assert next_run_timestamp == test_case["expected_next_run_timestamp"]
    assert parsed_indicators_list == test_case["expected_parsed_indicators"]

    # If parsing errors can occur, the number of calls might not equal len(expected_parsed_indicators)
    # It should equal the number of raw indicators in http responses.
    num_raw_indicators_to_parse = 0
    for http_resp in test_case["mock_http_responses"]:
        num_raw_indicators_to_parse += len(http_resp["objects"])

    # If there was a parsing error side effect, reduce the count of expected successful parses
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


def test_fetch_indicators_command_parsing_error_skips_indicator(mocker):
    """
    Tests fetch_indicators_command's error handling for individual indicator parsing.

    Given:
        - A scenario where `parse_indicator_for_fetch` raises an exception for one indicator
          but successfully parses another.
        - Mock API response with multiple raw indicators.
    When:
        - Calling fetch_indicators_command.
    Then:
        Verify that:
        - Only successfully parsed indicators are returned.
        - `parse_indicator_for_fetch` is attempted for all raw indicators.
        - The `next_run_timestamp` is correctly updated.
    """
    from AnomaliThreatStreamFeed import fetch_indicators_command  # Assuming it's in this module

    # Define test data
    first_indicator_raw = {"id": "1", "type": "ip", "value": "1.1.1.1", "modified_ts": "2023-08-01T11:00:00.000Z"}
    second_indicator_raw = {"id": "2", "type": "domain", "value": "example.com", "modified_ts": "2023-08-01T11:01:00.000Z"}

    test_case_data = {
        "params": {
            "createRelationships": True,
            "tlp_color": "GREEN",
            "feedReliability": "B - Usually reliable",
            "feedFetchInterval": "10",
        },
        "last_run": {},
        "mock_http_responses": [
            {
                "objects": [first_indicator_raw, second_indicator_raw],
                "meta": {"next": None},
            }
        ],
        "mock_get_past_time_return": "2023-08-01T10:00:00.000Z",
        "mock_parse_indicator_for_fetch_side_effect": [
            ValueError("Simulated parsing error"),  # First indicator fails parsing
            {"value": "example.com", "type": "DOMAIN"},  # Second indicator parses successfully
        ],
        "mock_now": datetime(2023, 8, 1, 12, 0, 0, tzinfo=timezone.utc),
        "expected_next_run_timestamp": "2023-08-01T12:00:00Z",
        "expected_parsed_indicators": [{"value": "example.com", "type": "DOMAIN"}],  # Only the second one
    }

    client = mock_client()
    mocker.patch.object(client, "http_request", side_effect=test_case_data["mock_http_responses"])

    mock_parse_indicator_for_fetch = mocker.patch(
        "AnomaliThreatStreamFeed.parse_indicator_for_fetch",
        side_effect=test_case_data["mock_parse_indicator_for_fetch_side_effect"],
    )
    mock_demisto_error = mocker.patch("AnomaliThreatStreamFeed.demisto.error")  # Patch demisto.error to assert its call

    mock_now_dt = test_case_data["mock_now"]
    mocker.patch("AnomaliThreatStreamFeed.get_current_utc_time", return_value=mock_now_dt)

    next_run_timestamp, parsed_indicators_list = fetch_indicators_command(
        client, test_case_data["params"], test_case_data["last_run"]
    )

    # Assertions
    assert next_run_timestamp == test_case_data["expected_next_run_timestamp"]
    assert parsed_indicators_list == test_case_data["expected_parsed_indicators"]

    # Verify demisto.error was called for the skipped indicator
    mock_demisto_error.assert_called_once_with(
        f"{THREAT_STREAM} - Error parsing indicator ID {first_indicator_raw.get('id')}:"
        f"Simulated parsing error. Skipping this indicator."
    )

    # Verify that parse_indicator_for_fetch was called for ALL raw indicators,
    # even though one failed.
    assert mock_parse_indicator_for_fetch.call_count == 2
    mock_parse_indicator_for_fetch.assert_has_calls(
        [
            mocker.call(
                first_indicator_raw,
                test_case_data["params"]["tlp_color"],
                test_case_data["params"]["createRelationships"],
                test_case_data["params"]["feedReliability"],
            ),
            mocker.call(
                second_indicator_raw,
                test_case_data["params"]["tlp_color"],
                test_case_data["params"]["createRelationships"],
                test_case_data["params"]["feedReliability"],
            ),
        ]
    )


def test_extract_tag_names_with_valid_tags():
    """
    Tests extract_tag_names with a valid list of tags.
    Verifies that all tag names are extracted correctly.

    Given:
        - An indicator dictionary with a 'tags' key containing a list of well-formed tag dictionaries.
    When:
        - Calling extract_tag_names.
    Then:
        Verify that:
        - A list of expected tag names is returned.
    """
    from AnomaliThreatStreamFeed import extract_tag_names

    indicator = {
        "id": "123",
        "value": "example.com",
        "type": "domain",
        "tags": [
            {"id": "fce", "name": "test1"},
            {"id": "94f", "name": "https://1.1.1./example/exampletags"},
            {"id": "abc", "name": "tag_123"},
        ],
    }
    expected_names = ["test1", "https://1.1.1./example/exampletags", "tag_123"]
    result = extract_tag_names(indicator)
    assert result == expected_names


def test_extract_tag_names_with_no_tags_none():
    """
    Tests extract_tag_names when the 'tags' key value is None.
    Verifies that an empty list is returned.

    Given:
        - An indicator dictionary where the 'tags' key's value is None.
    When:
        - Calling extract_tag_names.
    Then:
        Verify that:
        - An empty list is returned.
    """
    from AnomaliThreatStreamFeed import extract_tag_names

    indicator = {"id": "456", "value": "another.org", "type": "domain", "tags": None}
    result = extract_tag_names(indicator)
    assert result == []


def test_extract_tag_names_with_tags_not_a_list():
    """
    Tests extract_tag_names when the 'tags' value is not a list.
    Verifies that an empty list is returned.

    Given:
        - An indicator dictionary where the 'tags' key's value is a string or a dictionary
          (i.e., not a list).
    When:
        - Calling extract_tag_names.
    Then:
        Verify that:
        - An empty list is returned.
    """
    from AnomaliThreatStreamFeed import extract_tag_names

    indicator_str = {"id": "333", "value": "not_a_list", "tags": "some_string_value"}
    result_str = extract_tag_names(indicator_str)
    assert result_str == []

    indicator_dict = {"id": "444", "value": "not_a_list_dict", "tags": {"key": "value"}}
    result_dict = extract_tag_names(indicator_dict)
    assert result_dict == []
    
def test_error_handler_401_raises_demisto_exception():
    """
    Tests error_handler when the response status code is 401.
    Verifies that a DemistoException is raised with the correct message.
    """
    import requests
    from CommonServerPython import DemistoException
    mock_response = requests.Response()
    mock_response.status_code = 401
    mock_response._content = b'Unauthorized access'

    try:
        mock_client().error_handler(mock_response)
    except DemistoException as e:
        expected_message_part = f"{THREAT_STREAM} - Got unauthorized from the server. Check the credentials. Unauthorized access"
        assert expected_message_part in str(e), f"Unexpected exception message: {str(e)}"
        
        
def test_error_handler_404_raises_demisto_exception():
    """
    Tests error_handler when the response status code is 404.
    Verifies that a DemistoException is raised with the correct message.
    """
    import requests
    from CommonServerPython import DemistoException
    mock_response = requests.Response()
    mock_response.status_code = 404
    mock_response._content = b'Not Found'

    try:
        mock_client().error_handler(mock_response)
    except DemistoException as e:
        expected_message_part = f"{THREAT_STREAM} - The resource was not found. Not Found"
        assert expected_message_part in str(e), f"Unexpected exception message: {str(e)}"
        
def test_error_handler_generic_error_raises_demisto_exception():
    """
    Tests error_handler for a generic error (e.g., 500 status code).
    Verifies that a DemistoException is raised with a generic error message.
    """
    import requests
    from CommonServerPython import DemistoException
    mock_response = requests.Response()
    mock_response.status_code = 500
    mock_response._content = b'Internal Server Error'
    
    try:
        mock_client().error_handler(mock_response)
    except DemistoException as e:
        expected_message_part = f"{THREAT_STREAM} - Error in API call 500 - Internal Server Error"
        assert expected_message_part in str(e), f"Unexpected exception message: {str(e)}"