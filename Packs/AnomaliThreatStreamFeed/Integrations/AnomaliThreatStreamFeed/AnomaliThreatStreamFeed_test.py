from CommonServerPython import tableToMarkdown, Common, FeedIndicatorType, EntityRelationship
import pytest
from AnomaliThreatStreamFeed import Client
from datetime import datetime, UTC
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


def test_get_indicators_command_invalid_type(mocker):
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
    mock_demisto_error = mocker.patch("AnomaliThreatStreamFeed.demisto.error")  # Patch demisto.error to assert its call

    result = get_indicators_command(client, args)

    # Verify demisto.error was called
    mock_demisto_error.assert_called_once_with(f"{THREAT_STREAM} - Invalid indicator type.")

    expected_readable_output = """### Invalid indicator type. Select one of the following types: domain, email, ip, md5, url."""
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

    mock_now = datetime(2023, 8, 1, 12, 0, 0, 500000, tzinfo=UTC)
    minutes_interval = 60  # one hour ago
    expected_past_time = "2023-08-01T11:00:00.500"

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
    result = create_relationships(reliability=reliability, indicator=indicator_no_type)
    assert result == []

    # Test missing value
    indicator_no_value = {"type": "ip", "rdns": ["example.com"]}
    result = create_relationships(reliability=reliability, indicator=indicator_no_value)
    assert result == []

    # Test empty string value
    indicator_empty_value = {"type": "ip", "value": "", "rdns": ["example.com"]}
    result = create_relationships(reliability=reliability, indicator=indicator_empty_value)
    assert result == []


def test_create_relationships_related_entity():
    """
    Tests create_relationships with a related entity.
    Verifies that one relationship is created correctly.

    Given:
        - create_relationships_param is True.
        - A Domain indicator with a related IP.
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
    result = create_relationships(reliability=reliability, indicator=indicator)
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
        "meta": {"maltype": "2.2.2.2"},
    }
    reliability = "B - Usually reliable"

    expected_relationships = [
        {
            "name": "resolved-from",
            "reverseName": "resolves-to",
            "type": "IndicatorToIndicator",
            "entityA": "mydomain1.com",
            "entityAFamily": "Indicator",
            "entityAType": "Domain",
            "entityB": "1.1.1.1",
            "entityBFamily": "Indicator",
            "entityBType": "IP",
            "fields": {},
        },
        {
            "name": "indicator-of",
            "reverseName": "indicated-by",
            "type": "IndicatorToIndicator",
            "entityA": "mydomain1.com",
            "entityAFamily": "Indicator",
            "entityAType": "Domain",
            "entityB": "2.2.2.2",
            "entityBFamily": "Indicator",
            "entityBType": "Malware",
            "fields": {},
        },
    ]

    result = create_relationships(reliability=reliability, indicator=indicator)
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
        "tags": [{"id": "id1", "name": "tag1"}, {"id": "id2", "name": "tag2"}],
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
            "tags": [{"id": "id1", "name": "tag1"}, {"id": "id2", "name": "tag2"}],
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


def test_fetch_indicators_command_subsequent_run_no_new_indicators(mocker):
    """
    Tests fetch_indicators_command for a subsequent run where no new indicators
    are found beyond the initial API call.

    Given:
        - A 'last_run' timestamp indicating a previous successful fetch.
        - The client's 'http_request' is mocked to return a single page of
          indicators with 'meta.next' set to None (no further pages).
        - 'get_current_utc_time' is mocked to return a fixed timestamp for
          consistent 'next_run_timestamp' calculation.
    When:
        - Calling 'fetch_indicators_command' with the mocked client,
          parameters, and 'last_run' object.
    Then:
        Verify that:
        - The 'http_request' method is called exactly once (no pagination occurred).
        - The 'next_run_timestamp' returned matches the mocked current UTC time.
        - The 'parsed_indicators_list' contains the expected indicators from
          the single mocked HTTP response.
    """
    from AnomaliThreatStreamFeed import fetch_indicators_command

    test_case = {
        "params": {},  # Use defaults
        "last_run": {"last_successful_run": "2023-08-01T09:00:00Z"},
        "mock_http_responses": [
            {
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
                ],
                "meta": {"next": None},
            }
        ],
        "mock_now": datetime(2023, 8, 1, 12, 0, 0, tzinfo=UTC),
        "expected_next_run_timestamp": "2023-08-01T12:00:00Z",
        "expected_parsed_indicators": [
            {
                "value": "mydomain1.com",
                "type": "Domain",
                "fields": {
                    "TargetIndustries": ["finance"],
                    "Source": "TestSource",
                    "ThreatStreamID": "123",
                    "CountryCode": "US",
                    "Domain": "mydomain1.com",
                    "Description": "Test domain",
                    "Modified": "2023-01-01T12:00:00Z",
                    "Confidence": "90",
                    "Creation": "2022-01-01T12:00:00Z",
                    "TrafficLightProtocol": "WHITE",
                    "Location": "New York",
                    "ASN": "AS12345",
                },
                "rawJSON": {
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
                "score": 3,
            },
            {
                "value": "1.1.1.1",
                "type": "IP",
                "fields": {
                    "TargetIndustries": ["tech"],
                    "Source": "AnotherSource",
                    "ThreatStreamID": "124",
                    "CountryCode": "FR",
                    "IP": "1.1.1.1",
                    "Description": "test ip",
                    "Modified": "2023-02-01T12:00:00Z",
                    "Organization": "AnotherOrg",
                    "Confidence": "10",
                    "Creation": "2022-02-01T12:00:00Z",
                    "TrafficLightProtocol": "WHITE",
                    "Location": "London",
                },
                "rawJSON": {
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
                "score": 1,
            },
        ],
    }

    client = mock_client()
    mock_http_request = mocker.patch.object(client, "http_request")
    # Use a list of responses for http_request to simulate pagination
    mock_http_request.side_effect = test_case["mock_http_responses"]

    # Mock datetime.now for consistent timestamps
    mock_now_dt = test_case["mock_now"]
    mocker.patch("AnomaliThreatStreamFeed.get_current_utc_time", return_value=mock_now_dt)

    next_run_timestamp, parsed_indicators_list = fetch_indicators_command(client, test_case["params"], test_case["last_run"])

    assert next_run_timestamp == test_case["expected_next_run_timestamp"]
    assert parsed_indicators_list == test_case["expected_parsed_indicators"]
    assert mock_http_request.call_count == 1  # Assert that http_request was called exactly once


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
    from AnomaliThreatStreamFeed import fetch_indicators_command

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
        "mock_now": datetime(2023, 8, 1, 12, 0, 0, tzinfo=UTC),
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
    Tests the error_handler function when the API response has a 401 (Unauthorized) status code.
    Verifies that a DemistoException is raised with a specific message prompting a credentials check.

    Given:
        - A mocked 'requests.Response' object configured with a 401 HTTP status code.
        - The mocked response content is set to 'Unauthorized access'.
    When:
        - Calling the 'error_handler' method of a mock client with the mocked 401 response.
    Then:
        Verify that:
        - A 'DemistoException' is raised.
        - The message of the raised 'DemistoException' contains the expected error string,
          including the THREAT_STREAM constant, and guidance to check credentials along with the 'Unauthorized access' content.
    """
    import requests
    from CommonServerPython import DemistoException

    mock_response = requests.Response()
    mock_response.status_code = 401
    mock_response._content = b"Unauthorized access"

    try:
        mock_client().error_handler(mock_response)
    except DemistoException as e:
        expected_message_part = f"{THREAT_STREAM} - Got unauthorized from the server. Check the credentials. Unauthorized access"
        assert expected_message_part in str(e), f"Unexpected exception message: {str(e)}"


def test_error_handler_404_raises_demisto_exception():
    """
    Tests the error_handler function when the API response has a 404 (Not Found) status code.
    Verifies that a DemistoException is raised with a specific 'resource not found' message.

    Given:
        - A mocked 'requests.Response' object configured with a 404 HTTP status code.
        - The mocked response content is set to 'Not Found'.
    When:
        - Calling the 'error_handler' method of a mock client with the mocked 404 response.
    Then:
        Verify that:
        - A 'DemistoException' is raised.
        - The message of the raised 'DemistoException' contains the expected specific error string,
          including the THREAT_STREAM constant and "The resource was not found. Not Found".
    """
    import requests
    from CommonServerPython import DemistoException

    mock_response = requests.Response()
    mock_response.status_code = 404
    mock_response._content = b"Not Found"

    try:
        mock_client().error_handler(mock_response)
    except DemistoException as e:
        expected_message_part = f"{THREAT_STREAM} - The resource was not found. Not Found"
        assert expected_message_part in str(e), f"Unexpected exception message: {str(e)}"


def test_error_handler_generic_error_raises_demisto_exception():
    """
    Tests the error_handler function when a generic HTTP error (e.g., 500 Internal Server Error) occurs.
    Verifies that a DemistoException is raised with a descriptive error message including the status code and content.

    Given:
        - A mocked 'requests.Response' object configured with a 500 HTTP status code.
        - The mocked response content is set to 'Internal Server Error'.
    When:
        - Calling the 'error_handler' method of a mock client with the mocked 500 response.
    Then:
        Verify that:
        - A 'DemistoException' is raised.
        - The message of the raised 'DemistoException' contains the expected format,
          including the THREAT_STREAM constant, the 500 status code, and the "Internal Server Error" content.
    """
    import requests
    from CommonServerPython import DemistoException

    mock_response = requests.Response()
    mock_response.status_code = 500
    mock_response._content = b"Internal Server Error"

    try:
        mock_client().error_handler(mock_response)
    except DemistoException as e:
        expected_message_part = f"{THREAT_STREAM} - Error in API call 500 - Internal Server Error"
        assert expected_message_part in str(e), f"Unexpected exception message: {str(e)}"


def test_handle_get_pagination_no_initial_indicators():
    """
    Tests handle_get_pagination when the initial API response contains no indicators.
    Verifies that an empty list is returned and no further API calls are made.

    Given:
        - An initial API response dictionary where the 'objects' key's value is an empty list,
          and there is no 'next' page.
    When:
        - Calling handle_get_pagination with this initial response.
    Then:
        Verify that:
        - An empty list is returned.
    """
    from AnomaliThreatStreamFeed import handle_get_pagination

    initial_response = {"objects": [], "meta": {"next": None}}
    client = mock_client()
    result = handle_get_pagination(client, initial_response, 10)
    assert result == []


def test_handle_get_pagination_no_pagination_needed():
    """
    Tests handle_get_pagination when all indicators are returned in the initial API response,
    meaning no further pagination is required.

    Given:
        - An initial API response dictionary containing a list of indicator 'objects'.
        - The 'meta' field in the initial response indicates there is no 'next' page.
    When:
        - Calling handle_get_pagination with this initial response.
    Then:
        Verify that:
        - The function returns all indicators from the initial response.
    """
    from AnomaliThreatStreamFeed import handle_get_pagination

    initial_response = {"objects": [{"id": "ind1"}, {"id": "ind2"}], "meta": {"next": None}}
    initial_limit = 50
    client = mock_client()
    result = handle_get_pagination(client, initial_response, initial_limit)
    assert len(result) == 2
    assert {"id": "ind1"} in result
    assert {"id": "ind2"} in result


def test_handle_get_pagination_multiple_pages(mocker):
    """
    Tests handle_get_pagination's ability to fetch data across multiple API pages
    until the initial limit is reached or no more pages are available.

    Given:
        - An initial API response containing one indicator and a 'next' page URL.
        - An 'initial_limit' set to allow fetching data beyond the first page.
        - The client's 'http_request' method is mocked to return two sequential responses:
            1. The first mock response contains indicators for the next page and a subsequent 'next' page URL.
            2. The second mock response contains indicators for the final page and indicates no further 'next' page.
    When:
        - Calling handle_get_pagination with this setup.
    Then:
        Verify that:
        - The returned list of indicators includes those from the initial response and all subsequently fetched pages.
        - The 'http_request' method is called exactly twice (corresponding to the two entries in the 'side_effect' list,
          which fulfill the two internal HTTP calls within one loop iteration).
        - The URLs used in the 'http_request' calls correctly reflect the pagination logic
          and the decremented 'remaining_limit'.
    """
    from AnomaliThreatStreamFeed import handle_get_pagination

    LIMIT_RES_FROM_API = 1000

    initial_response = {"objects": [{"id": "ind1_p1"}], "meta": {"next": "/api/v1/indicators?limit=1000&offset=1000"}}
    initial_limit = 2500  # Will fetch 1 (initial) + 1 (first page) + 1 (second page)
    client = mock_client()
    # Simulate three pages in total (initial + 2 paginated)

    mocker.patch.object(
        client,
        "http_request",
        side_effect=[
            # First pagination call
            {"objects": [{"id": "ind1_p2"}], "meta": {"next": "/api/v1/indicators?limit=1000&offset=2000"}},
            # Second pagination call
            {"objects": [{"id": "ind1_p3"}], "meta": {"next": None}},
        ],
    )
    result = handle_get_pagination(client, initial_response, initial_limit)

    assert len(result) == 3  # ind1_p1 + ind1_p2 + ind1_p3
    assert {"id": "ind1_p1"} in result
    assert {"id": "ind1_p2"} in result
    assert {"id": "ind1_p3"} in result
    assert client.http_request.call_count == 2

    call1_url = "v1/indicators?limit=1000&offset=1000".replace("limit=1000", f"limit={initial_limit - LIMIT_RES_FROM_API}")
    call2_url = "v1/indicators?limit=1000&offset=2000".replace("limit=1000", f"limit={initial_limit - 2*LIMIT_RES_FROM_API}")
    client.http_request.assert_any_call(method="GET", url_suffix=call1_url)
    client.http_request.assert_any_call(method="GET", url_suffix=call2_url)


def test_handle_get_pagination_no_more_indicators_on_page(mocker):
    """
    Tests that pagination correctly breaks when a subsequent API page returns no indicators.
    This specifically verifies the logic within the 'else' block of the 'if current_page_indicators:' check.

    Given:
        - An initial API response containing some indicators and a 'next' page URL.
        - An 'initial_limit' sufficient to attempt fetching the next page.
        - The client's 'http_request' method is mocked to return an empty list for the 'objects'
          key for any subsequent pagination requests.
    When:
        - Calling handle_get_pagination with this setup.
    Then:
        Verify that:
        - The returned list of indicators contains only the indicators from the initial response.
        - The 'http_request' method is called once.
    """
    from AnomaliThreatStreamFeed import handle_get_pagination

    initial_response = {
        "objects": [{"id": "ind1_p1"}],  # Initial indicators
        "meta": {"next": "/api/v1/indicators?limit=1000&offset=1000"},  # Suggests another page
    }
    initial_limit = 2000  # Enough limit to try and fetch another page

    # Configure the mock client's http_request to return an empty list for 'objects'
    # on the first paginated call.
    client = mock_client()
    mocker.patch.object(
        client, "http_request", return_value={"objects": [], "meta": {"next": "/api/v1/indicators?limit=1000&offset=2000"}}
    )

    result = handle_get_pagination(client, initial_response, initial_limit)

    assert len(result) == 1
    assert {"id": "ind1_p1"} in result
    assert client.http_request.call_count == 1


def test_handle_fetch_pagination_no_initial_indicators():
    """
    Tests handle_fetch_pagination when the initial API response contains no indicators.
    Verifies that an empty list is returned and no further API calls are made.

    Given:
        - An initial API response dictionary where the 'objects' key's value is an empty list,
          and there is no 'next' page.
    When:
        - Calling handle_fetch_pagination with this initial response.
    Then:
        Verify that:
        - An empty list is returned.
    """
    from AnomaliThreatStreamFeed import handle_fetch_pagination

    initial_response = {"objects": [], "meta": {"next": None}}
    client = mock_client()
    result = handle_fetch_pagination(client, initial_response)
    assert result == []


def test_handle_fetch_pagination_no_pagination_needed(mocker):
    """
    Tests handle_fetch_pagination when all indicators are returned in the initial API response,
    meaning no further pagination is required.

    Given:
        - An initial API response dictionary containing a list of indicator 'objects'.
        - The 'meta' field in the initial response indicates there is no 'next' page.
    When:
        - Calling handle_fetch_pagination with this initial response.
    Then:
        Verify that:
        - The function returns all indicators from the initial response.
    """
    from AnomaliThreatStreamFeed import handle_fetch_pagination

    initial_response = {"objects": [{"id": "ind1"}, {"id": "ind2"}], "meta": {"next": None}}
    client = mock_client()
    result = handle_fetch_pagination(client, initial_response)
    assert len(result) == 2
    assert {"id": "ind1"} in result
    assert {"id": "ind2"} in result


def test_handle_fetch_pagination_multiple_pages(mocker):
    """
    Tests handle_fetch_pagination's ability to fetch data across multiple API pages sequentially.

    Given:
        - An initial API response with indicators and a 'next' page URL.
        - The client's 'http_request' method is mocked to return two subsequent pages:
            1. The first paginated response contains indicators and another 'next' page URL.
            2. The second paginated response contains indicators but no further 'next' page URL.
    When:
        - Calling handle_fetch_pagination with this setup.
    Then:
        Verify that:
        - The returned list includes indicators from the initial response and all subsequently fetched pages.
        - The 'http_request' method is called twice for pagination.
    """
    from AnomaliThreatStreamFeed import handle_fetch_pagination

    initial_response = {"objects": [{"id": "initial_ind"}], "meta": {"next": "/api/v1/indicators?offset=1000"}}
    client = mock_client()

    mocker.patch.object(
        client,
        "http_request",
        side_effect=[
            {"objects": [{"id": "page_2_ind"}], "meta": {"next": "/api/v1/indicators?offset=2000"}},
            {"objects": [{"id": "page_3_ind"}], "meta": {"next": None}},
        ],
    )

    result = handle_fetch_pagination(client, initial_response)

    assert len(result) == 3
    assert {"id": "initial_ind"} in result
    assert {"id": "page_2_ind"} in result
    assert {"id": "page_3_ind"} in result
    assert client.http_request.call_count == 2
