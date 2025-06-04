from CommonServerPython import tableToMarkdown
import AnomaliThreatStreamFeed
import pytest
from AnomaliThreatStreamFeed import Client

THREAT_STREAM = "Anomali ThreatStream Feed"

def mock_client():
    return Client(
        base_url="https://svlpartner-optic-api.threatstream.com",
        user_name="user",
        api_key="key",
        verify=True
    )

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
        "TargetIndustries", "Source", "ThreatStreamID", "Country Code", "domain",
        "Description", "Modified", "Organization", "Confidence",
        "Creation", "Expiration", "Tags", "TrafficLightProtocol", "Location", "ASN"
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
                "tags": [{
                    "id": "125a",
                    "name": "tag125a"
                },
                {
                    "id": "125b",
                    "name": "tag125b"
                }],
                "tlp": "RED",
                "country": "",
                "modified_ts": "2023-02-01T12:00:00Z",
                "org": "NewOrg",
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
                "Tags": [{
                    "id": "125a",
                    "name": "tag125a"
                },
                {
                    "id": "125b",
                    "name": "tag125b"
                }],
                "TrafficLightProtocol": "RED",
                "CountryCode": "",
                "Modified": "2023-02-01T12:00:00Z",
                "Organization": "NewOrg",
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
        "TargetIndustries", "Source", "ThreatStreamID", "Country Code",
        "Description", "Modified", "Organization", "Confidence",
        "Creation", "Expiration", "Tags", "TrafficLightProtocol", "Location", "ASN"
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

    mocker.patch.object(client, 'http_request', return_value={"objects": []})

    result = get_indicators_command(client, args)

    client.http_request.assert_called_once_with(
        method="GET",
        url_suffix="v2/intelligence",
        params={"limit": 10, "type": "url"}
    )
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
            "tags": [{
                    "id": "125a",
                    "name": "tag125a"
                },
                {
                    "id": "125b",
                    "name": "tag125b"
                }],
            "tlp": "RED",
            "org": "newOrg",
            "country": "US",
            "modified_ts": "2023-01-01T12:00:00Z",
            "org": "newOrg",
            "created_ts": "2022-01-01T12:00:00Z",
            "expiration_ts": "2024-01-01T12:00:00Z",
            "target_industry": ['target_industry'],
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
        "Tags": [{
                    "id": "125a",
                    "name": "tag125a"
                },
                {
                    "id": "125b",
                    "name": "tag125b"
                }],
        "TrafficLightProtocol": "RED",
        "Location": "New York",
        "ASN": "AS12345",
        "TargetIndustries": ['target_industry'],
        "Organization": "newOrg"
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
        {
            "Source": "AnotherSource",
            "ThreatStreamID": "456",
            "ip": "2.2.2.2",
            "Description": "Simple IP",
            "Confidence": "None"
        },
    ]

    result = parse_indicators_for_get_command(mock_raw_indicators)
    print(result)
    assert result == expected_parsed_indicators