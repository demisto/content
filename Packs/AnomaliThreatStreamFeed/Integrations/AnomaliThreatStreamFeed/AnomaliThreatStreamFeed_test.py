from CommonServerPython import CommandResults
import AnomaliThreatStreamFeed
import pytest
from AnomaliThreatStreamFeed import Client

THREAT_STREAM = "Anomali ThreatStream Feed"

def mock_client():
    return Client(
        base_url="https://svlpartner-optic-api.threatstream.com",
        user_name="user",
        api_key="key",
        verify=False
    )

def test_get_indicators_command_success_with_type(mocker):
    from AnomaliThreatStreamFeed import get_indicators_command

    """
    Tests the successful execution of the get_indicators_command function
    when a specific indicator type is provided.

    Given:
        - A mock client instance for the Anomali ThreatStream API.
        - Arguments including 'indicator_type' and 'limit'.
    When:
        - Running the get_indicators_command function with the mock client and arguments.
    Then:
        1. Mocks the HTTP request to the ThreatStream API to return predefined indicator data.
        2. Mocks internal demisto debug/info logging to prevent console output.
        3. Mocks the `tableToMarkdown` function to control its output.
        4. Mocks the `parse_indicators_for_get_command` function to ensure consistent parsing behavior.
        5. Confirms that the `http_request` method was called with the correct parameters, including the indicator type.
        6. Asserts that a `CommandResults` object is returned with the expected human-readable output
           and raw response data.
        7. Verifies that debug messages indicate the API call and the number of indicators found.
        8. Ensures `tableToMarkdown` was called with the correctly formatted data and dynamic headers.
    """
    client = mock_client()
    mock_api_response = {
        "objects": [
            {
                "threatstream_id": "123",
                "indicator": "test.com",
                "type": "domain",
                "confidence": 90,
                "description": "Test domain",
                "source": "TestSource",
                "tags": ["malware", "phishing"],
                "traffic_light_protocol": "RED",
                "modified": "2023-01-01T12:00:00Z",
                "organization": "TestOrg",
                "creation": "2022-01-01T12:00:00Z",
                "expiration": "2024-01-01T12:00:00Z",
                "target_industries": ["finance"],
                "asn": "AS12345",
                "location": "New York",
            },
            {
                "threatstream_id": "124",
                "indicator": "another.com",
                "type": "domain",
                "confidence": 80,
                "description": "Another test domain",
                "source": "AnotherSource",
                "tags": ["c2"],
                "traffic_light_protocol": "AMBER",
                "modified": "2023-02-01T12:00:00Z",
                "organization": "AnotherOrg",
                "creation": "2022-02-01T12:00:00Z",
                "expiration": "2024-02-01T12:00:00Z",
                "target_industries": ["tech"],
                "asn": "AS67890",
                "location": "London",
            },
        ]
    }
    mocker.patch.object(client, "http_request", return_value=mock_api_response)
    # client.http_request.return_value = mock_api_response

    # Mock parse_indicators_for_get_command to return a controlled parsed output
    mock_parsed_indicators = [
        {"domain": "test.com", "Confidence": 90},
        {"domain": "another.com", "Confidence": 80},
    ]
    mocker.patch("parse_indicators_for_get_command", return_value=mock_parsed_indicators)

    args = {"indicator_type": "domain", "limit": 2}
    result = get_indicators_command(client, args)

    # Assertions
    client.http_request.assert_called_once_with(method="GET", url_suffix="v2/intelligence", params={"limit": 2, "type": "domain"})

    assert result.readable_output == "Mocked Markdown Table"
    assert result.raw_response == mock_api_response["objects"]

    # Verify tableToMarkdown call arguments
    expected_headers_with_type = [
        "TargetIndustries",
        "Source",
        "ThreatStreamID",
        "Country Code",
        "domain",  # Dynamic header
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