from Packs.CommonScripts.Scripts.SearchIndicatorAgentix.SearchIndicatorAgentix import prepare_query, search_indicators
import demistomock as demisto


def test_prepare_list_query():
    """
    Given: Arguments with multiple values for each field including value, expirationStatus, verdict, and type
    When: prepare_query is called with these arguments
    Then: Returns a properly formatted query string with OR conditions for multiple values and AND conditions between fields
    """
    args = {
        "value": ["example.com", "example.org"],  # List of values to search
        "expirationStatus": ["active"],  # Possible expiration statuses
        "verdict": ["Benign", "Malicious"],  # Possible verdicts
        "type": ["Domain", "IP", "URL"],  # Indicator
    }
    res = """(value:"example.com" OR value:"example.org") AND (expirationStatus:"active") AND\
 (verdict:"Benign" OR verdict:"Malicious") AND (type:"Domain" OR type:"IP" OR type:"URL")"""
    generated_query = prepare_query(args)
    assert res == generated_query


def test_prepare_query_with_empty_values():
    """
    Given: Arguments with mixed empty lists and populated lists, including custom fields
    When: prepare_query is called with these arguments
    Then: Returns a query string that excludes empty fields and includes only populated fields
    """
    args = {
        "value": ["example.com"],  # Single value
        "expirationStatus": [],  # Empty list
        "verdict": ["Benign"],  # Single verdict
        "type": [],  # Empty list
        "score": ["5", "10"],  # Additional field with multiple values
    }
    res = '(value:"example.com") AND (verdict:"Benign") AND (score:"5" OR score:"10")'
    generated_query = prepare_query(args)
    assert res == generated_query


def test_prepare_query_edge_cases():
    """
    Given: Arguments with special characters, spaces, email formats, empty strings, and mixed data types
    When: prepare_query is called with these edge case arguments
    Then: Returns a properly formatted query string that handles special characters and excludes empty values
    """
    args = {
        "value": ["test with spaces", "test@email.com", "192.168.1.1"],  # Special characters and formats
        "expirationStatus": ["expired"],  # Single status
        "verdict": [],  # Empty verdict list
        "type": ["Email", "IP"],  # Mixed types
        "anotherField": ["value1"],  # Single custom field
    }
    res = """(value:"test with spaces" OR value:"test@email.com" OR value:"192.168.1.1") AND \
(expirationStatus:"expired") AND (type:"Email" OR type:"IP") AND (anotherField:"value1")"""
    generated_query = prepare_query(args)
    assert res == generated_query


def test_search_indicators_basic_functionality(mocker):
    """
    Given: Basic arguments with value, type, and size for searching indicators
    When: search_indicators is called with these arguments
    Then: Returns markdown output and filtered indicators with proper verdict mapping
    """
    args = {"value": "example.com", "type": "Domain", "size": 50}

    mock_indicators = [
        {
            "id": "1",
            "indicator_type": "Domain",
            "value": "example.com",
            "score": 2,
            "expirationStatus": "active",
            "investigationIDs": ["inv1"],
            "expiration": "2024-12-31",
            "lastSeen": "2024-01-01",
        }
    ]

    mocker.patch.object(demisto, "executeCommand", return_value=[{"Contents": mock_indicators}])
    markdown, filtered_indicators = search_indicators(args)

    assert "Indicators Found" in markdown
    assert len(filtered_indicators) == 1
    assert filtered_indicators[0]["id"] == "1"
    assert filtered_indicators[0]["verdict"] == "Suspicious"
