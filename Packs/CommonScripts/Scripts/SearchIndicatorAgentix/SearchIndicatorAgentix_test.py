import demistomock as demisto
from Packs.CommonScripts.Scripts.SearchIndicatorAgentix.SearchIndicatorAgentix import search_indicators, prepare_query


def test_main(mocker):
    """
    Given: A mocked demisto environment with executeCommand returning indicator data
    When: search_indicators is called with add_fields_to_context parameter
    Then: Returns formatted markdown table and context data with specified fields
    """
    mocker.patch.object(demisto, "results", return_value={})
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Contents": [{"CustomFields": {"field": "score"}}]}])
    assert search_indicators({"add_fields_to_context": "a,b,c"}) == (
        "### Indicators Found\n|id|indicator_type|value|score|a|b|c|verdict|\n|---|---|---|---|---|---|---|---|\n| n/a | n/a | n/a | n/a | n/a | n/a | n/a | None |\n",  # noqa
        [
            {
                "id": "n/a",
                "indicator_type": "n/a",
                "value": "n/a",
                "score": "n/a",
                "a": "n/a",
                "b": "n/a",
                "c": "n/a",  # noqa
                "verdict": "None",
            }
        ],
    )


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
    res = ("(value:example.com OR value:example.org) AND (expirationStatus:active) AND "
            "(verdict:Benign OR verdict:Malicious) AND (type:Domain OR type:IP OR type:URL)")
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
        "score": ["5", "10"]  # Additional field with multiple values
    }
    res = "(value:example.com) AND (verdict:Benign) AND (score:5 OR score:10)"
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
        "customField": [""],  # Empty string in list
        "anotherField": ["value1"]  # Single custom field
    }
    res = ("(value:test with spaces OR value:test@email.com OR value:192.168.1.1) AND "
           "(expirationStatus:expired) AND (type:Email OR type:IP) AND (anotherField:value1)")
    generated_query = prepare_query(args)
    assert res == generated_query
