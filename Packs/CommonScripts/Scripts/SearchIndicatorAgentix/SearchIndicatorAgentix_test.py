from SearchIndicatorAgentix import (
    escape_special_characters,
    build_query_for_indicator_values,
    prepare_query,
    KEYS_TO_EXCLUDE_FROM_QUERY,
    build_query_excluding_indicator_values,
    search_indicators,
)
import json
import pytest


def test_escape_special_characters_backslash():
    """
    Given: A value containing backslash characters
    When: escape_special_characters is called
    Then: Returns value with backslashes properly escaped
    """
    value = "test\\path\\file"
    expected = "test\\\\path\\\\file"
    result = escape_special_characters(value)
    assert result == expected


def test_escape_special_characters_quotes():
    """
    Given: A value containing double quotes
    When: escape_special_characters is called
    Then: Returns value with quotes properly escaped
    """
    value = 'This is a "quoted" string'
    expected = 'This\\ is\\ a\\ \\"quoted\\"\\ string'
    result = escape_special_characters(value)
    assert result == expected


def test_escape_special_characters_newlines_and_tabs():
    """
    Given: A value containing newlines, tabs, and carriage returns
    When: escape_special_characters is called
    Then: Returns value with whitespace characters properly escaped
    """
    value = "line1\nline2\tcolumn\rreturn"
    expected = "line1\\nline2\\tcolumn\\rreturn"
    result = escape_special_characters(value)
    assert result == expected


def test_escape_special_characters_colon_and_caret():
    """
    Given: A value containing colons and caret characters
    When: escape_special_characters is called
    Then: Returns value with special query characters properly escaped
    """
    value = "field:value^boost"
    expected = "field\\:value\\^boost"
    result = escape_special_characters(value)
    assert result == expected


def test_escape_special_characters_spaces():
    """
    Given: A value containing spaces
    When: escape_special_characters is called
    Then: Returns value with spaces properly escaped
    """
    value = "hello world test"
    expected = "hello\\ world\\ test"
    result = escape_special_characters(value)
    assert result == expected


def test_escape_special_characters_mixed_special_chars():
    """
    Given: A value containing multiple different special characters
    When: escape_special_characters is called
    Then: Returns value with all special characters properly escaped
    """
    value = 'path\\file:"value" test\nline^boost'
    expected = 'path\\\\file\\:\\"value\\"\\ test\\nline\\^boost'
    result = escape_special_characters(value)
    assert result == expected


def test_escape_special_characters_empty_string():
    """
    Given: An empty string
    When: escape_special_characters is called
    Then: Returns empty string unchanged
    """
    value = ""
    expected = ""
    result = escape_special_characters(value)
    assert result == expected


def test_escape_special_characters_no_special_chars():
    """
    Given: A value containing no special characters
    When: escape_special_characters is called
    Then: Returns the original value unchanged
    """
    value = "normaltext123"
    expected = "normaltext123"
    result = escape_special_characters(value)
    assert result == expected


def test_escape_special_characters_only_special_chars():
    """
    Given: A value containing only special characters
    When: escape_special_characters is called
    Then: Returns all characters properly escaped
    """
    value = '\\ \n\t\r"^:'
    expected = '\\\\\\ \\n\\t\\r\\"\\^\\:'
    result = escape_special_characters(value)
    assert result == expected


def test_escape_special_characters_repeated_chars():
    """
    Given: A value with repeated special characters
    When: escape_special_characters is called
    Then: Returns value with each occurrence properly escaped
    """
    value = "test::value^^boost  space"
    expected = "test\\:\\:value\\^\\^boost\\ \\ space"
    result = escape_special_characters(value)
    assert result == expected


@pytest.mark.parametrize(
    "n,expected_chunks",
    [
        (0, 0),  # empty -> []
        (50, 1),  # <100 -> one chunk
        (100, 1),  # exactly 100 -> one chunk
        (110, 2),  # 100 + 10 -> two chunks
        (250, 3),  # 100 + 100 + 50 -> three chunks
    ],
)
def test_build_query_for_indicator_values_chunk_counts(n, expected_chunks):
    # build n indicator values
    values = [f"v{i}" for i in range(n)]
    args = {"value": json.dumps(values)}

    result = build_query_for_indicator_values(args)

    # Check number of chunk queries returned
    assert isinstance(result, list)
    assert len(result) == expected_chunks

    # Optionally, verify each chunk's size by counting " OR " occurrences (+1 = items in chunk)
    # because our stub joins values with " OR " and build_query wraps with parentheses.
    remaining = n
    for chunk_str in result:
        # strip outer parentheses added in build_query_for_indicator_values
        inner = chunk_str[1:-1]
        items_in_chunk = 0 if inner == "" else inner.count(" OR ") + 1
        expected_size = min(100, remaining)
        assert items_in_chunk == expected_size
        remaining -= expected_size

    assert remaining == 0


def test_build_query_for_values_empty_args():
    """
    Given: Empty arguments dictionary
    When: build_query_for_values is called
    Then: Returns empty list
    """
    args = {}
    result = build_query_for_indicator_values(args)
    assert result == []


def test_build_query_for_values_no_value_key():
    """
    Given: Arguments without 'value' key
    When: build_query_for_values is called
    Then: Returns empty list
    """
    args = {"type": "Domain", "verdict": "Malicious"}
    result = build_query_for_indicator_values(args)
    assert result == []


def test_build_query_for_values_empty_value_list():
    """
    Given: Arguments with empty value list
    When: build_query_for_values is called
    Then: Returns empty list
    """
    args = {"value": []}
    result = build_query_for_indicator_values(args)
    assert result == []


def test_build_query_for_values_single_value():
    """
    Given: Arguments with single value in JSON string format
    When: build_query_for_values is called
    Then: Returns list with one properly formatted query
    """

    args = {"value": json.dumps(["example"])}
    result = build_query_for_indicator_values(args)
    assert len(result) == 1
    assert 'value:"example"' in result[0]


def test_build_query_for_values_multiple_values_under_100():
    """
    Given: Arguments with multiple values under 100 limit
    When: build_query_for_values is called
    Then: Returns list with one query containing OR operators
    """

    values = ["example", "test", "sample"]
    args = {"value": json.dumps(values)}
    result = build_query_for_indicator_values(args)
    assert len(result) == 1
    for value in values:
        assert f'value:"{value}"' in result[0]
    assert " OR " in result[0]


def test_build_query_for_values_exactly_100_values():
    """
    Given: Arguments with exactly 100 values
    When: build_query_for_values is called
    Then: Returns list with one query containing all values
    """

    values = [f"example{i}" for i in range(100)]
    args = {"value": json.dumps(values)}
    result = build_query_for_indicator_values(args)
    assert len(result) == 1
    assert "example0" in result[0]
    assert "example99" in result[0]


def test_build_query_for_values_over_100_values():
    """
    Given: Arguments with over 100 values
    When: build_query_for_values is called
    Then: Returns multiple queries with chunked values
    """

    values = [f"example{i}" for i in range(150)]
    args = {"value": json.dumps(values)}
    result = build_query_for_indicator_values(args)
    assert len(result) == 2
    assert "example0" in result[0]
    assert "example99" in result[0]
    assert "example100" in result[1]
    assert "example149" in result[1]


def test_build_query_for_values_exactly_101_values():
    """
    Given: Arguments with exactly 101 values
    When: build_query_for_values is called
    Then: Returns two queries with 100 and 1 values respectively
    """

    values = [f"test{i}" for i in range(101)]
    args = {"value": json.dumps(values)}
    result = build_query_for_indicator_values(args)
    assert len(result) == 2
    assert "test0" in result[0]
    assert "test99" in result[0]
    assert "test100" in result[1]
    assert " OR " not in result[1]


def test_build_query_for_values_with_special_characters():
    """
    Given: Arguments with values containing special characters
    When: build_query_for_values is called
    Then: Returns queries with properly escaped special characters
    """

    values = ["test with spaces", 'test"quotes', "test\\backslash"]
    args = {"value": json.dumps(values)}
    result = build_query_for_indicator_values(args)
    assert len(result) == 1
    assert "test\\ with\\ spaces" in result[0]
    assert 'test\\"quotes' in result[0]
    assert "test\\\\backslash" in result[0]


def test_build_query_for_values_with_whitespace():
    """
    Given: Arguments with values containing leading/trailing whitespace
    When: build_query_for_values is called
    Then: Returns queries with whitespace stripped from values
    """

    values = ["  example  ", "\ttest\n", " sample "]
    args = {"value": json.dumps(values)}
    result = build_query_for_indicator_values(args)
    assert len(result) == 1
    assert 'value:"example"' in result[0]
    assert 'value:"test"' in result[0]
    assert 'value:"sample"' in result[0]


def test_build_query_for_values_mixed_data_types():
    """
    Given: Arguments with values of mixed data types (strings, numbers)
    When: build_query_for_values is called
    Then: Returns queries with all values converted to strings
    """

    values = ["example", 192168001001, True, None]
    args = {"value": json.dumps(values)}
    result = build_query_for_indicator_values(args)
    assert len(result) == 1
    assert 'value:"example"' in result[0]
    assert 'value:"192168001001"' in result[0]
    assert 'value:"True"' in result[0]
    assert 'value:"None"' in result[0]


def test_build_query_for_values_large_chunk_boundary():
    """
    Given: Arguments with 250 values (tests multiple chunks)
    When: build_query_for_values is called
    Then: Returns three queries with proper chunk distribution
    """
    values = [f"domain{i}.example" for i in range(250)]
    args = {"value": json.dumps(values)}
    result = build_query_for_indicator_values(args)
    assert len(result) == 3
    assert "domain0.example" in result[0]
    assert "domain99.example" in result[0]
    assert "domain100.example" in result[1]
    assert "domain199.example" in result[1]
    assert "domain200.example" in result[2]
    assert "domain249.example" in result[2]


def test_prepare_query_empty_args():
    """
    Given: Empty arguments dictionary
    When: prepare_query is called
    Then: Returns empty list
    """
    args = {}
    result = prepare_query(args)
    assert result == []


def test_prepare_query_only_value_filters():
    """
    Given: Arguments with only value filters
    When: prepare_query is called
    Then: Returns queries containing only value filters
    """
    args = {"value": json.dumps(["example", "test"])}
    result = prepare_query(args)
    assert len(result) == 1
    assert 'value:"example"' in result[0]
    assert 'value:"test"' in result[0]
    assert " OR " in result[0]
    assert " AND " not in result[0]


def test_prepare_query_only_field_filters():
    """
    Given: Arguments with only field filters (no values)
    When: prepare_query is called
    Then: Returns empty list as no value filters exist
    """
    args = {"type": "Domain", "verdict": "Malicious"}
    result = prepare_query(args)
    assert result == ['(type:"Domain") AND (verdict:"Malicious")']


def test_prepare_query_value_and_field_filters():
    """
    Given: Arguments with both value and field filters
    When: prepare_query is called
    Then: Returns queries combining value and field filters with AND
    """

    args = {"value": json.dumps(["example"]), "type": json.dumps(["Domain"]), "verdict": json.dumps(["Malicious"])}
    result = prepare_query(args)
    assert len(result) == 1
    assert 'value:"example"' in result[0]
    assert "type:" in result[0]
    assert "verdict:" in result[0]
    assert "Domain" in result[0]
    assert "Malicious" in result[0]
    assert " AND " in result[0]


def test_prepare_query_multiple_value_chunks():
    """
    Given: Arguments with over 100 values requiring chunking
    When: prepare_query is called
    Then: Returns multiple queries each combined with field filters
    """

    values = [f"example{i}" for i in range(150)]
    args = {"value": json.dumps(values), "type": json.dumps(["Domain"])}
    result = prepare_query(args)
    assert len(result) == 2
    for query in result:
        assert "type:" in query
        assert "Domain" in query
        assert " AND " in query


def test_prepare_query_single_value_with_fields():
    """
    Given: Arguments with single value and multiple field filters
    When: prepare_query is called
    Then: Returns single query with value and all field filters
    """

    args = {
        "value": json.dumps(["test.example"]),
        "type": json.dumps(["Domain"]),
        "verdict": json.dumps(["Malicious"]),
        "score": json.dumps(["High"]),
    }
    result = prepare_query(args)
    assert len(result) == 1
    assert 'value:"test.example"' in result[0]
    assert "type:" in result[0]
    assert "verdict:" in result[0]
    assert "score:" in result[0]
    assert result[0].count(" AND ") == 3


def test_prepare_query_empty_value_list():
    """
    Given: Arguments with empty value list and field filters
    When: prepare_query is called
    Then: Returns empty list
    """

    args = {"value": "[]", "type": "Domain"}
    result = prepare_query(args)
    assert result == ['(type:"Domain")']


def test_prepare_query_values_with_special_characters():
    """
    Given: Arguments with values containing special characters and field filters
    When: prepare_query is called
    Then: Returns queries with properly escaped values combined with fields
    """

    args = {"value": json.dumps(["test with spaces", 'test"quotes']), "type": "Domain"}
    result = prepare_query(args)
    assert len(result) == 1
    assert "test\\ with\\ spaces" in result[0]
    assert 'test\\"quotes' in result[0]
    assert "type:" in result[0]
    assert " AND " in result[0]


def test_prepare_query_excluded_keys_ignored():
    """
    Given: Arguments with value filters, valid fields, and excluded keys
    When: prepare_query is called
    Then: Returns queries excluding the excluded keys but including valid fields
    """

    excluded_key = KEYS_TO_EXCLUDE_FROM_QUERY[0] if KEYS_TO_EXCLUDE_FROM_QUERY else "dummy"
    args = {"value": json.dumps(["example"]), "type": "Domain", excluded_key: json.dumps(["excluded_value"])}
    result = prepare_query(args)
    assert len(result) == 1
    assert 'value:"example"' in result[0]
    assert "type:" in result[0]
    assert f"{excluded_key}:" not in result[0]


def test_prepare_query_issues_ids_transformation():
    """
    Given: Arguments with IssuesIDs field and value filters
    When: prepare_query is called
    Then: Returns queries with IssuesIDs transformed to investigationIDs
    """

    args = {"value": json.dumps(["example"]), "IssuesIDs": "123,456"}
    result = prepare_query(args)
    assert len(result) == 1
    assert "investigationIDs:" in result[0]
    assert "IssuesIDs:" not in result[0]
    assert "123" in result[0]
    assert "456" in result[0]


def test_prepare_query_empty_fields_ignored():
    """
    Given: Arguments with value filters and empty field values
    When: prepare_query is called
    Then: Returns queries containing only value filters as empty fields are ignored
    """

    args = {"value": json.dumps(["example"]), "type": "", "verdict": ""}
    result = prepare_query(args)
    assert len(result) == 1
    assert 'value:"example"' in result[0]
    assert "type:" not in result[0]
    assert "verdict:" not in result[0]
    assert " AND " not in result[0]


def test_prepare_query_large_value_set_with_complex_fields():
    """
    Given: Arguments with 250 values and multiple complex field filters
    When: prepare_query is called
    Then: Returns three queries each combined with all field filters
    """

    values = [f"domain{i}.example" for i in range(250)]
    args = {
        "value": json.dumps(values),
        "type": json.dumps(["Domain", "IP"]),
        "verdict": json.dumps(["Malicious"]),
        "score": json.dumps(["High", "Medium"]),
    }
    result = prepare_query(args)
    assert len(result) == 3
    for query in result:
        assert "type:" in query
        assert "verdict:" in query
        assert "score:" in query
        assert query.count(" AND ") == 3


def test_prepare_query_mixed_data_types_in_values():
    """
    Given: Arguments with mixed data types in values and field filters
    When: prepare_query is called
    Then: Returns queries with all values converted to strings and combined with fields
    """

    args = {"value": json.dumps(["example", 192168001001, True]), "type": "Domain"}
    result = prepare_query(args)
    assert len(result) == 1
    assert 'value:"example"' in result[0]
    assert 'value:"192168001001"' in result[0]
    assert 'value:"True"' in result[0]
    assert "type:" in result[0]
    assert " AND " in result[0]


def test_prepare_query_whitespace_stripped_from_values():
    """
    Given: Arguments with values containing whitespace and field filters
    When: prepare_query is called
    Then: Returns queries with whitespace stripped from values
    """

    args = {"value": json.dumps(["  example  ", "\ttest.org\n"]), "type": "Domain"}
    result = prepare_query(args)
    assert len(result) == 1
    assert 'value:"example"' in result[0]
    assert 'value:"test.org"' in result[0]
    assert "type:" in result[0]
    assert " AND " in result[0]


def test_build_query_excluding_indicator_values_empty_args():
    """
    Given: Empty arguments dictionary
    When: build_query_excluding_indicator_values is called
    Then: Returns empty string
    """

    args = {}
    result = build_query_excluding_indicator_values(args)
    assert result == ""


def test_build_query_excluding_indicator_values_only_value_key():
    """
    Given: Arguments containing only 'value' key
    When: build_query_excluding_indicator_values is called
    Then: Returns empty string as value key is excluded
    """

    args = {"value": json.dumps(["example", "test"])}
    result = build_query_excluding_indicator_values(args)
    assert result == ""


def test_build_query_excluding_indicator_values_single_field():
    """
    Given: Arguments with single field excluding value
    When: build_query_excluding_indicator_values is called
    Then: Returns query string with single field condition in parentheses
    """

    args = {"type": "Domain"}
    result = build_query_excluding_indicator_values(args)
    assert result == '(type:"Domain")'


def test_build_query_excluding_indicator_values_multiple_fields():
    """
    Given: Arguments with multiple fields excluding value
    When: build_query_excluding_indicator_values is called
    Then: Returns query string with multiple field conditions joined by AND
    """

    args = {"type": json.dumps(["Domain"]), "verdict": "Malicious"}
    result = build_query_excluding_indicator_values(args)
    assert "(type:" in result
    assert "(verdict:" in result
    assert "Domain" in result
    assert "Malicious" in result
    assert " AND " in result


def test_build_query_excluding_indicator_values_with_value_field_mixed():
    """
    Given: Arguments with value field and other fields
    When: build_query_excluding_indicator_values is called
    Then: Returns query string excluding value field but including other fields
    """

    args = {"value": json.dumps(["example"]), "type": "Domain", "verdict": "Malicious"}
    result = build_query_excluding_indicator_values(args)
    assert "value:" not in result
    assert "type:" in result
    assert "verdict:" in result
    assert " AND " in result


def test_build_query_excluding_indicator_values_issues_ids_transformation():
    """
    Given: Arguments with IssuesIDs field
    When: build_query_excluding_indicator_values is called
    Then: Returns query string with IssuesIDs transformed to investigationIDs
    """
    args = {"IssuesIDs": "123,456"}
    result = build_query_excluding_indicator_values(args)
    assert "investigationIDs:" in result
    assert "IssuesIDs:" not in result
    assert "123" in result
    assert "456" in result


def test_build_query_excluding_indicator_values_excluded_keys_ignored():
    """
    Given: Arguments with fields in KEYS_TO_EXCLUDE_FROM_QUERY
    When: build_query_excluding_indicator_values is called
    Then: Returns query string excluding the excluded keys
    """

    excluded_key = KEYS_TO_EXCLUDE_FROM_QUERY[0] if KEYS_TO_EXCLUDE_FROM_QUERY else "dummy"
    args = {"type": "Domain", excluded_key: "excluded_value"}
    result = build_query_excluding_indicator_values(args)
    assert "type:" in result
    assert f"{excluded_key}:" not in result


def test_build_query_excluding_indicator_values_empty_field_values():
    """
    Given: Arguments with empty field values
    When: build_query_excluding_indicator_values is called
    Then: Returns empty string as empty fields are ignored
    """

    args = {"type": [], "verdict": "", "score": None}
    result = build_query_excluding_indicator_values(args)
    assert result == ""


def test_build_query_excluding_indicator_values_mixed_empty_and_valid_fields():
    """
    Given: Arguments with mix of empty and valid field values
    When: build_query_excluding_indicator_values is called
    Then: Returns query string containing only valid fields
    """

    args = {"type": "Domain", "verdict": "", "score": "High"}
    result = build_query_excluding_indicator_values(args)
    assert "type:" in result
    assert "score:" in result
    assert "verdict:" not in result
    assert " AND " in result


def test_build_query_excluding_indicator_values_multiple_values_in_field():
    """
    Given: Arguments with field containing multiple values
    When: build_query_excluding_indicator_values is called
    Then: Returns query string with OR operators between multiple values
    """

    args = {"type": "Domain,IP,URL"}
    result = build_query_excluding_indicator_values(args)
    assert "(type:" in result
    assert "Domain" in result
    assert "IP" in result
    assert "URL" in result
    assert " OR " in result


def test_build_query_excluding_indicator_values_single_value_no_or():
    """
    Given: Arguments with field containing single value
    When: build_query_excluding_indicator_values is called
    Then: Returns query string without OR operators
    """

    args = {"type": "Domain"}
    result = build_query_excluding_indicator_values(args)
    assert "(type:" in result
    assert "Domain" in result
    assert " OR " not in result


def test_build_query_excluding_indicator_values_complex_multiple_fields():
    """
    Given: Arguments with multiple fields each having multiple values
    When: build_query_excluding_indicator_values is called
    Then: Returns query string with proper AND/OR structure
    """

    args = {
        "type": "Domain,IP",
        "verdict": "Malicious,Suspicious",
        "score": "High",
    }
    result = build_query_excluding_indicator_values(args)
    assert result.count("(") == 3
    assert result.count(")") == 3
    assert result.count(" AND ") == 2
    assert "type:" in result
    assert "verdict:" in result
    assert "score:" in result


def test_build_query_excluding_indicator_values_non_json_string_values():
    """
    Given: Arguments with field values as plain strings (not JSON)
    When: build_query_excluding_indicator_values is called
    Then: Returns query string treating plain strings as single values
    """

    args = {"type": "Domain", "verdict": "Malicious"}
    result = build_query_excluding_indicator_values(args)
    assert "type:" in result
    assert "verdict:" in result
    assert "Domain" in result
    assert "Malicious" in result
    assert " AND " in result


def test_build_query_excluding_indicator_values_mixed_json_and_plain_values():
    """
    Given: Arguments with mix of JSON and plain string field values
    When: build_query_excluding_indicator_values is called
    Then: Returns query string handling both value types correctly
    """

    args = {"type": "Domain,IP", "verdict": "Malicious", "score": "High"}
    result = build_query_excluding_indicator_values(args)
    assert "type:" in result
    assert "verdict:" in result
    assert "score:" in result
    assert " OR " in result
    assert " AND " in result


def test_build_query_excluding_indicator_values_issues_ids_with_other_fields():
    """
    Given: Arguments with IssuesIDs and other fields
    When: build_query_excluding_indicator_values is called
    Then: Returns query string with IssuesIDs transformed and combined with other fields
    """

    args = {"IssuesIDs": "123,456", "type": "Domain"}
    result = build_query_excluding_indicator_values(args)
    assert "investigationIDs:" in result
    assert "type:" in result
    assert "IssuesIDs:" not in result
    assert " AND " in result


def test_build_query_excluding_indicator_values_value_field_at_different_positions():
    """
    Given: Arguments with value field at beginning, middle, and end positions
    When: build_query_excluding_indicator_values is called
    Then: Returns query string excluding value field regardless of position
    """

    args = {"value": json.dumps(["test"]), "type": "Domain", "verdict": "Malicious"}
    result = build_query_excluding_indicator_values(args)
    assert "value:" not in result
    assert "type:" in result
    assert "verdict:" in result


def test_search_indicators_empty_args():
    """
    Given: Empty arguments dictionary
    When: search_indicators is called
    Then: Returns empty markdown and empty list as no queries are generated
    """
    args = {}
    markdown, filtered_indicators = search_indicators(args)
    assert filtered_indicators == []
    assert "Indicators Found" in markdown


def test_search_indicators_no_results(mocker):
    """
    Given: Valid arguments that generate queries but find no indicators
    When: search_indicators is called
    Then: Returns empty results with proper markdown formatting
    """
    args = {"value": json.dumps(["nonexistent"])}

    mock_demisto = mocker.patch("SearchIndicatorAgentix.demisto")
    mock_demisto.executeCommand.return_value = [{"Contents": []}]
    mock_demisto.debug.return_value = None

    markdown, filtered_indicators = search_indicators(args)

    assert filtered_indicators == []
    assert "Indicators Found" in markdown


def test_search_indicators_single_query_single_result(mocker):
    """
    Given: Arguments that generate single query and return single indicator
    When: search_indicators is called
    Then: Returns properly formatted indicator with all required fields
    """
    args = {"value": json.dumps(["example.com"])}
    mock_indicator = {
        "id": "123",
        "indicator_type": "Domain",
        "value": "example",
        "score": 3,
        "expirationStatus": "Active",
        "investigationIDs": ["inv1"],
        "lastSeen": "2023-01-01",
    }

    mock_demisto = mocker.patch("SearchIndicatorAgentix.demisto")
    mock_demisto.executeCommand.return_value = [{"Contents": [mock_indicator]}]
    mock_demisto.debug.return_value = None

    markdown, filtered_indicators = search_indicators(args)

    assert len(filtered_indicators) == 1
    assert filtered_indicators[0]["id"] == "123"
    assert filtered_indicators[0]["verdict"] == "Malicious"
    assert "example" in markdown


def test_search_indicators_multiple_queries_multiple_results(mocker):
    """
    Given: Arguments generating multiple queries each returning indicators
    When: search_indicators is called
    Then: Returns combined results from all queries
    """
    values = [f"example{i}.com" for i in range(150)]
    args = {"value": json.dumps(values)}

    mock_indicator1 = {
        "id": "123",
        "indicator_type": "Domain",
        "value": "example1.com",
        "score": 2,
        "expirationStatus": "Active",
        "investigationIDs": [],
        "lastSeen": "2023-01-01",
    }

    mock_indicator2 = {
        "id": "456",
        "indicator_type": "Domain",
        "value": "example2.com",
        "score": 1,
        "expirationStatus": "Expired",
        "investigationIDs": ["inv2"],
        "lastSeen": "2023-01-02",
    }

    mock_demisto = mocker.patch("SearchIndicatorAgentix.demisto")
    mock_demisto.executeCommand.side_effect = [[{"Contents": [mock_indicator1]}], [{"Contents": [mock_indicator2]}]]
    mock_demisto.debug.return_value = None

    markdown, filtered_indicators = search_indicators(args)

    assert len(filtered_indicators) == 2
    assert filtered_indicators[0]["id"] == "123"
    assert filtered_indicators[1]["id"] == "456"
    assert mock_demisto.executeCommand.call_count == 2


def test_search_indicators_missing_fields_with_custom_fields(mocker):
    """
    Given: Indicator with missing standard fields but present in CustomFields
    When: search_indicators is called
    Then: Returns indicator with fields populated from CustomFields
    """
    args = {"value": json.dumps(["example"])}
    mock_indicator = {
        "id": "123",
        "value": "example",
        "CustomFields": {
            "indicator_type": "Domain",
            "score": 2,
            "expirationStatus": "Active",
            "investigationIDs": ["inv1"],
            "lastSeen": "2023-01-01",
        },
    }

    mock_demisto = mocker.patch("SearchIndicatorAgentix.demisto")
    mock_demisto.executeCommand.return_value = [{"Contents": [mock_indicator]}]
    mock_demisto.debug.return_value = None

    markdown, filtered_indicators = search_indicators(args)

    assert len(filtered_indicators) == 1
    assert filtered_indicators[0]["indicator_type"] == "Domain"
    assert filtered_indicators[0]["score"] == 2


def test_search_indicators_with_size_parameter(mocker):
    """
    Given: Arguments with size parameter to limit results
    When: search_indicators is called
    Then: Passes size parameter to executeCommand
    """
    args = {"value": json.dumps(["example.com"]), "size": 50}

    mock_demisto = mocker.patch("SearchIndicatorAgentix.demisto")
    mock_demisto.executeCommand.return_value = [{"Contents": []}]
    mock_demisto.debug.return_value = None

    search_indicators(args)

    mock_demisto.executeCommand.assert_called()
    call_args = mock_demisto.executeCommand.call_args[0][1]
    assert call_args["size"] == 50


def test_search_indicators_no_size_parameter(mocker):
    """
    Given: Arguments without size parameter
    When: search_indicators is called
    Then: Passes None as size to executeCommand
    """
    args = {"value": json.dumps(["example"])}

    mock_demisto = mocker.patch("SearchIndicatorAgentix.demisto")
    mock_demisto.executeCommand.return_value = [{"Contents": []}]
    mock_demisto.debug.return_value = None

    search_indicators(args)

    mock_demisto.executeCommand.assert_called()
    call_args = mock_demisto.executeCommand.call_args[0][1]
    assert call_args["size"] is None


def test_search_indicators_execute_command_returns_none(mocker):
    """
    Given: executeCommand returns None
    When: search_indicators is called
    Then: Handles None result gracefully and returns empty results
    """
    args = {"value": json.dumps(["example"])}

    mock_demisto = mocker.patch("SearchIndicatorAgentix.demisto")
    mock_demisto.executeCommand.return_value = None
    mock_demisto.debug.return_value = None

    markdown, filtered_indicators = search_indicators(args)

    assert filtered_indicators == []


def test_search_indicators_execute_command_empty_result(mocker):
    """
    Given: executeCommand returns empty result structure
    When: search_indicators is called
    Then: Handles empty result gracefully
    """
    args = {"value": json.dumps(["example.com"])}

    mock_demisto = mocker.patch("SearchIndicatorAgentix.demisto")
    mock_demisto.executeCommand.return_value = [{}]
    mock_demisto.debug.return_value = None

    markdown, filtered_indicators = search_indicators(args)

    assert filtered_indicators == []


def test_search_indicators_score_to_reputation_conversion(mocker):
    """
    Given: Indicators with different score values
    When: search_indicators is called
    Then: Returns indicators with correct verdict based on score
    """
    args = {"value": json.dumps(["example"])}
    mock_indicators = [
        {"id": "2", "score": 1, "value": "unknown"},
        {"id": "3", "score": 2, "value": "suspicious"},
        {"id": "4", "score": 3, "value": "bad"},
    ]

    mock_demisto = mocker.patch("SearchIndicatorAgentix.demisto")
    mock_demisto.executeCommand.return_value = [{"Contents": mock_indicators}]
    mock_demisto.debug.return_value = None

    markdown, filtered_indicators = search_indicators(args)

    assert len(filtered_indicators) == 3
    assert filtered_indicators[0]["verdict"] == "Benign"
    assert filtered_indicators[1]["verdict"] == "Suspicious"
    assert filtered_indicators[2]["verdict"] == "Malicious"


def test_search_indicators_mixed_field_sources(mocker):
    """
    Given: Indicators with fields from both standard and CustomFields locations
    When: search_indicators is called
    Then: Returns indicators with proper field precedence (standard over CustomFields)
    """
    args = {"value": json.dumps(["example."])}
    mock_indicator = {
        "id": "123",
        "indicator_type": "Domain",
        "value": "example.",
        "score": 2,
        "CustomFields": {
            "indicator_type": "IP",
            "score": 3,
            "expirationStatus": "Expired",
            "investigationIDs": ["custom_inv"],
            "lastSeen": "2022-01-01",
        },
    }

    mock_demisto = mocker.patch("SearchIndicatorAgentix.demisto")
    mock_demisto.executeCommand.return_value = [{"Contents": [mock_indicator]}]
    mock_demisto.debug.return_value = None

    markdown, filtered_indicators = search_indicators(args)

    assert len(filtered_indicators) == 1
    assert filtered_indicators[0]["indicator_type"] == "Domain"
    assert filtered_indicators[0]["score"] == 2
    assert filtered_indicators[0]["expirationStatus"] == "Expired"
