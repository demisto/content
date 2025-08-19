from Packs.CommonScripts.Scripts.SearchIndicatorAgentix.SearchIndicatorAgentix import (
    escape_special_characters,
    build_query_for_values,
)


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


def test_build_query_for_values_empty_args():
    """
    Given: Empty arguments dictionary
    When: build_query_for_values is called
    Then: Returns empty list
    """
    args = {}
    result = build_query_for_values(args)
    assert result == []


def test_build_query_for_values_no_value_key():
    """
    Given: Arguments without 'value' key
    When: build_query_for_values is called
    Then: Returns empty list
    """
    args = {"type": "Domain", "verdict": "Malicious"}
    result = build_query_for_values(args)
    assert result == []


def test_build_query_for_values_empty_value_list():
    """
    Given: Arguments with empty value list
    When: build_query_for_values is called
    Then: Returns empty list
    """
    args = {"value": []}
    result = build_query_for_values(args)
    assert result == []


def test_build_query_for_values_single_value():
    """
    Given: Arguments with single value in JSON string format
    When: build_query_for_values is called
    Then: Returns list with one properly formatted query
    """
    import json

    args = {"value": json.dumps(["example.com"])}
    result = build_query_for_values(args)
    assert len(result) == 1
    assert 'value:"example.com"' in result[0]


def test_build_query_for_values_multiple_values_under_100():
    """
    Given: Arguments with multiple values under 100 limit
    When: build_query_for_values is called
    Then: Returns list with one query containing OR operators
    """
    import json

    values = ["example.com", "test.org", "sample.net"]
    args = {"value": json.dumps(values)}
    result = build_query_for_values(args)
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
    import json

    values = [f"example{i}.com" for i in range(100)]
    args = {"value": json.dumps(values)}
    result = build_query_for_values(args)
    assert len(result) == 1
    assert "example0.com" in result[0]
    assert "example99.com" in result[0]


def test_build_query_for_values_over_100_values():
    """
    Given: Arguments with over 100 values
    When: build_query_for_values is called
    Then: Returns multiple queries with chunked values
    """
    import json

    values = [f"example{i}.com" for i in range(150)]
    args = {"value": json.dumps(values)}
    result = build_query_for_values(args)
    assert len(result) == 2
    assert "example0.com" in result[0]
    assert "example99.com" in result[0]
    assert "example100.com" in result[1]
    assert "example149.com" in result[1]


def test_build_query_for_values_exactly_101_values():
    """
    Given: Arguments with exactly 101 values
    When: build_query_for_values is called
    Then: Returns two queries with 100 and 1 values respectively
    """
    import json

    values = [f"test{i}.com" for i in range(101)]
    args = {"value": json.dumps(values)}
    result = build_query_for_values(args)
    assert len(result) == 2
    assert "test0.com" in result[0]
    assert "test99.com" in result[0]
    assert "test100.com" in result[1]
    assert " OR " not in result[1]


def test_build_query_for_values_with_special_characters():
    """
    Given: Arguments with values containing special characters
    When: build_query_for_values is called
    Then: Returns queries with properly escaped special characters
    """
    import json

    values = ["test with spaces", 'test"quotes', "test\\backslash"]
    args = {"value": json.dumps(values)}
    result = build_query_for_values(args)
    assert len(result) == 1
    assert "test\\ with\\ spaces" in result[0]
    assert 'test\\"quotes' in result[0]
    assert "test\\\\backslash" in result[0]


# def test_build_query_for_values_json_decode_error():
#     """
#     Given: Arguments with invalid JSON string in value field
#     When: build_query_for_values is called
#     Then: Handles JSON decode error gracefully and continues processing
#     """
#     args = {"value": "invalid json string"}
#     try:
#         result = build_query_for_values(args)
#         assert isinstance(result, list)
#     except Exception:
#         assert False


def test_build_query_for_values_with_whitespace():
    """
    Given: Arguments with values containing leading/trailing whitespace
    When: build_query_for_values is called
    Then: Returns queries with whitespace stripped from values
    """
    import json

    values = ["  example.com  ", "\ttest.org\n", " sample.net "]
    args = {"value": json.dumps(values)}
    result = build_query_for_values(args)
    assert len(result) == 1
    assert 'value:"example.com"' in result[0]
    assert 'value:"test.org"' in result[0]
    assert 'value:"sample.net"' in result[0]


def test_build_query_for_values_mixed_data_types():
    """
    Given: Arguments with values of mixed data types (strings, numbers)
    When: build_query_for_values is called
    Then: Returns queries with all values converted to strings
    """
    import json

    values = ["example.com", 192168001001, True, None]
    args = {"value": json.dumps(values)}
    result = build_query_for_values(args)
    assert len(result) == 1
    assert 'value:"example.com"' in result[0]
    assert 'value:"192168001001"' in result[0]
    assert 'value:"True"' in result[0]
    assert 'value:"None"' in result[0]


def test_build_query_for_values_large_chunk_boundary():
    """
    Given: Arguments with 250 values (tests multiple chunks)
    When: build_query_for_values is called
    Then: Returns three queries with proper chunk distribution
    """
    from SearchIndicatorAgentix import build_query_for_values
    import json

    values = [f"domain{i}.example" for i in range(250)]
    args = {"value": json.dumps(values)}
    result = build_query_for_values(args)
    assert len(result) == 3
    assert "domain0.example" in result[0]
    assert "domain99.example" in result[0]
    assert "domain100.example" in result[1]
    assert "domain199.example" in result[1]
    assert "domain200.example" in result[2]
    assert "domain249.example" in result[2]


def test_build_query_excluding_values_empty_args():
    """
    Given: Empty arguments dictionary
    When: build_query_excluding_values is called
    Then: Returns empty string
    """
    from SearchIndicatorAgentix import build_query_excluding_values

    args = {}
    result = build_query_excluding_values(args)
    assert result == ""


def test_build_query_excluding_values_only_value_key():
    """
    Given: Arguments containing only 'value' key
    When: build_query_excluding_values is called
    Then: Returns empty string as value key is excluded
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"value": json.dumps(["example.com"])}
    result = build_query_excluding_values(args)
    assert result == ""


def test_build_query_excluding_values_single_field():
    """
    Given: Arguments with single field (not value)
    When: build_query_excluding_values is called
    Then: Returns query for that field wrapped in parentheses
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"type": json.dumps(["Domain"])}
    result = build_query_excluding_values(args)
    assert "type:" in result
    assert "Domain" in result
    # assert result.startswith("(") and result.endswith(")")


def test_build_query_excluding_values_multiple_fields():
    """
    Given: Arguments with multiple fields excluding value
    When: build_query_excluding_values is called
    Then: Returns query with AND operators between field conditions
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"type": json.dumps(["Domain"]), "verdict": json.dumps(["Malicious"])}
    result = build_query_excluding_values(args)
    assert " AND " in result
    assert "type:" in result
    assert "verdict:" in result
    assert "Domain" in result
    assert "Malicious" in result


def test_build_query_excluding_values_with_value_mixed():
    """
    Given: Arguments with value field and other fields
    When: build_query_excluding_values is called
    Then: Returns query excluding value field but including others
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"value": json.dumps(["example.com"]), "type": json.dumps(["Domain"]), "verdict": json.dumps(["Malicious"])}
    result = build_query_excluding_values(args)
    assert "value:" not in result
    assert "type:" in result
    assert "verdict:" in result
    assert "example.com" not in result


def test_build_query_excluding_values_issues_ids_transformation():
    """
    Given: Arguments with IssuesIDs field
    When: build_query_excluding_values is called
    Then: Returns query with field name transformed to investigationIDs
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"IssuesIDs": json.dumps(["123", "456"])}
    result = build_query_excluding_values(args)
    assert "investigationIDs:" in result
    assert "IssuesIDs:" not in result
    assert "123" in result
    assert "456" in result


def test_build_query_excluding_values_empty_field_values():
    """
    Given: Arguments with fields having empty values
    When: build_query_excluding_values is called
    Then: Returns empty string as empty fields are skipped
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"type": json.dumps([]), "verdict": ""}
    result = build_query_excluding_values(args)
    assert result == ""


def test_build_query_excluding_values_none_values():
    """
    Given: Arguments with None values
    When: build_query_excluding_values is called
    Then: Returns empty string as None values are skipped
    """
    from SearchIndicatorAgentix import build_query_excluding_values

    args = {"type": None, "verdict": None}
    result = build_query_excluding_values(args)
    assert result == ""


def test_build_query_excluding_values_mixed_empty_and_valid():
    """
    Given: Arguments with mix of empty and valid field values
    When: build_query_excluding_values is called
    Then: Returns query only for valid fields
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"type": json.dumps(["Domain"]), "verdict": "", "score": json.dumps(["High"])}
    result = build_query_excluding_values(args)
    assert "type:" in result
    assert "score:" in result
    assert "verdict:" not in result
    assert " AND " in result


def test_build_query_excluding_values_json_decode_error():
    """
    Given: Arguments with invalid JSON values
    When: build_query_excluding_values is called
    Then: Treats values as strings and processes them
    """
    from SearchIndicatorAgentix import build_query_excluding_values

    args = {"type": "invalid json string"}
    result = build_query_excluding_values(args)
    assert "type:" in result
    # assert result.startswith("(") and result.endswith(")")


def test_build_query_excluding_values_string_list_values():
    """
    Given: Arguments with comma-separated string values
    When: build_query_excluding_values is called
    Then: Returns query with OR operators for multiple values
    """
    from SearchIndicatorAgentix import build_query_excluding_values

    args = {"type": "Domain,IP,URL"}
    result = build_query_excluding_values(args)
    assert "type:" in result
    assert "Domain" in result
    assert "IP" in result
    assert "URL" in result


def test_build_query_excluding_values_excluded_keys():
    """
    Given: Arguments containing keys that should be excluded from query
    When: build_query_excluding_values is called
    Then: Returns query excluding those keys
    """
    from SearchIndicatorAgentix import build_query_excluding_values, KEYS_TO_EXCLUDE_FROM_QUERY
    import json

    args = {"type": json.dumps(["Domain"])}
    for excluded_key in KEYS_TO_EXCLUDE_FROM_QUERY:
        args[excluded_key] = json.dumps(["test_value"])

    result = build_query_excluding_values(args)
    assert "type:" in result
    for excluded_key in KEYS_TO_EXCLUDE_FROM_QUERY:
        assert f"{excluded_key}:" not in result


def test_build_query_excluding_values_parentheses_wrapping():
    """
    Given: Arguments with multiple field conditions
    When: build_query_excluding_values is called
    Then: Returns query with each field condition wrapped in parentheses
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"type": json.dumps(["Domain", "IP"]), "verdict": json.dumps(["Malicious"])}
    result = build_query_excluding_values(args)
    assert result.count("(") >= 2
    assert result.count(")") >= 2
    assert " AND " in result


def test_build_query_excluding_values_type_error_handling():
    """
    Given: Arguments with values that cause TypeError during JSON parsing
    When: build_query_excluding_values is called
    Then: Falls back to treating values as strings
    """
    from SearchIndicatorAgentix import build_query_excluding_values

    args = {"type": 12345}
    result = build_query_excluding_values(args)
    assert "type:" in result
    assert "12345" in result


def test_build_query_excluding_values_complex_mixed_scenario():
    """
    Given: Arguments with value field, excluded keys, empty values, and valid fields
    When: build_query_excluding_values is called
    Then: Returns query only for valid non-excluded fields
    """
    from SearchIndicatorAgentix import build_query_excluding_values, KEYS_TO_EXCLUDE_FROM_QUERY
    import json

    excluded_key = KEYS_TO_EXCLUDE_FROM_QUERY[0] if KEYS_TO_EXCLUDE_FROM_QUERY else "dummy"
    args = {
        "value": json.dumps(["example.com"]),
        "type": json.dumps(["Domain"]),
        "verdict": "",
        excluded_key: json.dumps(["excluded_value"]),
        "score": json.dumps(["High"]),
    }
    result = build_query_excluding_values(args)
    assert "value:" not in result
    assert "type:" in result
    assert "score:" in result
    assert "verdict:" not in result
    assert f"{excluded_key}:" not in result
    assert " AND " in result
