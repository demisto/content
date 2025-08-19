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

    args = {"value": json.dumps(["example"])}
    result = build_query_for_values(args)
    assert len(result) == 1
    assert 'value:"example"' in result[0]


def test_build_query_for_values_multiple_values_under_100():
    """
    Given: Arguments with multiple values under 100 limit
    When: build_query_for_values is called
    Then: Returns list with one query containing OR operators
    """
    import json

    values = ["example", "test", "sample"]
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

    values = [f"example{i}" for i in range(100)]
    args = {"value": json.dumps(values)}
    result = build_query_for_values(args)
    assert len(result) == 1
    assert "example0" in result[0]
    assert "example99" in result[0]


def test_build_query_for_values_over_100_values():
    """
    Given: Arguments with over 100 values
    When: build_query_for_values is called
    Then: Returns multiple queries with chunked values
    """
    import json

    values = [f"example{i}" for i in range(150)]
    args = {"value": json.dumps(values)}
    result = build_query_for_values(args)
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
    import json

    values = [f"test{i}" for i in range(101)]
    args = {"value": json.dumps(values)}
    result = build_query_for_values(args)
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

    values = ["  example  ", "\ttest\n", " sample "]
    args = {"value": json.dumps(values)}
    result = build_query_for_values(args)
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
    import json

    values = ["example", 192168001001, True, None]
    args = {"value": json.dumps(values)}
    result = build_query_for_values(args)
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


def test_prepare_query_empty_args():
    """
    Given: Empty arguments dictionary
    When: prepare_query is called
    Then: Returns empty list
    """
    from SearchIndicatorAgentix import prepare_query

    args = {}
    result = prepare_query(args)
    assert result == []


def test_prepare_query_only_value_filters():
    """
    Given: Arguments with only value filters
    When: prepare_query is called
    Then: Returns queries containing only value filters
    """
    from SearchIndicatorAgentix import prepare_query
    import json

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
    from SearchIndicatorAgentix import prepare_query
    import json

    args = {"type": json.dumps(["Domain"]), "verdict": json.dumps(["Malicious"])}
    result = prepare_query(args)
    assert result == []


def test_prepare_query_value_and_field_filters():
    """
    Given: Arguments with both value and field filters
    When: prepare_query is called
    Then: Returns queries combining value and field filters with AND
    """
    from SearchIndicatorAgentix import prepare_query
    import json

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
    from SearchIndicatorAgentix import prepare_query
    import json

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
    from SearchIndicatorAgentix import prepare_query
    import json

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
    from SearchIndicatorAgentix import prepare_query
    import json

    args = {"value": json.dumps([]), "type": json.dumps(["Domain"])}
    result = prepare_query(args)
    assert result == []


def test_prepare_query_values_with_special_characters():
    """
    Given: Arguments with values containing special characters and field filters
    When: prepare_query is called
    Then: Returns queries with properly escaped values combined with fields
    """
    from SearchIndicatorAgentix import prepare_query
    import json

    args = {"value": json.dumps(["test with spaces", 'test"quotes']), "type": json.dumps(["Domain"])}
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
    from SearchIndicatorAgentix import prepare_query, KEYS_TO_EXCLUDE_FROM_QUERY
    import json

    excluded_key = KEYS_TO_EXCLUDE_FROM_QUERY[0] if KEYS_TO_EXCLUDE_FROM_QUERY else "dummy"
    args = {"value": json.dumps(["example"]), "type": json.dumps(["Domain"]), excluded_key: json.dumps(["excluded_value"])}
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
    from SearchIndicatorAgentix import prepare_query
    import json

    args = {"value": json.dumps(["example"]), "IssuesIDs": json.dumps(["123", "456"])}
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
    from SearchIndicatorAgentix import prepare_query
    import json

    args = {"value": json.dumps(["example"]), "type": json.dumps([]), "verdict": ""}
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
    from SearchIndicatorAgentix import prepare_query
    import json

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
    from SearchIndicatorAgentix import prepare_query
    import json

    args = {"value": json.dumps(["example", 192168001001, True]), "type": json.dumps(["Domain"])}
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
    from SearchIndicatorAgentix import prepare_query
    import json

    args = {"value": json.dumps(["  example  ", "\ttest.org\n"]), "type": json.dumps(["Domain"])}
    result = prepare_query(args)
    assert len(result) == 1
    assert 'value:"example"' in result[0]
    assert 'value:"test.org"' in result[0]
    assert "type:" in result[0]
    assert " AND " in result[0]


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

    args = {"value": json.dumps(["example", "test"])}
    result = build_query_excluding_values(args)
    assert result == ""


def test_build_query_excluding_values_single_field():
    """
    Given: Arguments with single field excluding value
    When: build_query_excluding_values is called
    Then: Returns query string with single field condition in parentheses
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"type": json.dumps(["Domain"])}
    result = build_query_excluding_values(args)
    assert result == '(type:"Domain")'


def test_build_query_excluding_values_multiple_fields():
    """
    Given: Arguments with multiple fields excluding value
    When: build_query_excluding_values is called
    Then: Returns query string with multiple field conditions joined by AND
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"type": json.dumps(["Domain"]), "verdict": json.dumps(["Malicious"])}
    result = build_query_excluding_values(args)
    assert "(type:" in result
    assert "(verdict:" in result
    assert "Domain" in result
    assert "Malicious" in result
    assert " AND " in result


def test_build_query_excluding_values_with_value_field_mixed():
    """
    Given: Arguments with value field and other fields
    When: build_query_excluding_values is called
    Then: Returns query string excluding value field but including other fields
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"value": json.dumps(["example"]), "type": json.dumps(["Domain"]), "verdict": json.dumps(["Malicious"])}
    result = build_query_excluding_values(args)
    assert "value:" not in result
    assert "type:" in result
    assert "verdict:" in result
    assert " AND " in result


def test_build_query_excluding_values_issues_ids_transformation():
    """
    Given: Arguments with IssuesIDs field
    When: build_query_excluding_values is called
    Then: Returns query string with IssuesIDs transformed to investigationIDs
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"IssuesIDs": json.dumps(["123", "456"])}
    result = build_query_excluding_values(args)
    assert "investigationIDs:" in result
    assert "IssuesIDs:" not in result
    assert "123" in result
    assert "456" in result


def test_build_query_excluding_values_excluded_keys_ignored():
    """
    Given: Arguments with fields in KEYS_TO_EXCLUDE_FROM_QUERY
    When: build_query_excluding_values is called
    Then: Returns query string excluding the excluded keys
    """
    from SearchIndicatorAgentix import build_query_excluding_values, KEYS_TO_EXCLUDE_FROM_QUERY
    import json

    excluded_key = KEYS_TO_EXCLUDE_FROM_QUERY[0] if KEYS_TO_EXCLUDE_FROM_QUERY else "dummy"
    args = {"type": json.dumps(["Domain"]), excluded_key: json.dumps(["excluded_value"])}
    result = build_query_excluding_values(args)
    assert "type:" in result
    assert f"{excluded_key}:" not in result


def test_build_query_excluding_values_empty_field_values():
    """
    Given: Arguments with empty field values
    When: build_query_excluding_values is called
    Then: Returns empty string as empty fields are ignored
    """
    from SearchIndicatorAgentix import build_query_excluding_values

    args = {"type": [], "verdict": "", "score": None}
    result = build_query_excluding_values(args)
    assert result == ""


def test_build_query_excluding_values_mixed_empty_and_valid_fields():
    """
    Given: Arguments with mix of empty and valid field values
    When: build_query_excluding_values is called
    Then: Returns query string containing only valid fields
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"type": json.dumps(["Domain"]), "verdict": "", "score": json.dumps(["High"])}
    result = build_query_excluding_values(args)
    assert "type:" in result
    assert "score:" in result
    assert "verdict:" not in result
    assert " AND " in result


def test_build_query_excluding_values_multiple_values_in_field():
    """
    Given: Arguments with field containing multiple values
    When: build_query_excluding_values is called
    Then: Returns query string with OR operators between multiple values
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"type": json.dumps(["Domain", "IP", "URL"])}
    result = build_query_excluding_values(args)
    assert "(type:" in result
    assert "Domain" in result
    assert "IP" in result
    assert "URL" in result
    assert " OR " in result


def test_build_query_excluding_values_single_value_no_or():
    """
    Given: Arguments with field containing single value
    When: build_query_excluding_values is called
    Then: Returns query string without OR operators
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"type": json.dumps(["Domain"])}
    result = build_query_excluding_values(args)
    assert "(type:" in result
    assert "Domain" in result
    assert " OR " not in result


def test_build_query_excluding_values_special_characters_in_values():
    """
    Given: Arguments with field values containing special characters
    When: build_query_excluding_values is called
    Then: Returns query string with properly escaped special characters
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"description": json.dumps(["test with spaces", 'test"quotes', "test\\backslash"])}
    result = build_query_excluding_values(args)
    assert "test\\ with\\ spaces" in result
    assert 'test\\"quotes' in result
    assert "test\\\\backslash" in result


def test_build_query_excluding_values_complex_multiple_fields():
    """
    Given: Arguments with multiple fields each having multiple values
    When: build_query_excluding_values is called
    Then: Returns query string with proper AND/OR structure
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {
        "type": json.dumps(["Domain", "IP"]),
        "verdict": json.dumps(["Malicious", "Suspicious"]),
        "score": json.dumps(["High"]),
    }
    result = build_query_excluding_values(args)
    assert result.count("(") == 3
    assert result.count(")") == 3
    assert result.count(" AND ") == 2
    assert "type:" in result
    assert "verdict:" in result
    assert "score:" in result


def test_build_query_excluding_values_non_json_string_values():
    """
    Given: Arguments with field values as plain strings (not JSON)
    When: build_query_excluding_values is called
    Then: Returns query string treating plain strings as single values
    """
    from SearchIndicatorAgentix import build_query_excluding_values

    args = {"type": "Domain", "verdict": "Malicious"}
    result = build_query_excluding_values(args)
    assert "type:" in result
    assert "verdict:" in result
    assert "Domain" in result
    assert "Malicious" in result
    assert " AND " in result


def test_build_query_excluding_values_mixed_json_and_plain_values():
    """
    Given: Arguments with mix of JSON and plain string field values
    When: build_query_excluding_values is called
    Then: Returns query string handling both value types correctly
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"type": json.dumps(["Domain", "IP"]), "verdict": "Malicious", "score": json.dumps(["High"])}
    result = build_query_excluding_values(args)
    assert "type:" in result
    assert "verdict:" in result
    assert "score:" in result
    assert " OR " in result
    assert " AND " in result


def test_build_query_excluding_values_whitespace_in_field_values():
    """
    Given: Arguments with field values containing leading/trailing whitespace
    When: build_query_excluding_values is called
    Then: Returns query string with whitespace stripped from values
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"type": json.dumps(["  Domain  ", "\tIP\n", " URL "])}
    result = build_query_excluding_values(args)
    assert 'type:"Domain"' in result
    assert 'type:"IP"' in result
    assert 'type:"URL"' in result


def test_build_query_excluding_values_large_number_of_fields():
    """
    Given: Arguments with many different fields
    When: build_query_excluding_values is called
    Then: Returns query string joining all fields with AND operators
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {
        "type": json.dumps(["Domain"]),
        "verdict": json.dumps(["Malicious"]),
        "score": json.dumps(["High"]),
        "source": json.dumps(["VirusTotal"]),
        "category": json.dumps(["Malware"]),
    }
    result = build_query_excluding_values(args)
    assert result.count(" AND ") == 4
    assert result.count("(") == 5
    assert result.count(")") == 5


def test_build_query_excluding_values_issues_ids_with_other_fields():
    """
    Given: Arguments with IssuesIDs and other fields
    When: build_query_excluding_values is called
    Then: Returns query string with IssuesIDs transformed and combined with other fields
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"IssuesIDs": json.dumps(["123", "456"]), "type": json.dumps(["Domain"])}
    result = build_query_excluding_values(args)
    assert "investigationIDs:" in result
    assert "type:" in result
    assert "IssuesIDs:" not in result
    assert " AND " in result


def test_build_query_excluding_values_value_field_at_different_positions():
    """
    Given: Arguments with value field at beginning, middle, and end positions
    When: build_query_excluding_values is called
    Then: Returns query string excluding value field regardless of position
    """
    from SearchIndicatorAgentix import build_query_excluding_values
    import json

    args = {"value": json.dumps(["test"]), "type": json.dumps(["Domain"]), "verdict": json.dumps(["Malicious"])}
    result = build_query_excluding_values(args)
    assert "value:" not in result
    assert "type:" in result
    assert "verdict:" in result
