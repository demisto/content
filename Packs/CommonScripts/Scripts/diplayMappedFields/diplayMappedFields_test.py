import pytest

from diplayMappedFields import (
    convert_to_html,
    extract_keys_with_values,
    format_data_to_rows,
    remove_empty_rows,
)

MULTISELECT_JSON_VALUE = (
    '{"process_evidence":[{"verdict":"suspicious","tags":[],' '"userAccount":{"resourceAccessEvents":[]}}],"custom_details":{}}'
)


def test_extract_keys_with_values_keeps_list_values():
    """A multiSelect field value (a list) must be preserved as a list, not flattened away."""
    fields = {"additionaldata": [MULTISELECT_JSON_VALUE]}

    items = extract_keys_with_values(fields)

    assert ("additionaldata", [MULTISELECT_JSON_VALUE]) in items


def test_multiselect_value_survives_to_html():
    """
    A multiSelect field (additionaldata/rawevent) whose value contains empty
    objects/arrays must still be rendered in the Mapped Fields HTML.

    Previously the row was dropped/corrupted because the value was flattened into a
    pipe-delimited row string that (a) was substring-matched against EMPTY_VALUES
    (dropping any row containing "{}") and (b) was re-split on "|".
    """
    fields = {"additionaldata": [MULTISELECT_JSON_VALUE]}

    items = extract_keys_with_values(fields)
    rows = format_data_to_rows(items)
    filtered_rows = remove_empty_rows(rows)
    html = convert_to_html(filtered_rows)

    assert "additionaldata" in html
    assert "process_evidence" in html
    assert "suspicious" in html


def test_value_containing_pipe_is_not_split_into_extra_columns():
    """
    A field value that literally contains a pipe character must not be broken into
    extra table columns (delimiter collision).
    """
    fields = {"somefield": "a|b|c"}

    items = extract_keys_with_values(fields)
    rows = format_data_to_rows(items)
    filtered_rows = remove_empty_rows(rows)
    html = convert_to_html(filtered_rows)

    # Exactly one key cell and one value cell -> two <td> elements
    assert html.count("<td") == 2
    assert "somefield" in html
    # The full literal value (including the pipes) must be preserved intact inside a single cell
    assert ">a|b|c</td>" in html


def test_multiselect_list_with_multiple_items_renders_all_items():
    """A multiSelect list holding several plain values renders all of them joined."""
    fields = {"labels": ["alpha", "beta", "gamma"]}

    items = extract_keys_with_values(fields)
    rows = format_data_to_rows(items)
    filtered_rows = remove_empty_rows(rows)
    html = convert_to_html(filtered_rows)

    assert "labels" in html
    for expected in ("alpha", "beta", "gamma"):
        assert expected in html
    # Still exactly one key + one value cell
    assert html.count("<td") == 2


def test_genuinely_empty_values_are_removed():
    """Rows that are genuinely empty ("{}", "[{}]") must still be filtered out."""
    fields = {
        "emptyobj": "{}",
        "emptylist": "[{}]",
        "realfield": "hello",
    }

    items = extract_keys_with_values(fields)
    rows = format_data_to_rows(items)
    filtered_rows = remove_empty_rows(rows)
    html = convert_to_html(filtered_rows)

    assert "realfield" in html
    assert "hello" in html
    assert "emptyobj" not in html
    assert "emptylist" not in html


def test_key_containing_empty_marker_substring_is_not_dropped():
    """
    A field whose value merely CONTAINS an empty marker as a substring (e.g. a JSON
    payload with a nested "{}") must NOT be dropped. This is the core regression.
    """
    fields = {"payload": '{"a":1,"nested":{}}'}

    items = extract_keys_with_values(fields)
    rows = format_data_to_rows(items)
    filtered_rows = remove_empty_rows(rows)
    html = convert_to_html(filtered_rows)

    assert "payload" in html
    assert "nested" in html


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
