from typing import Any

import pytest
from JiraCreateIssueExample import add_custom_fields, parse_custom_fields, validate_date_field


@pytest.mark.parametrize("due_date", [("2022-01-01"), ("2023-01-31"), ("2024-02-29")])
def test_validate_date_field_data_remains(due_date: str):
    """
    Given:
        - A string representing a date in format '%Y-%m-%d'.

    When:
        - Case A: A valid string is in expected format and passed to `validate_date_field`
        - Case B: A valid string is in expected format and passed to `validate_date_field`
        - Case C: A leap year string is in expected format and passed to `validate_date_field`

    Then:
        - Case A: No exception is thrown.
        - Case B: No exception is thrown.
        - Case C: No exception is thrown.
    """

    validate_date_field(due_date)


@pytest.mark.parametrize("due_date", [("2022-31-31"), ("202-51-XY"), ("ABC")])
def test_validate_date_field_format(due_date: str):
    """
    Given:
        - An invalid string.

    When:
        - Case A: Attempting to validate the string with `validate_date_field` but it has an invalid month (31)
        - Case B: Attempting to validate the string with `validate_date_field` but it has an invalid month (51) and day(XY)
        - Case C: Attempting to validate the string with `validate_date_field` but it has invalid everything
    Then:
        - Case A: A `ValueError` exception is thrown.
        - Case B: A `ValueError` exception is thrown.
        - Case C: A `ValueError` exception is thrown.
    """

    with pytest.raises(ValueError, match=r"time data '(.*)' does not match format '%Y-%m-%d'"):
        raise validate_date_field(due_date)


@pytest.mark.parametrize("due_date", [("2022-12-12T13:00:00"), ("2022-12-12Z12")])
def test_validate_date_field_time_data_doesnt_match(due_date: str):
    """
    Given:
        - An invalid string.

    When:
        - Case A: Attempting to validate the string with `validate_date_field` but it has added time.
        - Case B: Attempting to validate the string with `validate_date_field` but it has added timezone.

    Then:
        - Case A: A `ValueError` exception is thrown.
        - Case B: A `ValueError` exception is thrown.
    """

    with pytest.raises(ValueError, match=r"unconverted data remains: "):
        raise validate_date_field(due_date)


@pytest.mark.parametrize(
    "custom_fields, expected",
    [
        # ASCII text value
        (["customfield_10096=test"], {"customfield_10096": "test"}),
        # Integer value (no leading zero) is coerced to int
        (["customfield_10096=test", "customfield_10040=100"], {"customfield_10096": "test", "customfield_10040": 100}),
        # Integer with leading zero stays as string
        (["customfield_10096=test", "customfield_10040=0100"], {"customfield_10096": "test", "customfield_10040": "0100"}),
        # Alphanumeric value
        (["customfield_10096=test", "customfield_10040=A100"], {"customfield_10096": "test", "customfield_10040": "A100"}),
        # Missing '=' delimiter - skipped (no match)
        (["customfield_10096:test", "customfield_10040=A100"], {"customfield_10040": "A100"}),
        # Double '==' - value becomes '=test' (everything after first '=', stops at comma)
        (["customfield_10096==test", "customfield_10040=A100"], {"customfield_10096": "=test", "customfield_10040": "A100"}),
        # Empty list
        ([], {}),
        # Non-ASCII value (Korean) - previously silently dropped by \w+ regex, now supported
        (["customfield_10214=\uc6d4\ub3c4\uc2dc\uac04"], {"customfield_10214": "\uc6d4\ub3c4\uc2dc\uac04"}),
        # Value with spaces
        (["customfield_10096=hello world"], {"customfield_10096": "hello world"}),
        # Value with hyphens and special chars
        (["customfield_10096=foo-bar@baz/qux"], {"customfield_10096": "foo-bar@baz/qux"}),
        # Unsplit multi-field string (argToList didn't split) - [^,]+ stops at comma, both fields parsed
        (
            ["customfield_10214=\uc6d4\ub3c4\uc2dc\uac04,customfield_10226=Allowed"],
            {"customfield_10214": "\uc6d4\ub3c4\uc2dc\uac04", "customfield_10226": "Allowed"},
        ),
        # Standard field key (non-customfield_ prefix) - supported after regex broadening
        (["summary=My Issue"], {"summary": "My Issue"}),
        # Mix of standard and custom fields in one string
        (
            ["summary=My Issue,projectKey=PROJ,customfield_10101=foo"],
            {"summary": "My Issue", "projectKey": "PROJ", "customfield_10101": "foo"},
        ),
        # Leading space before key (e.g. after a comma with a space) - key is stripped
        (
            ["customfield_10214=\uc6d4\ub3c4\uc2dc\uac04, customfield_10226=Allowed"],
            {"customfield_10214": "\uc6d4\ub3c4\uc2dc\uac04", "customfield_10226": "Allowed"},
        ),
    ],
)
def test_parse_custom_fields(custom_fields: list[str], expected: dict[str, Any]):
    """
    Given:
        - A list of strings of custom fields.
        - An expected list of dicts of custom fields.

    When:
        - Case A: Passing a list of 1 string with text type custom field to `parse_custom_fields`.
        - Case B: Passing a list of 2 strings, one with text type custom field, one with integer type custom field into
        `parse_custom_fields`.
        - Case C: Passing a list of 2 strings, one with text type custom field, one with integer type custom field with 0
        padding into `parse_custom_fields`.
        - Case D: Passing a list of 2 strings of text type custom fields into `parse_custom_fields`.
        - Case E: Passing a list of 2 strings of 1 text type custom field, 1 custom field with unexpected delimiter (:).
        - Case F: Passing a list of 1 string with text type custom field, 1 custom field with double '==' delimiter.
        - Case G: Passing an empty list.
        - Case H: Non-ASCII (Korean) value - previously silently dropped by \\w+ regex, now supported.
        - Case I: Value containing spaces.
        - Case J: Value containing hyphens and special characters.
        - Case K: Standard field key (non-customfield_ prefix) e.g. summary=My Issue.
        - Case L: Mix of standard and custom fields in one unsplit string.
        - Case M: Leading space before a key after a comma - key is stripped.

    Then:
        - Case A: A dictionary with 1 attribute is returned.
        - Case B: A dictionary with 1 attribute field, 1 integer custom field is returned.
        - Case C: A dictionary with 2 attributes fields is returned.
        - Case D: A dictionary with 2 attributes fields is returned.
        - Case E: A dictionary with 1 attribute field is returned (bad delimiter skipped).
        - Case F: A dictionary with 2 attributes; the '==' entry has value '=test' (everything after first '=').
        - Case G: An empty dictionary is returned.
        - Case H: A dictionary with the Korean value correctly parsed.
        - Case I: A dictionary with the space-containing value correctly parsed.
        - Case J: A dictionary with the special-char value correctly parsed.
        - Case K: A dictionary with the standard field key correctly parsed.
        - Case L: A dictionary with all three fields correctly parsed.
        - Case M: A dictionary with the leading-space key stripped and both fields parsed.
    """

    actual = parse_custom_fields(custom_fields)
    assert actual == expected


@pytest.mark.parametrize(
    "args, custom_fields, expected",
    [
        # Custom fields merged into existing args
        (
            {"summary": "My Issue", "projectKey": "PROJ"},
            {"customfield_10096": "test", "customfield_10040": 100},
            {"summary": "My Issue", "projectKey": "PROJ", "customfield_10096": "test", "customfield_10040": 100},
        ),
        # Custom fields merged into empty args
        (
            {},
            {"customfield_10096": "test", "customfield_10040": 100},
            {"customfield_10096": "test", "customfield_10040": 100},
        ),
        # Korean custom field value merged alongside named args (the customer's use case)
        (
            {"summary": "Test", "projectKey": "TEST1", "issueTypeName": "보안이벤트"},
            {"customfield_10214": "출발시간", "customfield_10226": "Allowed"},
            {"summary": "Test", "projectKey": "TEST1", "issueTypeName": "보안이벤트",
             "customfield_10214": "출발시간", "customfield_10226": "Allowed"},
        ),
    ],
)
def test_add_custom_fields(args: dict[str, Any], custom_fields: dict[str, Any], expected: dict[str, Any]):
    """
    Given:
        - A dictionary of arguments (named args like summary, projectKey).
        - A dictionary representing custom fields.
        - An expected merged dictionary.

    When:
        - Case A: Named args + custom fields are merged.
        - Case B: Empty args + custom fields are merged.
        - Case C: Korean custom field values alongside named args (the customer's use case from XSUP-75309).

    Then:
        - Case A: Custom fields are merged directly into args alongside named args.
        - Case B: Custom fields are the only entries in the result.
        - Case C: Korean values are preserved and merged correctly.
    """

    actual = add_custom_fields(args, custom_fields)

    assert actual == expected
