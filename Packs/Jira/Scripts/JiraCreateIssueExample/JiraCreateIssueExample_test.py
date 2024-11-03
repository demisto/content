from JiraCreateIssueExample import validate_date_field, parse_custom_fields, add_custom_fields
import pytest
from typing import Any


@pytest.mark.parametrize("due_date", [
    ("2022-01-01"),
    ("2023-01-31"),
    ("2024-02-29")
])
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


@pytest.mark.parametrize("due_date", [
    ("2022-31-31"),
    ("202-51-XY"),
    ("ABC")
])
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


@pytest.mark.parametrize("due_date", [
    ("2022-12-12T13:00:00"),
    ("2022-12-12Z12")
])
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


@pytest.mark.parametrize("custom_fields, expected", [
    (["customfield_10096=test"], {"customfield_10096": "test"}),
    (["customfield_10096=test", "customfield_10040=100"], {"customfield_10096": "test", "customfield_10040": 100}),
    (["customfield_10096=test", "customfield_10040=0100"], {"customfield_10096": "test", "customfield_10040": "0100"}),
    (["customfield_10096=test", "customfield_10040=A100"], {"customfield_10096": "test", "customfield_10040": "A100"}),
    (["customfield_10096:test", "customfield_10040=A100"], {"customfield_10040": "A100"}),
    (["customfield_10096==test", "customfield_10040=A100"], {"customfield_10040": "A100"}),
    ([], {}),
])
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
        - Case F: Passing a list of 1 string wit text type custom field, 1 custom field with unexpected delimiter (==).
        - Case G: Passing an empty list.

    Then:
        - Case A: A dictionary with 1 attribute is returned.
        - Case B: A dictionary with 1 attribute field, 1 integer custom field is returned.
        - Case C: A dictionary with 2 attributes fields is returned.
        - Case D: A dictionary with 2 attributes fields is returned.
        - Case E: A dictionary with 1 attribute field is returned.
        - Case F: A dictionary with 1 attribute field is returned.
        - Case G: An empty dictionary is returned.
    """

    actual = parse_custom_fields(custom_fields)
    assert actual == expected


@pytest.mark.parametrize("args, custom_fields, expected", [
    (
        {"arg1": "val1", "arg2": 1},
        {"customfield_10096": "test", "customfield_10040": 100},
        {"arg1": "val1", "arg2": 1, "issueJson": {"fields": {"customfield_10096": "test", "customfield_10040": 100}}}
    ),
    (
        {},
        {"customfield_10096": "test", "customfield_10040": 100},
        {"issueJson": {"fields": {"customfield_10096": "test", "customfield_10040": 100}}}
    )
])
def test_add_custom_fields(args: dict[str, Any], custom_fields: dict[str, Any], expected):
    """
    Given:
        - A dictionary of arguments.
        - A dictionary representing custom fields.
        - An expected dictionary result.

    When:
        - Case A: Passing a dictionary with 2 attributes and another dictionary with 2 attributes into `add_custom_fields`.
        - Case B: Passing a dictionary with 2 attributes and an empty dictionary into `add_custom_fields`.
        - Case C: Passing a empty dictionary and another one with 2 attributes into `add_custom_fields`.
    Then:
        - Case A: The resulting dictionary will have 4 attributes with `issueJson` root.
        - Case B: The resulting dictionary will be identical to the first one supplied.
        - Case C: The resulting dictionary will have 2 attributes with `issueJson` root.
    """

    actual = add_custom_fields(args, custom_fields)

    assert actual == expected
