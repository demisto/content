from JiraCreateIssueExample import DATE_FORMAT, validate_date_field, parse_custom_fields, add_custom_fields,\
    rm_custom_field_from_args
import pytest


@pytest.mark.parametrize("due_date", [
    ("2022-01-01"),
    ("2022-12-12T13:00:00")
])
def test_validate_date_field_data_remains(due_date):
    """
    Given:
        - A date.

    When:
        - Case A: The date is in valid format.
        - Case B: The date has a time included

    Then:
        - Case A: No exception is thrown.
        - Case B: A `ValueError` exception is thrown.
    """

    try:
        validate_date_field(due_date)
    except ValueError as ve:
        assert "unconverted data remains" in str(ve)


@pytest.mark.parametrize("due_date", [
    ("2022-1-1"),
    ("2022-31-31")
])
def test_validate_date_field_format(due_date):

    """
    Given:
        - A date.

    When:
        - Case A: The date is in valid format.
        - Case B: The date has an invalid month.

    Then:
        - Case A: No exception is thrown.
        - Case B: A `ValueError` exception is thrown.
    """

    try:
        validate_date_field(due_date)
    except ValueError as ve:
        assert f"time data '{due_date}' does not match format '{DATE_FORMAT}'" in str(ve)


@pytest.mark.parametrize("custom_fields, expected", [
    (["customfield_10096=test"], {"customfield_10096": "test"}),
    (["customfield_10096=test", "customfield_10040=100"], {"customfield_10096": "test", "customfield_10040": 100}),
    (["customfield_10096=test", "customfield_10040=0100"], {"customfield_10096": "test", "customfield_10040": "0100"}),
    (["customfield_10096=test", "customfield_10040=A100"], {"customfield_10096": "test", "customfield_10040": "A100"}),
    (["customfield_10096:test", "customfield_10040=A100"], {"customfield_10040": "A100"}),
    (["customfield_10096==test", "customfield_10040=A100"], {"customfield_10040": "A100"}),
    ([], {}),
])
def test_parse_custom_fields(custom_fields, expected):

    """
    Given:
        - A list of strings of custom fields.
        - An expected list of dicts of custom fields.

    When:
        - Case A: 1 text custom field.
        - Case B: 1 text custom field, 1 integer custom field.
        - Case C: 1 text custom field, 1 integer custom field with 0 padding.
        - Case D: 2 text custom fields.
        - Case E: 1 text custom field, 1 custom field with unexpected delimiter (:).
        - Case E: 1 text custom field, 1 custom field with unexpected delimiter (==).
        - Case F: Empty custom field list.

    Then:
        - Case A: 1 text custom field returned.
        - Case B: 1 text custom field, 1 integer custom field returned.
        - Case C: 2 text custom fields returned.
        - Case D: 2 text custom fields returned.
        - Case E: 1 text custom field returned.
        - Case F: 1 text custom field returned.
        - Case G: Empty dict returned.
    """

    actual = parse_custom_fields(custom_fields)

    assert len(actual) == len(expected)
    assert actual == expected


@pytest.mark.parametrize("args, custom_fields, expected", [
    ({"arg1": "val1", "arg2": 1}, {"customfield_10096": "test", "customfield_10040": 100},
        {"arg1": "val1", "arg2": 1, "issueJson": {"fields": {"customfield_10096": "test", "customfield_10040": 100}}}),
    ({"arg1": "val1", "arg2": 1}, {},
        {"arg1": "val1", "arg2": 1}),
    ({}, {"customfield_10096": "test", "customfield_10040": 100},
        {"issueJson": {"fields": {"customfield_10096": "test", "customfield_10040": 100}}})
])
def test_add_custom_fields(args, custom_fields, expected):
    """
    Given:
        - A dictionary of arguments.
        - A list of dictionaries representing custom fields.

    When:
        - The argument dictionary has 2 attributes and the custom fields list has 2 custom field dictionaries.
        - The argument dictionary has 2 attributes and the custom fields list is empty.
        - The argument dictionary is empty and the list has 2 custom field dictionaries.
    Then:
        - The resulting dictionary will have 4 attributes.
        - The resulting dictionary will have 2 attributes.
        - The resulting dictionary will have 2 attributes.
    """

    actual = add_custom_fields(args, custom_fields)

    assert len(actual) == len(expected)
    assert actual == expected


@pytest.mark.parametrize("args, expected", [
    ({"arg1:": "val1", "arg2": "val2", "customFields": "customfield_10040=100"}, {"arg1:": "val1", "arg2": "val2"}),
    ({"arg1:": "val1", "arg2": "val2"}, {"arg1:": "val1", "arg2": "val2"})
])
def test_rm_custom_field_from_args(args, expected):

    try:
        actual = rm_custom_field_from_args(args)

        assert actual == expected
    except KeyError as ke:
        assert "customFields" in str(ke)
