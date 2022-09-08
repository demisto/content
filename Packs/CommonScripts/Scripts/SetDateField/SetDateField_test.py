from SetDateField import is_valid_field, get_custom_fields_from_incident, get_oob_fields_from_incident
import demistomock as demisto
import pytest


@pytest.mark.parametrize(
    "field_name, incident, expected",
    [
        ("name", demisto.incident(), True),
        ("bar", demisto.incident(), False),
        ("foo", demisto.incident(), False)
    ]
)
def test_is_valid_field(field_name, incident, expected):

    """
    Given:
        - A field name and an incident

    When:
        A) The field exists in incident
        B) The field doesn't exist in the incident or its custom fields
        C) The field exists in the custom fields

    Then:
        A) Field is valid
        B) Field is invalid
        C) Field is invalid
    """

    actual = is_valid_field(field_name, incident)
    assert actual == expected


@pytest.mark.parametrize(
    "incident, expected",
    [
        ({"CustomFields": {"foo": "bar", "goo": "baz"}, "account": ""}, ["foo", "goo"]),
        ({"name": "1", "CustomFields": {"foo": "bar"}}, ["foo"]),
        ({"name": "1"}, [])
    ]
)
def test_get_custom_fields_from_incident(incident, expected):

    """
    Given:
        - An incident

    When:
        A) Incident has 'foo' and 'goo' custom fields
        B) Incident has 'foo' in custom fields
        C) Incident doesn't have custom fields

    Then:
        A) 2 custom fields returned in list
        B) 1 custom field returned in list
        C) Empty list returned
    """

    actual = get_custom_fields_from_incident(incident)
    assert actual == expected


@pytest.mark.parametrize(
    "incident, expected",
    [
        ({"name": "a", "id": 1}, ["name", "id"]),
        ({"name": "a", "CustomFields": {"foo": "bar"}}, ["name"]),
        ({}, [])
    ]
)
def test_get_oob_fields_from_incident(incident, expected):

    """
    Given:
        - An incident

    When:
        A) Incident has 'name' and 'id' fields
        B) Incident has 'name' and custom fields
        C) Incident doesn't have any fields

    Then:
        A) 2 fields returned in list
        B) 1 field returned in list
        C) Empty list returned
    """

    actual = get_oob_fields_from_incident(incident)
    assert actual == expected
