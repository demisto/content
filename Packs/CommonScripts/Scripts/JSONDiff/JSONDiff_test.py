import pytest
from unittest.mock import MagicMock
from JSONDiff import compare_jsons

# Mock demisto
demisto = MagicMock()


def test_compare_jsons_simple():
    """
    When: Comparing two JSON objects with simple key-value pairs.
    Given: json1 = {"a": 1, "b": 2}, json2 = {"a": 1, "c": 3}.
    Then: The result should indicate 'b' was removed and 'c' was added.
    """
    json1 = {"a": 1, "b": 2}
    json2 = {"a": 1, "c": 3}
    result = compare_jsons(json1, json2)
    assert result == {
        "changed": [],
        "added": [{"field": "c", "value": 3}],
        "removed": [{"field": "b", "value": 2}]
    }


def test_compare_jsons_nested():
    """
    When: Comparing two nested JSON objects.
    Given: json1 = {"a": {"b": 1, "c": 2}}, json2 = {"a": {"b": 1, "d": 3}}.
    Then: The result should indicate 'c' was removed and 'd' was added inside 'a'.
    """
    json1 = {"a": {"b": 1, "c": 2}}
    json2 = {"a": {"b": 1, "d": 3}}
    result = compare_jsons(json1, json2)
    assert result == {
        "changed": [],
        "added": [{"field": "a.d", "value": 3}],
        "removed": [{"field": "a.c", "value": 2}]
    }


def test_compare_jsons_changed():
    """
    When: Comparing two JSON objects with a changed value.
    Given: json1 = {"a": 1, "b": {"c": 2}}, json2 = {"a": 2, "b": {"c": 2}}.
    Then: The result should indicate that 'a' changed from 1 to 2.
    """
    json1 = {"a": 1, "b": {"c": 2}}
    json2 = {"a": 2, "b": {"c": 2}}
    result = compare_jsons(json1, json2)
    assert result == {
        "changed": [
            {"field": "a", "from": 1, "to": 2}
        ],
        "added": [],
        "removed": []
    }


@pytest.mark.parametrize("json1,json2,expected", [
    ("""
    When: Comparing lists within JSON objects.
    Given: json1 = {"a": [1, 2]}, json2 = {"a": [1, 3]}.
    Then: The result should indicate that 'a' changed from [1,2] to [1,3].
    """, {"a": [1, 2]}, {"a": [1, 3]}, {"changed": [{"field": "a", "from": [1, 2], "to": [1, 3]}], "added": [], "removed": []}),
    ("""
    When: Comparing JSON objects where a None value is replaced.
    Given: json1 = {"a": None}, json2 = {"a": 1}.
    Then: The result should indicate that 'a' changed from None to 1.
    """, {"a": None}, {"a": 1}, {"changed": [{"field": "a", "from": None, "to": 1}], "added": [], "removed": []}),
    ("""
    When: Comparing boolean values in JSON.
    Given: json1 = {"a": True}, json2 = {"a": False}.
    Then: The result should indicate that 'a' changed from True to False.
    """, {"a": True}, {"a": False}, {"changed": [{"field": "a", "from": True, "to": False}], "added": [], "removed": []}),
])
def test_compare_jsons_various_types(json1, json2, expected):
    assert compare_jsons(json1, json2) == expected
