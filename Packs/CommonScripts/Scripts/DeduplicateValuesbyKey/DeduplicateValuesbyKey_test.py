
import pytest


def test_generate_unique_values_from_objects():
    from DeduplicateValuesbyKey import generate_unique_values_from_objects
    objects = [
        {
            "key": "value1",
            "value": "value1"
        },
        {
            "key": "value1",
            "value": "value2"
        },
        {
            "key": "value2",
            "value": "value3"
        },
        {
            "key": "value2",
            "value": "value4"
        },
        {
            "key": "value3",
            "value": "value5"
        },
        {
            "key": "value3",
            "value": "value6"
        }]
    values = generate_unique_values_from_objects(objects, "key", False)
    assert set(values) == set(["value1", "value2", "value3"])


def test_generate_unique_values_from_objects_with_none():
    from DeduplicateValuesbyKey import generate_unique_values_from_objects
    objects = [
        {
            "key": "value1",
            "value": "value1"
        },
        {
            "key": "value1",
            "value": "value2"
        },
        {
            "key": "value2",
            "value": "value3"
        },
        {
            "key": "value2",
            "value": "value4"
        },
        {
            "key": "value3",
            "value": "value5"
        },
        {
            "key": "None_value",
            "value": None
        }]
    values = generate_unique_values_from_objects(objects, "key", True)
    assert set(values) == set(["None_value", "value1", "value2", "value3"])


def test_generate_unique_values_from_objects_fail():
    from DeduplicateValuesbyKey import generate_unique_values_from_objects

    with pytest.raises(SystemExit):
        generate_unique_values_from_objects([], "key", True)
