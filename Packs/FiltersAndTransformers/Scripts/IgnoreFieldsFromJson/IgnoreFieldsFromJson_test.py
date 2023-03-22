import demistomock as demisto
import pytest

INPUTS = [
    ('{"a": "1", "b": "2", "c": "3"}', ["a"], {"b": "2", "c": "3"}),  # case removing valid input.V
    ('{"a": "1", "b": "2", "c": "3"}', ["d"], {"a": "1", "b": "2", "c": "3"}),  # case removing invalid input.
    ('{"a": "1", "b": "2", "c": "3"}', ["a", "b"], {"c": "3"}),  # case removing multiple inputs.
    ('{"a": "1", "b": "2", "c": "3"}', ["a", "b", "d"], {"c": "3"}),  # case removing multiple inputs, one invalid.
    ('{"a": "1", "b": "2", "c": "3"}', "a,b,c", {}),  # case removing all fields.
    ('{}', "a,b,c", {}),  # case removing fields from empty json. V
    ('{"a": "1", "b": "2", "c": "3"}', "", {"a": "1", "b": "2", "c": "3"}),  # case removing no fields from json.
    ({"a": "1", "b": "2", "c": "3"}, "", {"a": "1", "b": "2", "c": "3"}),  # case removing no fields from dict.
    ({"a": "1", "b": "2", "c": "3"}, ["a", "b"], {"c": "3"}),  # case removing multiple inputs from dict.

]


@pytest.mark.parametrize("json_obj, fields, expected", INPUTS)
def test_ignore_fields_json_obj(mocker, json_obj, fields, expected):
    from IgnoreFieldsFromJson import ignore_fields

    res = ignore_fields(json_obj, fields)
    assert res == expected


@pytest.mark.parametrize("value, fields, expected", INPUTS)
def test_ignore_fields_value(mocker, value, fields, expected):
    from IgnoreFieldsFromJson import ignore_fields

    res = ignore_fields(value, fields)
    assert res == expected


FAILED_INPUTS = [
    ('invalid json format', ["a"], 'invalid json format'),  # case removing from invalid json
]


@pytest.mark.parametrize("json_obj, fields, expected", FAILED_INPUTS)
def test_ignore_fields_fail_json_obj(mocker, json_obj, fields, expected):
    from IgnoreFieldsFromJson import ignore_fields

    debug_mock = mocker.patch.object(demisto, 'debug')
    res = ignore_fields(json_obj, fields)
    debug_mock.assert_called_once_with('Could not parse invalid json format to Json. Please insert a valid json format.')
    assert res == expected


@pytest.mark.parametrize("value, fields, expected", FAILED_INPUTS)
def test_ignore_fields_fail_value(mocker, value, fields, expected):
    from IgnoreFieldsFromJson import ignore_fields

    debug_mock = mocker.patch.object(demisto, 'debug')
    res = ignore_fields(value, fields)
    debug_mock.assert_called_once_with('Could not parse invalid json format to Json. Please insert a valid json format.')
    assert res == expected


def test_main_value_priority(mocker):
    from IgnoreFieldsFromJson import main

    mocker.patch.object(demisto, 'args', return_value={
        'value': {'a': 'b'},
        'json_obj': {'b': 'c'},
        'fields': []
    })

    expected = {'a': 'b'}

    mocker.patch.object(demisto, 'results')
    main()
    res = demisto.results.call_args[0][0]
    assert res == expected
