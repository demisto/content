import SetAndHandleEmpty
import pytest
set_and_handle_empty = SetAndHandleEmpty.main


data_test_set_and_handle_empty_with_value = [
    ('key', 'value', {'key': 'value'}),
    ('key', '["val0", "val1", "val2"]', {'key': ['val0', 'val1', 'val2']}),
    ('key', '{"key_inside": "val_inside"}', {'key': {"key_inside": "val_inside"}}),
    ('key', ["val0", "val1", "val2"], {'key': ['val0', 'val1', 'val2']}),
    ('key', {'key_inside': 'val_inside'}, {'key': {'key_inside': 'val_inside'}}),
]


@pytest.mark.parametrize('input_key, input_value, expected_output', data_test_set_and_handle_empty_with_value)
def test_set_and_handle_empty_with_value(input_key, input_value, expected_output, mocker):
    mocker.patch.object(SetAndHandleEmpty.demisto, 'args', return_value={'key': input_key, 'value': input_value})
    output = mocker.patch('SetAndHandleEmpty.return_outputs')
    set_and_handle_empty()
    assert output.call_args.args[1] == expected_output


data_test_set_and_handle_empty_with_value_and_stringify = [
    ('key', 'value', {'key': 'value'}),
    ('key', '["val0", "val1", "val2"]', {'key': '["val0", "val1", "val2"]'}),
    ('key', '{"key_inside": "val_inside"}', {'key': '{"key_inside": "val_inside"}'}),
    ('key', ["val0", "val1", "val2"], {'key': "['val0', 'val1', 'val2']"}),
    ('key', {"key_inside": "val_inside"}, {'key': "{'key_inside': 'val_inside'}"}),
]


@pytest.mark.parametrize('input_key, input_value, expected_output',
                         data_test_set_and_handle_empty_with_value_and_stringify)
def test_set_and_handle_empty_with_value_and_stringify(input_key, input_value, expected_output, mocker):
    args = {'key': input_key, 'value': input_value, 'stringify': 'true'}
    mocker.patch.object(SetAndHandleEmpty.demisto, 'args', return_value=args)
    output = mocker.patch('SetAndHandleEmpty.return_outputs')
    set_and_handle_empty()
    assert output.call_args.args[1] == expected_output


test_set_and_handle_empty_without_value = [None, '']


@pytest.mark.parametrize('value', test_set_and_handle_empty_without_value)
def test_set_and_handle_empty_without_value(value, mocker):
    mocker.patch.object(SetAndHandleEmpty.demisto, 'args', return_value={'key': 'test', 'value': value})
    output = mocker.patch('SetAndHandleEmpty.return_outputs')
    set_and_handle_empty()
    assert output.call_args.args[1].get('test') is None


data_test_set_and_handle_empty_append_arg = [
    ('true', {'key': 'test', 'value': 'test'}, False),
    (None, {'key': 'test', 'value': 'test'}, False),
    ('false', {'key': 'test', 'value': 'test'}, True),
    ('false', {'key': 'test', 'value': ''}, False),
    ('false', {'key': 'test', 'value': None}, False)
]


@pytest.mark.parametrize('append, args, expected_delete', data_test_set_and_handle_empty_append_arg)
def test_set_and_handle_empty_append_arg(append, args, expected_delete, mocker):
    args.update({'append': append})
    mocker.patch.object(SetAndHandleEmpty.demisto, 'args', return_value=args)
    output = mocker.patch.object(SetAndHandleEmpty.demisto, 'executeCommand')
    set_and_handle_empty()
    assert bool(output.call_args) == bool(expected_delete)


data_test_get_value = [
    ({}, {}),
    ('{}', {}),
    ('[]', []),
    (u'{}', {}),
    (b'{"test": "test"}', {'test': 'test'}),
    (None, None),
    ('', ''),
    (False, False),
    ('{"test": "test"}', {'test': 'test'}),
    ('["test", "test"]', ['test', 'test']),
    ({"test": "test"}, {'test': 'test'}),
    (["test", "test"], ['test', 'test']),
]


@pytest.mark.parametrize('value, expected_output', data_test_get_value)
def test_get_value(value, expected_output):
    output = SetAndHandleEmpty.get_value(value)
    assert output == expected_output
