import SetAndHandleEmpty
import pytest
set_and_handle_empty = SetAndHandleEmpty.main


data_test_set_and_handle_empty_with_value = [
    ('key', 'value', {'key': 'value'}),
    ('key', '["val0", "val1", "val2"]', {'key': ['val0', 'val1', 'val2']}),
    ('key', '{"key_inside": "val_inside"}', {'key': {"key_inside": "val_inside"}}),
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
