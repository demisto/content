import os
import demistomock as demisto


RETURN_ERROR_TARGET = 'DocumentationAutomation.return_error'


def test_get_yaml_obj(mocker):
    from DocumentationAutomation import get_yaml_obj
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)

    # sanity
    print os.getcwd()
    file_path = os.path.join('test_data', 'ANYRUN_yml.txt')
    mocker.patch.object(demisto, 'getFilePath',
                        return_value={'path': file_path})
    data = get_yaml_obj('12345')
    # error count should not change
    assert return_error_mock.call_count == 0
    # call_args last call with a tuple of args list and kwargs
    assert data['commonfields']['id'] == 'ANYRUN'

    # invalid yml
    mocker.patch.object(demisto, 'getFilePath',
                        return_value={'path': os.path.join('test_data', 'not_yml_file.txt')})
    get_yaml_obj('234')
    assert return_error_mock.call_count == 1
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == 'Failed to open integration file'

    # no such file
    mocker.patch.object(demisto, 'getFilePath', side_effect=ValueError('no such file'))
    get_yaml_obj('234')
    assert return_error_mock.call_count == 2
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == 'Failed to open integration file'


def test_extract_command():
    from DocumentationAutomation import extract_command

    # no args
    cmd, args = extract_command('!no-args-command')
    assert cmd == '!no-args-command'
    assert args == {}

    # sanity
    cmd, args = extract_command('!command ip=8.8.8.8')
    expected = {'ip': '8.8.8.8'}
    assert cmd == '!command'

    assert len(expected) == len(args)
    for k, v in expected.items():
        assert args[k] == v

    # edge cases
    cmd, args = extract_command('!command SomeParam=8.8.8.8 dash-arg="args" special_chars="1qazxsw2 EW3- *3d" '
                                'backTick=`hello "hello" \'hello\'` triple_quotes="""this is a multi quotes"""')
    expected = {
        'SomeParam': '8.8.8.8',
        'dash-arg': 'args',
        'special_chars': '1qazxsw2 EW3- *3d',
        'backTick': 'hello "hello" \'hello\'',
        'triple_quotes': 'this is a multi quotes'
    }
    assert cmd == '!command'

    assert len(expected) == len(args)
    for k, v in expected.items():
        assert args[k] == v

    cmd, args = extract_command('!command SomeParam="""hello\nthis is multiline"""')
    expected = {
        'SomeParam': 'hello\nthis is multiline',
    }
    assert cmd == '!command'

    assert len(expected) == len(args)
    for k, v in expected.items():
        assert args[k] == v
