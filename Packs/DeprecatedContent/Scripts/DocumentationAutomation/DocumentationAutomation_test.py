import os
import demistomock as demisto


RETURN_ERROR_TARGET = 'DocumentationAutomation.return_error'


def test_get_yaml_obj(mocker):
    from DocumentationAutomation import get_yaml_obj
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)

    # sanity
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


def test_generate_commands_section():
    from DocumentationAutomation import generate_commands_section

    yml_data = {
        'script': {
            'commands': [
                {'deprecated': True,
                 'name': 'deprecated-cmd'},
                {'deprecated': False,
                 'name': 'non-deprecated-cmd'}
            ]
        }
    }

    section, errors = generate_commands_section(yml_data, {})

    expected_section = [
        '## Commands', '---',
        'You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.',
        'After you successfully execute a command, a DBot message appears in the War Room with the command details.',
        '1. non-deprecated-cmd', '### 1. non-deprecated-cmd', '---', ' ', '##### Required Permissions',
        '**FILL IN REQUIRED PERMISSIONS HERE**', '##### Base Command', '', '`non-deprecated-cmd`', '##### Input', '',
        'There are no input arguments for this command.', '', '##### Context Output', '',
        'There is no context output for this command.', '', '##### Command Example', '``` ```', '',
        '##### Human Readable Output', '', '']

    assert section == expected_section


def test_add_lines():
    from DocumentationAutomation import add_lines

    outputs = [
        add_lines('this is some free text.'),
        add_lines('1.this is numbered text.'),
        add_lines('this is multi line\nwithout numbers'),
        add_lines('1.this is multi line\n2.with numbers'),
        add_lines('12.this is multi line\n1234.with large numbers'),
    ]

    expected_values = [
        ['this is some free text.'],
        ['1.this is numbered text.'],
        ['this is multi line\nwithout numbers'],
        ['1.this is multi line', '2.with numbers'],
        ['12.this is multi line', '1234.with large numbers']
    ]

    for expected, out in zip(expected_values, outputs):
        assert out == expected
