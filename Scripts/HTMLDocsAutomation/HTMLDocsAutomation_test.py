from CommonServerPython import *

import os
import demistomock as demisto


RETURN_ERROR_TARGET = 'HTMLDocsAutomation.return_error'


def test_get_yaml_obj(mocker):
    from HTMLDocsAutomation import get_yaml_obj
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
    assert err_msg == 'Failed to open integration file: not a yml file'

    # no such file
    mocker.patch.object(demisto, 'getFilePath', side_effect=ValueError('no such file'))
    get_yaml_obj('234')
    assert return_error_mock.call_count == 2
    # call_args last call with a tuple of args list and kwargs
    err_msg = return_error_mock.call_args[0][0]
    assert err_msg == 'Failed to open integration file: no such file'


def test_extract_command():
    from HTMLDocsAutomation import extract_command

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
    from HTMLDocsAutomation import generate_commands_section

    yml_data = {
        'script': {
            'commands': [
                {'deprecated': True,
                 'name': 'deprecated-cmd',
                 'description': 'desc'},
                {'deprecated': False,
                 'name': 'non-deprecated-cmd',
                 'description': 'desc1'},
                {'name': 'non-deprecated-cmd2',
                 'description': 'desc2.'}
            ]
        }
    }

    section, errors = generate_commands_section(yml_data, {}, True)

    expected_section = '''<h2>Commands</h2>
<p>
  You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li><a href="#non-deprecated-cmd" target="_self">desc1: non-deprecated-cmd</a></li>
  <li><a href="#non-deprecated-cmd2" target="_self">desc2: non-deprecated-cmd2</a></li>
</ol>
<h3 id="non-deprecated-cmd">1. non-deprecated-cmd</h3>
<hr>
<p>desc1</p>
<h5>Base Command</h5>
<p>
  <code>non-deprecated-cmd</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>
<h5>Input</h5>
There are no input arguments for this command.
<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code> </code>
</p>

<h5>Human Readable Output</h5>
<p>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="non-deprecated-cmd2">2. non-deprecated-cmd2</h3>
<hr>
<p>desc2.</p>
<h5>Base Command</h5>
<p>
  <code>non-deprecated-cmd2</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>
<h5>Input</h5>
There are no input arguments for this command.
<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code> </code>
</p>

<h5>Human Readable Output</h5>
<p>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
'''

    assert section == expected_section
    assert len(errors) == 2  # no example for both commands


def test_to_html_table():
    from HTMLDocsAutomation import to_html_table
    data = [
        ['hello', 'hello', 'hello'],
        ['world', 'world', 'world'],
        ['!', '!', '!'],
    ]
    expected = '''<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>header1</strong></th>
      <th><strong>header2</strong></th>
      <th><strong>header3</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>hello</td>
      <td>hello</td>
      <td>hello</td>
    </tr>
    <tr>
      <td>world</td>
      <td>world</td>
      <td>world</td>
    </tr>
    <tr>
      <td>!</td>
      <td>!</td>
      <td>!</td>
    </tr>
  </tbody>
</table>
'''
    assert to_html_table(['header1', 'header2', 'header3'], data) == expected


def test_human_readable_example_to_html():
    from HTMLDocsAutomation import human_readable_example_to_html
    data = [
        {
            'header1': 'hello',
            'header2': 'hello',
        },
        {
            'header1': 'world',
            'header2': 'world',
        },
    ]

    md = tableToMarkdown('Title', data, headers=['header1', 'header2'])
    expected = '''<h3>Title</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>header1</strong></th>
      <th><strong>header2</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> hello </td>
      <td> hello </td>
    </tr>
    <tr>
      <td> world </td>
      <td> world </td>
    </tr>
  </tbody>
</table>
'''
    assert human_readable_example_to_html(md) == expected

    md = md + '\n# Headline\nsome text\nanother line of text\n' + md
    expected = expected + '\n<h1>Headline</h1>\n<p>\nsome text\nanother line of text\n</p>\n' + expected
    assert human_readable_example_to_html(md) == expected

#     md = '''Key | Value
# - | -
# city | Mountain View
# country | US
# hostname | dns.google
# ip | 8.8.8.8
# loc | 37.3860,-122.0838
# org | AS15169 Google LLC
# postal | 94035
# readme | https://ipinfo.io/missingauth
# region | California
# {"lat": 37.386, "lng": -122.0838}'''
#
#     print(human_readable_example_to_html(md))
