# -*- coding: utf-8 -*-
import demistomock as demisto
import copy
import json
import re
import os
import sys
import requests
from pytest import raises, mark
import pytest

from CommonServerPython import xml2json, json2xml, entryTypes, formats, tableToMarkdown, underscoreToCamelCase, \
    flattenCell, date_to_timestamp, datetime, camelize, pascalToSpace, argToList, \
    remove_nulls_from_dictionary, is_error, get_error, hash_djb2, fileResult, is_ip_valid, get_demisto_version, \
    IntegrationLogger, parse_date_string, IS_PY3, DebugLogger, b64_encode, parse_date_range, return_outputs, \
    argToBoolean, ipv4Regex, ipv4cidrRegex, ipv6cidrRegex, ipv6Regex, batch, FeedIndicatorType, \
    encode_string_results, safe_load_json, remove_empty_elements, aws_table_to_markdown, is_demisto_version_ge, \
    appendContext, auto_detect_indicator_type, handle_proxy, get_demisto_version_as_str, get_x_content_info_headers,\
    url_to_clickable_markdown

try:
    from StringIO import StringIO
except ImportError:
    # Python 3
    from io import StringIO  # noqa

INFO = {'b': 1,
        'a': {
            'safd': 3,
            'b': [
                {'c': {'d': 432}, 'd': 2},
                {'c': {'f': 1}},
                {'b': 1234},
                {'c': {'d': 4567}},
                {'c': {'d': 11}},
                {'c': {'d': u'asdf'}}],
            'c': {'d': 10},
        }
        }


@pytest.fixture()
def clear_version_cache():
    """
    Clear the version cache at end of the test (in case we mocked demisto.serverVersion)
    """
    yield
    get_demisto_version._version = None


def test_xml():
    import json

    xml = b"<work><employee><id>100</id><name>foo</name></employee><employee><id>200</id><name>goo</name>" \
          b"</employee></work>"
    jsonExpected = '{"work": {"employee": [{"id": "100", "name": "foo"}, {"id": "200", "name": "goo"}]}}'

    jsonActual = xml2json(xml)
    assert jsonActual == jsonExpected, "expected\n" + jsonExpected + "\n to equal \n" + jsonActual

    jsonDict = json.loads(jsonActual)
    assert jsonDict['work']['employee'][0]['id'] == "100", 'id of first employee must be 100'
    assert jsonDict['work']['employee'][1]['name'] == "goo", 'name of second employee must be goo'

    xmlActual = json2xml(jsonActual)
    assert xmlActual == xml, "expected:\n{}\nto equal:\n{}".format(xml, xmlActual)


def toEntry(table):
    return {

        'Type': entryTypes['note'],
        'Contents': table,
        'ContentsFormat': formats['table'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': table
    }


DATA = [
    {
        'header_1': 'a1',
        'header_2': 'b1',
        'header_3': 'c1'
    },
    {
        'header_1': 'a2',
        'header_2': 'b2',
        'header_3': 'c2'
    },
    {
        'header_1': 'a3',
        'header_2': 'b3',
        'header_3': 'c3'
    }
]

TABLE_TO_MARKDOWN_ONLY_DATA_PACK = [
    (
        DATA,
        '''### tableToMarkdown test
|header_1|header_2|header_3|
|---|---|---|
| a1 | b1 | c1 |
| a2 | b2 | c2 |
| a3 | b3 | c3 |
'''
    ),
    (
        [
            {
                'header_1|with_pipe': 'a1',
                'header_2': 'b1',
            },
            {
                'header_1|with_pipe': 'a2',
                'header_2': 'b2',
            }
        ],
        '''### tableToMarkdown test
|header_1\\|with_pipe|header_2|
|---|---|
| a1 | b1 |
| a2 | b2 |
'''
    )
]

DATA_WITH_URLS =  [(
        [
            {
            'header_1': 'a1',
            'url1': 'b1',
            'url2': 'c1'
            },
            {
            'header_1': 'a2',
            'url1': 'b2',
            'url2': 'c2'
            },
            {
            'header_1': 'a3',
            'url1': 'b3',
            'url2': 'c3'
            }
        ],
'''### tableToMarkdown test
|header_1|url1|url2|
|---|---|---|
| a1 | [b1](b1) | [c1](c1) |
| a2 | [b2](b2) | [c2](c2) |
| a3 | [b3](b3) | [c3](c3) |
'''
    )]

COMPLEX_DATA_WITH_URLS = [(
    [
    {'data':
         {'id': '1',
          'result':
              {'files':
                  [
                      {
                          'filename': 'name',
                          'size': 0,
                          'url': 'url'
                      }
                  ]
              },
          'links': ['link']
          }
     },
    {'data':
        {'id': '2',
            'result':
            {'files':
               [
                   {
                       'filename': 'name',
                       'size': 0,
                       'url': 'url'
                    }
               ]
            },
            'links': ['link']
         }
     }
],
    [
    {'data':
         {'id': '1',
          'result':
              {'files':
                  [
                      {
                          'filename': 'name',
                          'size': 0,
                          'url': '[url](url)'
                      }
                  ]
              },
          'links': ['[link](link)']
          }
     },
    {'data':
        {'id': '2',
            'result':
            {'files':
               [
                   {
                       'filename': 'name',
                       'size': 0,
                       'url': '[url](url)'
                    }
               ]
            },
            'links': ['[link](link)']
         }
     }
])]


@pytest.mark.parametrize('data, expected_table', TABLE_TO_MARKDOWN_ONLY_DATA_PACK)
def test_tbl_to_md_only_data(data, expected_table):
    # sanity
    table = tableToMarkdown('tableToMarkdown test', data)

    assert table == expected_table


def test_tbl_to_md_header_transform_underscoreToCamelCase():
    # header transform
    table = tableToMarkdown('tableToMarkdown test with headerTransform', DATA,
                            headerTransform=underscoreToCamelCase)
    expected_table = '''### tableToMarkdown test with headerTransform
|Header1|Header2|Header3|
|---|---|---|
| a1 | b1 | c1 |
| a2 | b2 | c2 |
| a3 | b3 | c3 |
'''
    assert table == expected_table


def test_tbl_to_md_multiline():
    # escaping characters: multiline + md-chars
    data = copy.deepcopy(DATA)
    for i, d in enumerate(data):
        d['header_2'] = 'b%d.1\nb%d.2' % (i + 1, i + 1,)
        d['header_3'] = 'c%d|1' % (i + 1,)

    table = tableToMarkdown('tableToMarkdown test with multiline', data)
    expected_table = '''### tableToMarkdown test with multiline
|header_1|header_2|header_3|
|---|---|---|
| a1 | b1.1<br>b1.2 | c1\\|1 |
| a2 | b2.1<br>b2.2 | c2\\|1 |
| a3 | b3.1<br>b3.2 | c3\\|1 |
'''
    assert table == expected_table


def test_tbl_to_md_url():
    # url + empty data
    data = copy.deepcopy(DATA)
    for i, d in enumerate(data):
        d['header_3'] = '[url](https:\\demisto.com)'
        d['header_2'] = None
    table_url_missing_info = tableToMarkdown('tableToMarkdown test with url and missing info', data)
    expected_table_url_missing_info = '''### tableToMarkdown test with url and missing info
|header_1|header_2|header_3|
|---|---|---|
| a1 |  | [url](https:\\demisto.com) |
| a2 |  | [url](https:\\demisto.com) |
| a3 |  | [url](https:\\demisto.com) |
'''
    assert table_url_missing_info == expected_table_url_missing_info


def test_tbl_to_md_single_column():
    # single column table
    table_single_column = tableToMarkdown('tableToMarkdown test with single column', DATA, ['header_1'])
    expected_table_single_column = '''### tableToMarkdown test with single column
|header_1|
|---|
| a1 |
| a2 |
| a3 |
'''
    assert table_single_column == expected_table_single_column


def test_is_ip_valid():
    valid_ip_v6 = "FE80:0000:0000:0000:0202:B3FF:FE1E:8329"
    valid_ip_v6_b = "FE80::0202:B3FF:FE1E:8329"
    invalid_ip_v6 = "KKKK:0000:0000:0000:0202:B3FF:FE1E:8329"
    valid_ip_v4 = "10.10.10.10"
    invalid_ip_v4 = "10.10.10.9999"
    invalid_not_ip_with_ip_structure = "1.1.1.1.1.1.1.1.1.1.1.1.1.1.1"
    not_ip = "Demisto"
    assert not is_ip_valid(valid_ip_v6)
    assert is_ip_valid(valid_ip_v6, True)
    assert is_ip_valid(valid_ip_v6_b, True)
    assert not is_ip_valid(invalid_ip_v6, True)
    assert not is_ip_valid(not_ip, True)
    assert is_ip_valid(valid_ip_v4)
    assert not is_ip_valid(invalid_ip_v4)
    assert not is_ip_valid(invalid_not_ip_with_ip_structure)


def test_tbl_to_md_list_values():
    # list values
    data = copy.deepcopy(DATA)
    for i, d in enumerate(data):
        d['header_3'] = [i + 1, 'second item']
        d['header_2'] = 'hi'

    table_list_field = tableToMarkdown('tableToMarkdown test with list field', data)
    expected_table_list_field = '''### tableToMarkdown test with list field
|header_1|header_2|header_3|
|---|---|---|
| a1 | hi | 1,<br>second item |
| a2 | hi | 2,<br>second item |
| a3 | hi | 3,<br>second item |
'''
    assert table_list_field == expected_table_list_field


def test_tbl_to_md_empty_fields():
    # all fields are empty
    data = [
        {
            'a': None,
            'b': None,
            'c': None,
        } for _ in range(3)
    ]
    table_all_none = tableToMarkdown('tableToMarkdown test with all none fields', data)
    expected_table_all_none = '''### tableToMarkdown test with all none fields
|a|b|c|
|---|---|---|
|  |  |  |
|  |  |  |
|  |  |  |
'''
    assert table_all_none == expected_table_all_none

    # all fields are empty - removed
    table_all_none2 = tableToMarkdown('tableToMarkdown test with all none fields2', data, removeNull=True)
    expected_table_all_none2 = '''### tableToMarkdown test with all none fields2
**No entries.**
'''
    assert table_all_none2 == expected_table_all_none2


def test_tbl_to_md_header_not_on_first_object():
    # header not on first object
    data = copy.deepcopy(DATA)
    data[1]['extra_header'] = 'sample'
    table_extra_header = tableToMarkdown('tableToMarkdown test with extra header', data,
                                         headers=['header_1', 'header_2', 'extra_header'])
    expected_table_extra_header = '''### tableToMarkdown test with extra header
|header_1|header_2|extra_header|
|---|---|---|
| a1 | b1 |  |
| a2 | b2 | sample |
| a3 | b3 |  |
'''
    assert table_extra_header == expected_table_extra_header


def test_tbl_to_md_no_header():
    # no header
    table_no_headers = tableToMarkdown('tableToMarkdown test with no headers', DATA,
                                       headers=['no', 'header', 'found'], removeNull=True)
    expected_table_no_headers = '''### tableToMarkdown test with no headers
**No entries.**
'''
    assert table_no_headers == expected_table_no_headers


def test_tbl_to_md_dict_value():
    # dict value
    data = copy.deepcopy(DATA)
    data[1]['extra_header'] = {'sample': 'qwerty', 'sample2': 'asdf'}
    table_dict_record = tableToMarkdown('tableToMarkdown test with dict record', data,
                                        headers=['header_1', 'header_2', 'extra_header'])
    expected_dict_record = '''### tableToMarkdown test with dict record
|header_1|header_2|extra_header|
|---|---|---|
| a1 | b1 |  |
| a2 | b2 | sample: qwerty<br>sample2: asdf |
| a3 | b3 |  |
'''
    assert table_dict_record == expected_dict_record


def test_tbl_to_md_string_header():
    # string header (instead of list)
    table_string_header = tableToMarkdown('tableToMarkdown string header', DATA, 'header_1')
    expected_string_header_tbl = '''### tableToMarkdown string header
|header_1|
|---|
| a1 |
| a2 |
| a3 |
'''
    assert table_string_header == expected_string_header_tbl


def test_tbl_to_md_list_of_strings_instead_of_dict():
    # list of string values instead of list of dict objects
    table_string_array = tableToMarkdown('tableToMarkdown test with string array', ['foo', 'bar', 'katz'], ['header_1'])
    expected_string_array_tbl = '''### tableToMarkdown test with string array
|header_1|
|---|
| foo |
| bar |
| katz |
'''
    assert table_string_array == expected_string_array_tbl


def test_tbl_to_md_list_of_strings_instead_of_dict_and_string_header():
    # combination: string header + string values list
    table_string_array_string_header = tableToMarkdown('tableToMarkdown test with string array and string header',
                                                       ['foo', 'bar', 'katz'], 'header_1')
    expected_string_array_string_header_tbl = '''### tableToMarkdown test with string array and string header
|header_1|
|---|
| foo |
| bar |
| katz |
'''
    assert table_string_array_string_header == expected_string_array_string_header_tbl


def test_tbl_to_md_dict_with_special_character():
    data = {
        'header_1': u'foo',
        'header_2': [u'\xe2.rtf']
    }
    table_with_character = tableToMarkdown('tableToMarkdown test with special character', data)
    expected_string_with_special_character = '''### tableToMarkdown test with special character
|header_1|header_2|
|---|---|
| foo | â.rtf |
'''
    assert table_with_character == expected_string_with_special_character


def test_tbl_to_md_header_with_special_character():
    data = {
        'header_1': u'foo'
    }
    table_with_character = tableToMarkdown('tableToMarkdown test with special character Ù', data)
    expected_string_with_special_character = '''### tableToMarkdown test with special character Ù
|header_1|
|---|
| foo |
'''
    assert table_with_character == expected_string_with_special_character


@pytest.mark.parametrize('data, expected_table', DATA_WITH_URLS)
def test_tbl_to_md_clickable_url(data, expected_table):
    table = tableToMarkdown('tableToMarkdown test', data, url_keys=['url1', 'url2'])
    assert table == expected_table


@pytest.mark.parametrize('data, expected_data', COMPLEX_DATA_WITH_URLS)
def test_url_to_clickable_markdown(data, expected_data):
    table = url_to_clickable_markdown(data, url_keys=['url', 'links'])
    assert table == expected_data

def test_flatten_cell():
    # sanity
    utf8_to_flatten = b'abcdefghijklmnopqrstuvwxyz1234567890!'.decode('utf8')
    flatten_text = flattenCell(utf8_to_flatten)
    expected_string = 'abcdefghijklmnopqrstuvwxyz1234567890!'

    assert flatten_text == expected_string

    # list of uft8 and string to flatten
    str_a = b'abcdefghijklmnopqrstuvwxyz1234567890!'
    utf8_b = str_a.decode('utf8')
    list_to_flatten = [str_a, utf8_b]
    flatten_text2 = flattenCell(list_to_flatten)
    expected_flatten_string = 'abcdefghijklmnopqrstuvwxyz1234567890!,\nabcdefghijklmnopqrstuvwxyz1234567890!'

    assert flatten_text2 == expected_flatten_string

    # special character test
    special_char = u'会'
    list_of_special = [special_char, special_char]

    flattenCell(list_of_special)
    flattenCell(special_char)

    # dictionary test
    dict_to_flatten = {'first': u'会'}
    expected_flatten_dict = u'{\n    "first": "\u4f1a"\n}'
    assert flattenCell(dict_to_flatten) == expected_flatten_dict


def test_hash_djb2():
    assert hash_djb2("test") == 2090756197, "Invalid value of hash_djb2"


def test_camelize():
    non_camalized = [{'chookity_bop': 'asdasd'}, {'ab_c': 'd e', 'fgh_ijk': 'lm', 'nop': 'qr_st'}]
    expected_output = [{'ChookityBop': 'asdasd'}, {'AbC': 'd e', 'Nop': 'qr_st', 'FghIjk': 'lm'}]
    assert camelize(non_camalized, '_') == expected_output

    non_camalized2 = {'ab_c': 'd e', 'fgh_ijk': 'lm', 'nop': 'qr_st'}
    expected_output2 = {'AbC': 'd e', 'Nop': 'qr_st', 'FghIjk': 'lm'}
    assert camelize(non_camalized2, '_') == expected_output2


# Note this test will fail when run locally (in pycharm/vscode) as it assumes the machine (docker image) has UTC timezone set
def test_date_to_timestamp():
    assert date_to_timestamp('2018-11-06T08:56:41') == 1541494601000
    assert date_to_timestamp(datetime.strptime('2018-11-06T08:56:41', "%Y-%m-%dT%H:%M:%S")) == 1541494601000


def test_pascalToSpace():
    use_cases = [
        ('Validate', 'Validate'),
        ('validate', 'Validate'),
        ('TCP', 'TCP'),
        ('eventType', 'Event Type'),
        ('eventID', 'Event ID'),
        ('eventId', 'Event Id'),
        ('IPAddress', 'IP Address'),
    ]
    for s, expected in use_cases:
        assert pascalToSpace(s) == expected, 'Error on {} != {}'.format(pascalToSpace(s), expected)


def test_safe_load_json():
    valid_json_str = '{"foo": "bar"}'
    expected_valid_json_result = {u'foo': u'bar'}
    assert expected_valid_json_result == safe_load_json(valid_json_str)


def test_remove_empty_elements():
    test_dict = {
        "foo": "bar",
        "baz": {},
        "empty": [],
        "nested_dict": {
            "empty_list": [],
            "hummus": "pita"
        },
        "nested_list": {
            "more_empty_list": []
        }
    }

    expected_result = {
        "foo": "bar",
        "nested_dict": {
            "hummus": "pita"
        }
    }
    assert expected_result == remove_empty_elements(test_dict)


@pytest.mark.parametrize('header,raw_input,expected_output', [
    ('AWS DynamoDB DescribeBackup', {
        'BackupDescription': {
            "Foo": "Bar",
            "Baz": "Bang",
            "TestKey": "TestValue"
        }
    }, '''### AWS DynamoDB DescribeBackup\n|Baz|Foo|TestKey|\n|---|---|---|\n| Bang | Bar | TestValue |\n'''),
    ('Empty Results', {'key': []}, '### Empty Results\n**No entries.**\n')
])
def test_aws_table_to_markdown(header, raw_input, expected_output):
    """
    Given
        - A header and a dict with two levels
        - A header and a dict with one key pointing to an empty list
    When
        - Creating a markdown table using the aws_table_to_markdown function
    Ensure
        - The header appears as a markdown header and the dictionary is translated to a markdown table
        - The header appears as a markdown header and "No entries" text appears instead of a markdown table"
    """
    assert aws_table_to_markdown(raw_input, header) == expected_output


def test_argToList():
    expected = ['a', 'b', 'c']
    test1 = ['a', 'b', 'c']
    test2 = 'a,b,c'
    test3 = '["a","b","c"]'
    test4 = 'a;b;c'
    test5 = 1
    test6 = '1'
    test7 = True

    results = [argToList(test1), argToList(test2), argToList(test2, ','), argToList(test3), argToList(test4, ';')]

    for result in results:
        assert expected == result, 'argToList test failed, {} is not equal to {}'.format(str(result), str(expected))

    assert argToList(test5) == [1]
    assert argToList(test6) == ['1']
    assert argToList(test7) == [True]


def test_remove_nulls():
    temp_dictionary = {"a": "b", "c": 4, "e": [], "f": {}, "g": None, "h": "", "i": [1], "k": ()}
    expected_dictionary = {"a": "b", "c": 4, "i": [1]}

    remove_nulls_from_dictionary(temp_dictionary)

    assert expected_dictionary == temp_dictionary, \
        "remove_nulls_from_dictionary test failed, {} is not equal to {}".format(str(temp_dictionary),
                                                                                 str(expected_dictionary))


def test_is_error_true():
    execute_command_results = [
        {
            "Type": entryTypes["error"],
            "ContentsFormat": formats["text"],
            "Contents": "this is error message"
        }
    ]
    assert is_error(execute_command_results)


def test_is_error_none():
    assert not is_error(None)


def test_is_error_single_entry():
    execute_command_results = {
        "Type": entryTypes["error"],
        "ContentsFormat": formats["text"],
        "Contents": "this is error message"
    }

    assert is_error(execute_command_results)


def test_is_error_false():
    execute_command_results = [
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["text"],
            "Contents": "this is regular note"
        }
    ]
    assert not is_error(execute_command_results)


def test_not_error_entry():
    execute_command_results = "invalid command results as string"
    assert not is_error(execute_command_results)


def test_get_error():
    execute_command_results = [
        {
            "Type": entryTypes["error"],
            "ContentsFormat": formats["text"],
            "Contents": "this is error message"
        }
    ]
    error = get_error(execute_command_results)
    assert error == "this is error message"


def test_get_error_single_entry():
    execute_command_results = {
        "Type": entryTypes["error"],
        "ContentsFormat": formats["text"],
        "Contents": "this is error message"
    }

    error = get_error(execute_command_results)
    assert error == "this is error message"


def test_get_error_need_raise_error_on_non_error_input():
    execute_command_results = [
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["text"],
            "Contents": "this is not an error"
        }
    ]
    try:
        get_error(execute_command_results)
    except ValueError as exception:
        assert "execute_command_result has no error entry. before using get_error use is_error" in str(exception)
        return

    assert False


@mark.parametrize('data,data_expected', [
    ("this is a test", b"this is a test"),
    (u"עברית", u"עברית".encode('utf-8')),
    (b"binary data\x15\x00", b"binary data\x15\x00"),
])  # noqa: E124
def test_fileResult(mocker, request, data, data_expected):
    mocker.patch.object(demisto, 'uniqueFile', return_value="test_file_result")
    mocker.patch.object(demisto, 'investigation', return_value={'id': '1'})
    file_name = "1_test_file_result"

    def cleanup():
        try:
            os.remove(file_name)
        except OSError:
            pass

    request.addfinalizer(cleanup)
    res = fileResult("test.txt", data)
    assert res['File'] == "test.txt"
    with open(file_name, 'rb') as f:
        assert f.read() == data_expected


# Error that always returns a unicode string to it's str representation
class SpecialErr(Exception):
    def __str__(self):
        return u"מיוחד"


def test_logger():
    from CommonServerPython import LOG
    LOG(u'€')
    LOG(Exception(u'€'))
    LOG(SpecialErr(12))


def test_logger_write(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'credentials': {'password': 'my_password'},
    })
    mocker.patch.object(demisto, 'info')
    ilog = IntegrationLogger()
    ilog.write("This is a test with my_password")
    ilog.print_log()
    # assert that the print doesn't contain my_password
    # call_args is tuple (args list, kwargs). we only need the args
    args = demisto.info.call_args[0]
    assert 'This is a test' in args[0]
    assert 'my_password' not in args[0]
    assert '<XX_REPLACED>' in args[0]


def test_logger_init_key_name(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'key': {'password': 'my_password'},
        'secret': 'my_secret'
    })
    mocker.patch.object(demisto, 'info')
    ilog = IntegrationLogger()
    ilog.write("This is a test with my_password and my_secret")
    ilog.print_log()
    # assert that the print doesn't contain my_password
    # call_args is tuple (args list, kwargs). we only need the args
    args = demisto.info.call_args[0]
    assert 'This is a test' in args[0]
    assert 'my_password' not in args[0]
    assert 'my_secret' not in args[0]
    assert '<XX_REPLACED>' in args[0]


def test_logger_replace_strs(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'apikey': 'my_apikey',
    })
    ilog = IntegrationLogger()
    ilog.add_replace_strs('special_str', '')  # also check that empty string is not added by mistake
    ilog('my_apikey is special_str and b64: ' + b64_encode('my_apikey'))
    assert ('' not in ilog.replace_strs)
    assert ilog.messages[0] == '<XX_REPLACED> is <XX_REPLACED> and b64: <XX_REPLACED>'


TEST_SSH_KEY_ESC = '-----BEGIN OPENSSH PRIVATE KEY-----\\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFw' \
                   'AAAAdzc2gtcn\\n-----END OPENSSH PRIVATE KEY-----'

TEST_SSH_KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFw' \
               'AAAAdzc2gtcn\n-----END OPENSSH PRIVATE KEY-----'

SENSITIVE_PARAM = {
    'app': None,
    'authentication': {
        'credential': '',
        'credentials': {
            'id': '',
            'locked': False,
            'modified': '0001-01-01T00: 00: 00Z',
            'name': '',
            'password': 'cred_pass',
            'sortValues': None,
            'sshkey': TEST_SSH_KEY,
            'sshkeyEsc': TEST_SSH_KEY_ESC,
            'sshkeyPass': 'ssh_key_secret_pass',
            'user': '',
            'vaultInstanceId': '',
            'version': 0,
            'workgroup': ''
        },
        'identifier': 'admin',
        'password': 'ident_pass',
        'passwordChanged': False
    },
}


def test_logger_replace_strs_credentials(mocker):
    mocker.patch.object(demisto, 'params', return_value=SENSITIVE_PARAM)
    ilog = IntegrationLogger()
    # log some secrets
    ilog('my cred pass: cred_pass. my ssh key: ssh_key_secret. my ssh key: {}.'
         'my ssh key: {}. my ssh pass: ssh_key_secret_pass. ident: ident_pass:'.format(TEST_SSH_KEY, TEST_SSH_KEY_ESC))

    for s in ('cred_pass', TEST_SSH_KEY, TEST_SSH_KEY_ESC, 'ssh_key_secret_pass', 'ident_pass'):
        assert s not in ilog.messages[0]


def test_debug_logger_replace_strs(mocker):
    mocker.patch.object(demisto, 'params', return_value=SENSITIVE_PARAM)
    debug_logger = DebugLogger()
    debug_logger.int_logger.set_buffering(True)
    debug_logger.log_start_debug()
    msg = debug_logger.int_logger.messages[0]
    assert 'debug-mode started' in msg
    assert 'Params:' in msg
    for s in ('cred_pass', 'ssh_key_secret', 'ssh_key_secret_pass', 'ident_pass', TEST_SSH_KEY, TEST_SSH_KEY_ESC):
        assert s not in msg


def test_build_curl_post_noproxy():
    """
    Given:
       - HTTP client log messages of POST query
       - Proxy is not used and insecure is not checked
    When
       - Building curl query
    Then
       - Ensure curl is generated as expected
    """
    ilog = IntegrationLogger()
    ilog.build_curl("send: b'POST /api HTTP/1.1\\r\\n"
                    "Host: demisto.com\\r\\n"
                    "User-Agent: python-requests/2.25.0\\r\\n"
                    "Accept-Encoding: gzip, deflate\r\n"
                    "Accept: */*\\r\\n"
                    "Connection: keep-alive\\r\\n"
                    "Authorization: TOKEN\\r\\n"
                    "Content-Length: 57\\r\\n"
                    "Content-Type: application/json\\r\\n\\r\\n'")
    ilog.build_curl("send: b'{\"data\": \"value\"}'")
    assert ilog.curl == [
        'curl -X POST https://demisto.com/api -H "Authorization: TOKEN" -H "Content-Type: application/json" '
        '--noproxy -d \'{"data": "value"}\''
    ]


def test_build_curl_get_withproxy(mocker):
    """
    Given:
       - HTTP client log messages of GET query
       - Proxy used and insecure checked
    When
       - Building curl query
    Then
       - Ensure curl is generated as expected
    """
    mocker.patch.object(demisto, 'params', return_value={
        'proxy': True,
        'insecure': True
    })
    os.environ['https_proxy'] = 'http://proxy'
    ilog = IntegrationLogger()
    ilog.build_curl("send: b'GET /api HTTP/1.1\\r\\n"
                    "Host: demisto.com\\r\\n"
                    "User-Agent: python-requests/2.25.0\\r\\n"
                    "Accept-Encoding: gzip, deflate\r\n"
                    "Accept: */*\\r\\n"
                    "Connection: keep-alive\\r\\n"
                    "Authorization: TOKEN\\r\\n"
                    "Content-Length: 57\\r\\n"
                    "Content-Type: application/json\\r\\n\\r\\n'")
    ilog.build_curl("send: b'{\"data\": \"value\"}'")
    assert ilog.curl == [
        'curl -X GET https://demisto.com/api -H "Authorization: TOKEN" -H "Content-Type: application/json" '
        '--proxy http://proxy -k -d \'{"data": "value"}\''
    ]


def test_build_curl_multiple_queries():
    """
    Given:
       - HTTP client log messages of POST and GET queries
       - Proxy is not used and insecure is not checked
    When
       - Building curl query
    Then
       - Ensure two curl queries are generated as expected
    """
    ilog = IntegrationLogger()
    ilog.build_curl("send: b'POST /api/post HTTP/1.1\\r\\n"
                    "Host: demisto.com\\r\\n"
                    "User-Agent: python-requests/2.25.0\\r\\n"
                    "Accept-Encoding: gzip, deflate\r\n"
                    "Accept: */*\\r\\n"
                    "Connection: keep-alive\\r\\n"
                    "Authorization: TOKEN\\r\\n"
                    "Content-Length: 57\\r\\n"
                    "Content-Type: application/json\\r\\n\\r\\n'")
    ilog.build_curl("send: b'{\"postdata\": \"value\"}'")
    ilog.build_curl("send: b'GET /api/get HTTP/1.1\\r\\n"
                    "Host: demisto.com\\r\\n"
                    "User-Agent: python-requests/2.25.0\\r\\n"
                    "Accept-Encoding: gzip, deflate\r\n"
                    "Accept: */*\\r\\n"
                    "Connection: keep-alive\\r\\n"
                    "Authorization: TOKEN\\r\\n"
                    "Content-Length: 57\\r\\n"
                    "Content-Type: application/json\\r\\n\\r\\n'")
    ilog.build_curl("send: b'{\"getdata\": \"value\"}'")
    assert ilog.curl == [
        'curl -X POST https://demisto.com/api/post -H "Authorization: TOKEN" -H "Content-Type: application/json" '
        '--noproxy -d \'{"postdata": "value"}\'',
        'curl -X GET https://demisto.com/api/get -H "Authorization: TOKEN" -H "Content-Type: application/json" '
        '--noproxy -d \'{"getdata": "value"}\''
    ]


def test_is_mac_address():
    from CommonServerPython import is_mac_address

    mac_address_false = 'AA:BB:CC:00:11'
    mac_address_true = 'AA:BB:CC:00:11:22'

    assert (is_mac_address(mac_address_false) is False)
    assert (is_mac_address(mac_address_true))


def test_return_error_command(mocker):
    from CommonServerPython import return_error
    err_msg = "Testing unicode Ё"
    outputs = {'output': 'error'}
    expected_error = {
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': err_msg,
        "EntryContext": outputs
    }

    # Test command that is not fetch-incidents
    mocker.patch.object(demisto, 'command', return_value="test-command")
    mocker.patch.object(sys, 'exit')
    mocker.spy(demisto, 'results')
    return_error(err_msg, '', outputs)
    assert str(demisto.results.call_args) == "call({})".format(expected_error)


def test_return_error_fetch_incidents(mocker):
    from CommonServerPython import return_error
    err_msg = "Testing unicode Ё"

    # Test fetch-incidents
    mocker.patch.object(demisto, 'command', return_value="fetch-incidents")
    returned_error = False
    try:
        return_error(err_msg)
    except Exception as e:
        returned_error = True
        assert str(e) == err_msg
    assert returned_error


def test_return_error_fetch_indicators(mocker):
    from CommonServerPython import return_error
    err_msg = "Testing unicode Ё"

    # Test fetch-indicators
    mocker.patch.object(demisto, 'command', return_value="fetch-indicators")
    returned_error = False
    try:
        return_error(err_msg)
    except Exception as e:
        returned_error = True
        assert str(e) == err_msg
    assert returned_error


def test_return_error_long_running_execution(mocker):
    from CommonServerPython import return_error
    err_msg = "Testing unicode Ё"

    # Test long-running-execution
    mocker.patch.object(demisto, 'command', return_value="long-running-execution")
    returned_error = False
    try:
        return_error(err_msg)
    except Exception as e:
        returned_error = True
        assert str(e) == err_msg
    assert returned_error


def test_return_error_script(mocker, monkeypatch):
    from CommonServerPython import return_error
    mocker.patch.object(sys, 'exit')
    mocker.spy(demisto, 'results')
    monkeypatch.delattr(demisto, 'command')
    err_msg = "Testing unicode Ё"
    outputs = {'output': 'error'}
    expected_error = {
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': err_msg,
        "EntryContext": outputs
    }

    assert not hasattr(demisto, 'command')
    return_error(err_msg, '', outputs)
    assert str(demisto.results.call_args) == "call({})".format(expected_error)


def test_exception_in_return_error(mocker):
    from CommonServerPython import return_error, IntegrationLogger

    expected = {'EntryContext': None, 'Type': 4, 'ContentsFormat': 'text', 'Contents': 'Message'}
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(IntegrationLogger, '__call__')
    with raises(SystemExit, match='0'):
        return_error("Message", error=ValueError("Error!"))
    results = demisto.results.call_args[0][0]
    assert expected == results
    # IntegrationLogger = LOG (2 times if exception supplied)
    assert IntegrationLogger.__call__.call_count == 2


def test_get_demisto_version(mocker, clear_version_cache):
    # verify expected server version and build returned in case Demisto class has attribute demistoVersion
    mocker.patch.object(
        demisto,
        'demistoVersion',
        return_value={
            'version': '5.0.0',
            'buildNumber': '50000'
        }
    )
    assert get_demisto_version() == {
        'version': '5.0.0',
        'buildNumber': '50000'
    }
    # call again to check cache
    assert get_demisto_version() == {
        'version': '5.0.0',
        'buildNumber': '50000'
    }
    # call count should be 1 as we cached
    assert demisto.demistoVersion.call_count == 1
    # test is_demisto_version_ge
    assert is_demisto_version_ge('5.0.0')
    assert is_demisto_version_ge('4.5.0')
    assert not is_demisto_version_ge('5.5.0')
    assert get_demisto_version_as_str() == '5.0.0-50000'


def test_is_demisto_version_ge_4_5(mocker, clear_version_cache):
    get_version_patch = mocker.patch('CommonServerPython.get_demisto_version')
    get_version_patch.side_effect = AttributeError('simulate missing demistoVersion')
    assert not is_demisto_version_ge('5.0.0')
    assert not is_demisto_version_ge('6.0.0')
    with raises(AttributeError, match='simulate missing demistoVersion'):
        is_demisto_version_ge('4.5.0')


def test_is_demisto_version_build_ge(mocker):
    mocker.patch.object(
        demisto,
        'demistoVersion',
        return_value={
            'version': '6.0.0',
            'buildNumber': '50000'
        }
    )
    assert is_demisto_version_ge('6.0.0', '49999')
    assert is_demisto_version_ge('6.0.0', '50000')
    assert not is_demisto_version_ge('6.0.0', '50001')
    assert not is_demisto_version_ge('6.1.0', '49999')
    assert not is_demisto_version_ge('5.5.0', '50001')


def test_assign_params():
    from CommonServerPython import assign_params
    res = assign_params(a='1', b=True, c=None, d='')
    assert res == {'a': '1', 'b': True}


class TestBuildDBotEntry(object):
    def test_build_dbot_entry(self):
        from CommonServerPython import build_dbot_entry
        res = build_dbot_entry('user@example.com', 'Email', 'Vendor', 1)
        assert res == {'DBotScore': {'Indicator': 'user@example.com', 'Type': 'email', 'Vendor': 'Vendor', 'Score': 1}}

    def test_build_dbot_entry_no_malicious(self):
        from CommonServerPython import build_dbot_entry
        res = build_dbot_entry('user@example.com', 'Email', 'Vendor', 3, build_malicious=False)
        assert res == {'DBotScore': {'Indicator': 'user@example.com', 'Type': 'email', 'Vendor': 'Vendor', 'Score': 3}}

    def test_build_dbot_entry_malicious(self):
        from CommonServerPython import build_dbot_entry, outputPaths
        res = build_dbot_entry('user@example.com', 'Email', 'Vendor', 3, 'Malicious email')

        assert res == {
            "DBotScore": {
                "Vendor": "Vendor",
                "Indicator": "user@example.com",
                "Score": 3,
                "Type": "email"
            },
            outputPaths['email']: {
                "Malicious": {
                    "Vendor": "Vendor",
                    "Description": "Malicious email"
                },
                "Address": "user@example.com"
            }
        }

    def test_build_malicious_dbot_entry_file(self):
        from CommonServerPython import build_malicious_dbot_entry, outputPaths
        res = build_malicious_dbot_entry('md5hash', 'MD5', 'Vendor', 'Google DNS')
        assert res == {
            outputPaths['file']:
                {"Malicious": {"Vendor": "Vendor", "Description": "Google DNS"}, "MD5": "md5hash"}}

    def test_build_malicious_dbot_entry(self):
        from CommonServerPython import build_malicious_dbot_entry, outputPaths
        res = build_malicious_dbot_entry('8.8.8.8', 'ip', 'Vendor', 'Google DNS')
        assert res == {outputPaths['ip']: {
            'Address': '8.8.8.8', 'Malicious': {'Vendor': 'Vendor', 'Description': 'Google DNS'}}}

    def test_build_malicious_dbot_entry_wrong_indicator_type(self):
        from CommonServerPython import build_malicious_dbot_entry, DemistoException
        with raises(DemistoException, match='Wrong indicator type'):
            build_malicious_dbot_entry('8.8.8.8', 'notindicator', 'Vendor', 'Google DNS')

    def test_illegal_dbot_score(self):
        from CommonServerPython import build_dbot_entry, DemistoException
        with raises(DemistoException, match='illegal DBot score'):
            build_dbot_entry('1', 'ip', 'Vendor', 8)

    def test_illegal_indicator_type(self):
        from CommonServerPython import build_dbot_entry, DemistoException
        with raises(DemistoException, match='illegal indicator type'):
            build_dbot_entry('1', 'NOTHING', 'Vendor', 2)

    def test_file_indicators(self):
        from CommonServerPython import build_dbot_entry, outputPaths
        res = build_dbot_entry('md5hash', 'md5', 'Vendor', 3)
        assert res == {
            "DBotScore": {
                "Indicator": "md5hash",
                "Type": "file",
                "Vendor": "Vendor",
                "Score": 3
            },
            outputPaths['file']: {
                "MD5": "md5hash",
                "Malicious": {
                    "Vendor": "Vendor",
                    "Description": None
                }
            }
        }


class TestCommandResults:
    def test_multiple_outputs_keys(self):
        """
        Given
        - File has 3 unique keys. sha256, md5 and sha1

        When
        - creating CommandResults with outputs_key_field=[sha1, sha256, md5]

        Then
        - entrycontext DT expression contains all 3 unique fields
        """
        from CommonServerPython import CommandResults

        files = [
            {
                'sha256': '111',
                'sha1': '111',
                'md5': '111'
            },
            {
                'sha256': '222',
                'sha1': '222',
                'md5': '222'
            }
        ]
        results = CommandResults(outputs_prefix='File', outputs_key_field=['sha1', 'sha256', 'md5'], outputs=files)

        assert list(results.to_context()['EntryContext'].keys())[0] == \
               'File(val.sha1 == obj.sha1 && val.sha256 == obj.sha256 && val.md5 == obj.md5)'

    def test_output_prefix_includes_dt(self):
        """
        Given
        - Returning File with only outputs_prefix which includes DT in it
        - outputs key fields are not provided

        When
        - creating CommandResults

        Then
        - EntryContext key should contain only the outputs_prefix
        """
        from CommonServerPython import CommandResults

        files = [{"key": "value"}]  # if outputs is empty list, no results are returned
        results = CommandResults(outputs_prefix='File(val.sha1 == obj.sha1 && val.md5 == obj.md5)',
                                 outputs_key_field='', outputs=files)

        assert list(results.to_context()['EntryContext'].keys())[0] == \
               'File(val.sha1 == obj.sha1 && val.md5 == obj.md5)'

    def test_readable_only_context(self):
        """
        Given:
        - Markdown entry to CommandResults

        When:
        - Returning results

        Then:
        - Validate HumanReadable exists
        """
        from CommonServerPython import CommandResults
        markdown = '## Something'
        context = CommandResults(readable_output=markdown).to_context()
        assert context.get('HumanReadable') == markdown

    def test_empty_outputs(self):
        """
        Given:
        - Outputs as None

        When:
        - Returning results

        Then:
        - Validate EntryContext key value

        """
        from CommonServerPython import CommandResults
        res = CommandResults(
            outputs_prefix='FoundIndicators',
            outputs_key_field='value',
            outputs=None
        )
        context = res.to_context()
        assert {} == context.get('EntryContext')

    def test_empty_list_outputs(self):
        """
        Given:
        - Outputs with empty list

        When:
        - Returning results

        Then:
        - Validate EntryContext key value

        """
        from CommonServerPython import CommandResults
        res = CommandResults(
            outputs_prefix='FoundIndicators',
            outputs_key_field='value',
            outputs=[]
        )
        context = res.to_context()
        assert {} == context.get('EntryContext')

    def test_return_command_results(self, clear_version_cache):
        from CommonServerPython import Common, CommandResults, EntryFormat, EntryType, DBotScoreType

        dbot_score = Common.DBotScore(
            indicator='8.8.8.8',
            integration_name='Virus Total',
            indicator_type=DBotScoreType.IP,
            score=Common.DBotScore.GOOD
        )

        ip = Common.IP(
            ip='8.8.8.8',
            dbot_score=dbot_score,
            asn='some asn',
            hostname='test.com',
            geo_country=None,
            geo_description=None,
            geo_latitude=None,
            geo_longitude=None,
            positive_engines=None,
            detection_engines=None
        )

        results = CommandResults(
            outputs_key_field=None,
            outputs_prefix=None,
            outputs=None,
            indicators=[ip]
        )

        assert results.to_context() == {
            'Type': EntryType.NOTE,
            'ContentsFormat': EntryFormat.JSON,
            'Contents': None,
            'HumanReadable': None,
            'EntryContext': {
                'IP(val.Address && val.Address == obj.Address)': [
                    {
                        'Address': '8.8.8.8',
                        'ASN': 'some asn',
                        'Hostname': 'test.com'
                    }
                ],
                'DBotScore(val.Indicator && val.Indicator == obj.Indicator && '
                'val.Vendor == obj.Vendor && val.Type == obj.Type)': [
                    {
                        'Indicator': '8.8.8.8',
                        'Vendor': 'Virus Total',
                        'Score': 1,
                        'Type': 'ip'
                    }
                ]
            },
            'IndicatorTimeline': [],
            'IgnoreAutoExtract': False
        }

    def test_multiple_indicators(self, clear_version_cache):
        from CommonServerPython import Common, CommandResults, EntryFormat, EntryType, DBotScoreType
        dbot_score1 = Common.DBotScore(
            indicator='8.8.8.8',
            integration_name='Virus Total',
            indicator_type=DBotScoreType.IP,
            score=Common.DBotScore.GOOD
        )
        ip1 = Common.IP(
            ip='8.8.8.8',
            dbot_score=dbot_score1,
            asn='some asn',
            hostname='test.com',
            geo_country=None,
            geo_description=None,
            geo_latitude=None,
            geo_longitude=None,
            positive_engines=None,
            detection_engines=None
        )

        dbot_score2 = Common.DBotScore(
            indicator='5.5.5.5',
            integration_name='Virus Total',
            indicator_type=DBotScoreType.IP,
            score=Common.DBotScore.GOOD
        )
        ip2 = Common.IP(
            ip='5.5.5.5',
            dbot_score=dbot_score2,
            asn='some asn',
            hostname='test.com',
            geo_country=None,
            geo_description=None,
            geo_latitude=None,
            geo_longitude=None,
            positive_engines=None,
            detection_engines=None
        )

        results = CommandResults(
            outputs_key_field=None,
            outputs_prefix=None,
            outputs=None,
            indicators=[ip1, ip2]
        )

        assert results.to_context() == {
            'Type': EntryType.NOTE,
            'ContentsFormat': EntryFormat.JSON,
            'Contents': None,
            'HumanReadable': None,
            'EntryContext': {
                'IP(val.Address && val.Address == obj.Address)': [
                    {
                        'Address': '8.8.8.8',
                        'ASN': 'some asn',
                        'Hostname': 'test.com'
                    },
                    {
                        'Address': '5.5.5.5',
                        'ASN': 'some asn',
                        'Hostname': 'test.com'
                    }
                ],
                'DBotScore(val.Indicator && val.Indicator == obj.Indicator && '
                'val.Vendor == obj.Vendor && val.Type == obj.Type)': [
                    {
                        'Indicator': '8.8.8.8',
                        'Vendor': 'Virus Total',
                        'Score': 1,
                        'Type': 'ip'
                    },
                    {
                        'Indicator': '5.5.5.5',
                        'Vendor': 'Virus Total',
                        'Score': 1,
                        'Type': 'ip'
                    }
                ]
            },
            'IndicatorTimeline': [],
            'IgnoreAutoExtract': False
        }

    def test_return_list_of_items(self, clear_version_cache):
        from CommonServerPython import CommandResults, EntryFormat, EntryType
        tickets = [
            {
                'ticket_id': 1,
                'title': 'foo'
            },
            {
                'ticket_id': 2,
                'title': 'goo'
            }
        ]
        results = CommandResults(
            outputs_prefix='Jira.Ticket',
            outputs_key_field='ticket_id',
            outputs=tickets
        )

        assert results.to_context() == {
            'Type': EntryType.NOTE,
            'ContentsFormat': EntryFormat.JSON,
            'Contents': tickets,
            'HumanReadable': tableToMarkdown('Results', tickets),
            'EntryContext': {
                'Jira.Ticket(val.ticket_id == obj.ticket_id)': tickets
            },
            'IndicatorTimeline': [],
            'IgnoreAutoExtract': False
        }

    def test_return_list_of_items_the_old_way(self):
        from CommonServerPython import CommandResults, EntryFormat, EntryType
        tickets = [
            {
                'ticket_id': 1,
                'title': 'foo'
            },
            {
                'ticket_id': 2,
                'title': 'goo'
            }
        ]
        results = CommandResults(
            outputs_prefix=None,
            outputs_key_field=None,
            outputs={
                'Jira.Ticket(val.ticket_id == obj.ticket_id)': tickets
            },
            raw_response=tickets
        )

        assert sorted(results.to_context()) == sorted({
            'Type': EntryType.NOTE,
            'ContentsFormat': EntryFormat.JSON,
            'Contents': tickets,
            'HumanReadable': None,
            'EntryContext': {
                'Jira.Ticket(val.ticket_id == obj.ticket_id)': tickets
            },
            'IndicatorTimeline': [],
            'IgnoreAutoExtract': False
        })

    def test_create_dbot_score_with_invalid_score(self):
        from CommonServerPython import Common, DBotScoreType

        try:
            Common.DBotScore(
                indicator='8.8.8.8',
                integration_name='Virus Total',
                score=100,
                indicator_type=DBotScoreType.IP
            )

            assert False
        except TypeError:
            assert True

    def test_create_domain(self):
        from CommonServerPython import CommandResults, Common, EntryType, EntryFormat, DBotScoreType

        dbot_score = Common.DBotScore(
            indicator='somedomain.com',
            integration_name='Virus Total',
            indicator_type=DBotScoreType.DOMAIN,
            score=Common.DBotScore.GOOD
        )

        domain = Common.Domain(
            domain='somedomain.com',
            dbot_score=dbot_score,
            dns='dns.somedomain',
            detection_engines=10,
            positive_detections=5,
            organization='Some Organization',
            admin_phone='18000000',
            admin_email='admin@test.com',

            registrant_name='Mr Registrant',

            registrar_name='Mr Registrar',
            registrar_abuse_email='registrar@test.com',
            creation_date='2019-01-01T00:00:00',
            updated_date='2019-01-02T00:00:00',
            expiration_date=None,
            domain_status='ACTIVE',
            name_servers=[
                'PNS31.CLOUDNS.NET',
                'PNS32.CLOUDNS.NET'
            ],
            sub_domains=[
                'sub-domain1.somedomain.com',
                'sub-domain2.somedomain.com',
                'sub-domain3.somedomain.com'
            ]
        )

        results = CommandResults(
            outputs_key_field=None,
            outputs_prefix=None,
            outputs=None,
            indicators=[domain]
        )

        assert results.to_context() == {
            'Type': EntryType.NOTE,
            'ContentsFormat': EntryFormat.JSON,
            'Contents': None,
            'HumanReadable': None,
            'EntryContext': {
                'Domain(val.Name && val.Name == obj.Name)': [
                    {
                        "Name": "somedomain.com",
                        "DNS": "dns.somedomain",
                        "DetectionEngines": 10,
                        "PositiveDetections": 5,
                        "Registrar": {
                            "Name": "Mr Registrar",
                            "AbuseEmail": "registrar@test.com",
                            "AbusePhone": None
                        },
                        "Registrant": {
                            "Name": "Mr Registrant",
                            "Email": None,
                            "Phone": None,
                            "Country": None
                        },
                        "Admin": {
                            "Name": None,
                            "Email": "admin@test.com",
                            "Phone": "18000000",
                            "Country": None
                        },
                        "Organization": "Some Organization",
                        "Subdomains": [
                            "sub-domain1.somedomain.com",
                            "sub-domain2.somedomain.com",
                            "sub-domain3.somedomain.com"
                        ],
                        "DomainStatus": "ACTIVE",
                        "CreationDate": "2019-01-01T00:00:00",
                        "UpdatedDate": "2019-01-02T00:00:00",
                        "NameServers": [
                            "PNS31.CLOUDNS.NET",
                            "PNS32.CLOUDNS.NET"
                        ],
                        "WHOIS": {
                            "Registrar": {
                                "Name": "Mr Registrar",
                                "AbuseEmail": "registrar@test.com",
                                "AbusePhone": None
                            },
                            "Registrant": {
                                "Name": "Mr Registrant",
                                "Email": None,
                                "Phone": None,
                                "Country": None
                            },
                            "Admin": {
                                "Name": None,
                                "Email": "admin@test.com",
                                "Phone": "18000000",
                                "Country": None
                            },
                            "DomainStatus": "ACTIVE",
                            "CreationDate": "2019-01-01T00:00:00",
                            "UpdatedDate": "2019-01-02T00:00:00",
                            "NameServers": [
                                "PNS31.CLOUDNS.NET",
                                "PNS32.CLOUDNS.NET"
                            ]
                        }
                    }
                ],
                'DBotScore(val.Indicator && val.Indicator == obj.Indicator && '
                'val.Vendor == obj.Vendor && val.Type == obj.Type)': [
                    {
                        'Indicator': 'somedomain.com',
                        'Vendor': 'Virus Total',
                        'Score': 1,
                        'Type': 'domain'
                    }
                ]
            },
            'IndicatorTimeline': [],
            'IgnoreAutoExtract': False
        }

    def test_create_certificate(self):
        """
        Given:
            -  an X509 Certificate with its properties
        When
            - creating a CommandResults with the Certificate Standard Context
        Then
            - the proper output Context is created
        """
        from CommonServerPython import CommandResults, Common, EntryType, EntryFormat, DBotScoreType

        dbot_score = Common.DBotScore(
            indicator='bc33cf76519f1ec5ae7f287f321df33a7afd4fd553f364cf3c753f91ba689f8d',
            integration_name='test',
            indicator_type=DBotScoreType.CERTIFICATE,
            score=Common.DBotScore.NONE
        )

        cert_extensions = [
            Common.CertificateExtension(
                extension_type=Common.CertificateExtension.ExtensionType.AUTHORITYKEYIDENTIFIER,
                authority_key_identifier=Common.CertificateExtension.AuthorityKeyIdentifier(
                    key_identifier="0f80611c823161d52f28e78d4638b42ce1c6d9e2"
                ),
                critical=False
            ),
            Common.CertificateExtension(
                extension_type=Common.CertificateExtension.ExtensionType.SUBJECTKEYIDENTIFIER,
                digest="b34972bb12121b8851cd5564ff9656dcbca3f288",
                critical=False
            ),
            Common.CertificateExtension(
                extension_type=Common.CertificateExtension.ExtensionType.SUBJECTALTERNATIVENAME,
                subject_alternative_names=[
                    Common.GeneralName(
                        gn_type="dNSName",
                        gn_value="*.paloaltonetworks.com"
                    ),
                    Common.GeneralName(
                        gn_type="dNSName",
                        gn_value="paloaltonetworks.com"
                    )
                ],
                critical=False
            ),
            Common.CertificateExtension(
                extension_type=Common.CertificateExtension.ExtensionType.KEYUSAGE,
                digital_signature=True,
                key_encipherment=True,
                critical=True
            ),
            Common.CertificateExtension(
                extension_type=Common.CertificateExtension.ExtensionType.EXTENDEDKEYUSAGE,
                usages=[
                    "serverAuth",
                    "clientAuth"
                ],
                critical=False
            ),
            Common.CertificateExtension(
                extension_type=Common.CertificateExtension.ExtensionType.CRLDISTRIBUTIONPOINTS,
                distribution_points=[
                    Common.CertificateExtension.DistributionPoint(
                        full_name=[
                            Common.GeneralName(
                                gn_type="uniformResourceIdentifier",
                                gn_value="http://crl3.digicert.com/ssca-sha2-g7.crl"
                            )
                        ]
                    ),
                    Common.CertificateExtension.DistributionPoint(
                        full_name=[
                            Common.GeneralName(
                                gn_type="uniformResourceIdentifier",
                                gn_value="http://crl4.digicert.com/ssca-sha2-g7.crl"
                            )
                        ]
                    )
                ],
                critical=False
            ),
            Common.CertificateExtension(
                extension_type=Common.CertificateExtension.ExtensionType.CERTIFICATEPOLICIES,
                certificate_policies=[
                    Common.CertificateExtension.CertificatePolicy(
                        policy_identifier="2.16.840.1.114412.1.1",
                        policy_qualifiers=["https://www.digicert.com/CPS"]
                    ),
                    Common.CertificateExtension.CertificatePolicy(
                        policy_identifier="2.23.140.1.2.2"
                    )
                ],
                critical=False
            ),
            Common.CertificateExtension(
                extension_type=Common.CertificateExtension.ExtensionType.AUTHORITYINFORMATIONACCESS,
                authority_information_access=[
                    Common.CertificateExtension.AuthorityInformationAccess(
                        access_method="OCSP",
                        access_location=Common.GeneralName(
                            gn_type="uniformResourceIdentifier",
                            gn_value="http://ocsp.digicert.com"
                        )
                    ),
                    Common.CertificateExtension.AuthorityInformationAccess(
                        access_method="caIssuers",
                        access_location=Common.GeneralName(
                            gn_type="uniformResourceIdentifier",
                            gn_value="http://cacerts.digicert.com/DigiCertSHA2SecureServerCA.crt"
                        )
                    )
                ],
                critical=False
            ),
            Common.CertificateExtension(
                extension_type=Common.CertificateExtension.ExtensionType.BASICCONSTRAINTS,
                basic_constraints=Common.CertificateExtension.BasicConstraints(
                    ca=False
                ),
                critical=False
            ),
            Common.CertificateExtension(
                extension_type=Common.CertificateExtension.ExtensionType.PRESIGNEDCERTIFICATETIMESTAMPS,
                signed_certificate_timestamps=[
                    Common.CertificateExtension.SignedCertificateTimestamp(
                        version=0,
                        log_id="f65c942fd1773022145418083094568ee34d131933bfdf0c2f200bcc4ef164e3",
                        timestamp="2020-10-23T19:31:49.000Z",
                        entry_type="PreCertificate"
                    ),
                    Common.CertificateExtension.SignedCertificateTimestamp(
                        version=0,
                        log_id="5cdc4392fee6ab4544b15e9ad456e61037fbd5fa47dca17394b25ee6f6c70eca",
                        timestamp="2020-10-23T19:31:49.000Z",
                        entry_type="PreCertificate"
                    )
                ],
                critical=False
            ),
            Common.CertificateExtension(
                extension_type=Common.CertificateExtension.ExtensionType.SIGNEDCERTIFICATETIMESTAMPS,
                signed_certificate_timestamps=[
                    Common.CertificateExtension.SignedCertificateTimestamp(
                        version=0,
                        log_id="f65c942fd1773022145418083094568ee34d131933bfdf0c2f200bcc4ef164e3",
                        timestamp="2020-10-23T19:31:49.000Z",
                        entry_type="X509Certificate"
                    ),
                    Common.CertificateExtension.SignedCertificateTimestamp(
                        version=0,
                        log_id="5cdc4392fee6ab4544b15e9ad456e61037fbd5fa47dca17394b25ee6f6c70eca",
                        timestamp="2020-10-23T19:31:49.000Z",
                        entry_type="X509Certificate"
                    )
                ],
                critical=False
            )
        ]
        certificate = Common.Certificate(
            subject_dn='CN=*.paloaltonetworks.com,O=Palo Alto Networks\\, Inc.,L=Santa Clara,ST=California,C=US',
            dbot_score=dbot_score,
            serial_number='19290688218337824112020565039390569720',
            issuer_dn='CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US',
            validity_not_before='2020-10-23T00:00:00.000Z',
            validity_not_after='2021-11-21T23:59:59.000Z',
            sha256='bc33cf76519f1ec5ae7f287f321df33a7afd4fd553f364cf3c753f91ba689f8d',
            sha1='2392ea5cd4c2a61e51547570634ef887ab1942e9',
            md5='22769ae413997b86da4a0934072d9ed0',
            publickey=Common.CertificatePublicKey(
                algorithm=Common.CertificatePublicKey.Algorithm.RSA,
                length=2048,
                modulus='00:00:00:00',
                exponent=65537
            ),
            spki_sha256='94b716aeda21cd661949cfbf3f55457a277da712cdce0ab31989a4f288fad9b9',
            signature_algorithm='sha256',
            signature='SIGNATURE',
            extensions=cert_extensions
        )

        results = CommandResults(
            outputs_key_field=None,
            outputs_prefix=None,
            outputs=None,
            indicators=[certificate]
        )

        CONTEXT_PATH = "Certificate(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || " \
                       "val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512)"

        assert results.to_context() == {
            'Type': EntryType.NOTE,
            'ContentsFormat': EntryFormat.JSON,
            'Contents': None,
            'HumanReadable': None,
            'EntryContext': {
                CONTEXT_PATH: [{
                    "SubjectDN": "CN=*.paloaltonetworks.com,O=Palo Alto Networks\\, Inc.,L=Santa Clara,ST=California,C=US",
                    "SubjectAlternativeName": [
                        {
                            "Type": "dNSName",
                            "Value": "*.paloaltonetworks.com"
                        },
                        {
                            "Type": "dNSName",
                            "Value": "paloaltonetworks.com"
                        }
                    ],
                    "Name": [
                        "*.paloaltonetworks.com",
                        "paloaltonetworks.com"
                    ],
                    "IssuerDN": "CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US",
                    "SerialNumber": "19290688218337824112020565039390569720",
                    "ValidityNotBefore": "2020-10-23T00:00:00.000Z",
                    "ValidityNotAfter": "2021-11-21T23:59:59.000Z",
                    "SHA256": "bc33cf76519f1ec5ae7f287f321df33a7afd4fd553f364cf3c753f91ba689f8d",
                    "SHA1": "2392ea5cd4c2a61e51547570634ef887ab1942e9",
                    "MD5": "22769ae413997b86da4a0934072d9ed0",
                    "PublicKey": {
                        "Algorithm": "RSA",
                        "Length": 2048,
                        "Modulus": "00:00:00:00",
                        "Exponent": 65537
                    },
                    "SPKISHA256": "94b716aeda21cd661949cfbf3f55457a277da712cdce0ab31989a4f288fad9b9",
                    "Signature": {
                        "Algorithm": "sha256",
                        "Signature": "SIGNATURE"
                    },
                    "Extension": [
                        {
                            "OID": "2.5.29.35",
                            "Name": "authorityKeyIdentifier",
                            "Critical": False,
                            "Value": {
                                "KeyIdentifier": "0f80611c823161d52f28e78d4638b42ce1c6d9e2"
                            }
                        },
                        {
                            "OID": "2.5.29.14",
                            "Name": "subjectKeyIdentifier",
                            "Critical": False,
                            "Value": {
                                "Digest": "b34972bb12121b8851cd5564ff9656dcbca3f288"
                            }
                        },
                        {
                            "OID": "2.5.29.17",
                            "Name": "subjectAltName",
                            "Critical": False,
                            "Value": [
                                {
                                    "Type": "dNSName",
                                    "Value": "*.paloaltonetworks.com"
                                },
                                {
                                    "Type": "dNSName",
                                    "Value": "paloaltonetworks.com"
                                }
                            ]
                        },
                        {
                            "OID": "2.5.29.15",
                            "Name": "keyUsage",
                            "Critical": True,
                            "Value": {
                                "DigitalSignature": True,
                                "KeyEncipherment": True
                            }
                        },
                        {
                            "OID": "2.5.29.37",
                            "Name": "extendedKeyUsage",
                            "Critical": False,
                            "Value": {
                                "Usages": [
                                    "serverAuth",
                                    "clientAuth"
                                ]
                            }
                        },
                        {
                            "OID": "2.5.29.31",
                            "Name": "cRLDistributionPoints",
                            "Critical": False,
                            "Value": [
                                {
                                    "FullName": [
                                        {
                                            "Type": "uniformResourceIdentifier",
                                            "Value": "http://crl3.digicert.com/ssca-sha2-g7.crl"
                                        }
                                    ]
                                },
                                {
                                    "FullName": [
                                        {
                                            "Type": "uniformResourceIdentifier",
                                            "Value": "http://crl4.digicert.com/ssca-sha2-g7.crl"
                                        }
                                    ]
                                }
                            ]
                        },
                        {
                            "OID": "2.5.29.32",
                            "Name": "certificatePolicies",
                            "Critical": False,
                            "Value": [
                                {
                                    "PolicyIdentifier": "2.16.840.1.114412.1.1",
                                    "PolicyQualifiers": [
                                        "https://www.digicert.com/CPS"
                                    ]
                                },
                                {
                                    "PolicyIdentifier": "2.23.140.1.2.2"
                                }
                            ]
                        },
                        {
                            "OID": "1.3.6.1.5.5.7.1.1",
                            "Name": "authorityInfoAccess",
                            "Critical": False,
                            "Value": [
                                {
                                    "AccessMethod": "OCSP",
                                    "AccessLocation": {
                                        "Type": "uniformResourceIdentifier",
                                        "Value": "http://ocsp.digicert.com"
                                    }
                                },
                                {
                                    "AccessMethod": "caIssuers",
                                    "AccessLocation": {
                                        "Type": "uniformResourceIdentifier",
                                        "Value": "http://cacerts.digicert.com/DigiCertSHA2SecureServerCA.crt"
                                    }
                                }
                            ]
                        },
                        {
                            "OID": "2.5.29.19",
                            "Name": "basicConstraints",
                            "Critical": False,
                            "Value": {
                                "CA": False
                            }
                        },
                        {
                            "OID": "1.3.6.1.4.1.11129.2.4.2",
                            "Name": "signedCertificateTimestampList",
                            "Critical": False,
                            "Value": [
                                {
                                    "Version": 0,
                                    "LogId": "f65c942fd1773022145418083094568ee34d131933bfdf0c2f200bcc4ef164e3",
                                    "Timestamp": "2020-10-23T19:31:49.000Z",
                                    "EntryType": "PreCertificate"
                                },
                                {
                                    "Version": 0,
                                    "LogId": "5cdc4392fee6ab4544b15e9ad456e61037fbd5fa47dca17394b25ee6f6c70eca",
                                    "Timestamp": "2020-10-23T19:31:49.000Z",
                                    "EntryType": "PreCertificate"
                                }
                            ]
                        },
                        {
                            "OID": "1.3.6.1.4.1.11129.2.4.5",
                            "Name": "signedCertificateTimestampList",
                            "Critical": False,
                            "Value": [
                                {
                                    "Version": 0,
                                    "LogId": "f65c942fd1773022145418083094568ee34d131933bfdf0c2f200bcc4ef164e3",
                                    "Timestamp": "2020-10-23T19:31:49.000Z",
                                    "EntryType": "X509Certificate"
                                },
                                {
                                    "Version": 0,
                                    "LogId": "5cdc4392fee6ab4544b15e9ad456e61037fbd5fa47dca17394b25ee6f6c70eca",
                                    "Timestamp": "2020-10-23T19:31:49.000Z",
                                    "EntryType": "X509Certificate"
                                }
                            ]
                        }
                    ]
                }],
                'DBotScore(val.Indicator && val.Indicator == obj.Indicator && '
                'val.Vendor == obj.Vendor && val.Type == obj.Type)': [{
                    "Indicator": "bc33cf76519f1ec5ae7f287f321df33a7afd4fd553f364cf3c753f91ba689f8d",
                    "Type": "certificate",
                    "Vendor": "test",
                    "Score": 0
                }]
            },
            'IndicatorTimeline': [],
            'IgnoreAutoExtract': False
        }

    def test_indicator_timeline_with_list_of_indicators(self):
        """
       Given:
           -  a list of an indicator
       When
           - creating an IndicatorTimeline object
           - creating a CommandResults objects using the IndicatorTimeline object
       Then
           - the IndicatorTimeline receives the appropriate category and message
       """
        from CommonServerPython import CommandResults, IndicatorsTimeline

        indicators = ['8.8.8.8']
        timeline = IndicatorsTimeline(indicators=indicators, category='test', message='message')

        results = CommandResults(
            outputs_prefix=None,
            outputs_key_field=None,
            outputs=None,
            raw_response=indicators,
            indicators_timeline=timeline
        )

        assert sorted(results.to_context().get('IndicatorTimeline')) == sorted([
            {'Value': '8.8.8.8', 'Category': 'test', 'Message': 'message'}
        ])

    def test_indicator_timeline_running_from_an_integration(self, mocker):
        """
       Given:
           -  a list of an indicator
       When
           - mocking the demisto.params()
           - creating an IndicatorTimeline object
           - creating a CommandResults objects using the IndicatorTimeline object
       Then
           - the IndicatorTimeline receives the appropriate category and message
       """
        from CommonServerPython import CommandResults, IndicatorsTimeline
        mocker.patch.object(demisto, 'params', return_value={'insecure': True})
        indicators = ['8.8.8.8']
        timeline = IndicatorsTimeline(indicators=indicators)

        results = CommandResults(
            outputs_prefix=None,
            outputs_key_field=None,
            outputs=None,
            raw_response=indicators,
            indicators_timeline=timeline
        )

        assert sorted(results.to_context().get('IndicatorTimeline')) == sorted([
            {'Value': '8.8.8.8', 'Category': 'Integration Update'}
        ])

    def test_single_indicator(self, mocker):
        """
        Given:
            - a single indicator
        When
           - mocking the demisto.params()
           - creating an Common.IP object
           - creating a CommandResults objects using the indicator member
       Then
           - The CommandResults.to_context() returns single result of standard output IP and DBotScore
       """
        from CommonServerPython import CommandResults, Common, DBotScoreType
        mocker.patch.object(demisto, 'params', return_value={'insecure': True})
        dbot_score = Common.DBotScore(
            indicator='8.8.8.8',
            integration_name='Virus Total',
            indicator_type=DBotScoreType.IP,
            score=Common.DBotScore.GOOD
        )

        ip = Common.IP(
            ip='8.8.8.8',
            dbot_score=dbot_score
        )

        results = CommandResults(
            indicator=ip
        )

        assert results.to_context()['EntryContext'] == {
            'IP(val.Address && val.Address == obj.Address)': [
                {
                    'Address': '8.8.8.8'
                }
            ],
            'DBotScore(val.Indicator && val.Indicator == '
            'obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)': [
                {
                    'Indicator': '8.8.8.8',
                    'Type': 'ip',
                    'Vendor': 'Virus Total',
                    'Score': 1
                }
            ]
        }

    def test_single_indicator_with_indicators(self, mocker):
        """
        Given:
            - a single indicator and a list of indicators
        When
           - mocking the demisto.params()
           - creating an Common.IP object
           - creating a CommandResults objects using the indicator member AND indicators member
       Then
           - The CommandResults.__init__() should raise an ValueError with appropriate error
       """
        from CommonServerPython import CommandResults, Common, DBotScoreType
        mocker.patch.object(demisto, 'params', return_value={'insecure': True})
        dbot_score = Common.DBotScore(
            indicator='8.8.8.8',
            integration_name='Virus Total',
            indicator_type=DBotScoreType.IP,
            score=Common.DBotScore.GOOD
        )

        ip = Common.IP(
            ip='8.8.8.8',
            dbot_score=dbot_score
        )

        with pytest.raises(ValueError) as e:
            CommandResults(
                indicator=ip,
                indicators=[ip]
            )
        assert e.value.args[0] == 'indicators is DEPRECATED, use only indicator'

    def test_indicator_with_no_auto_extract(self):
        """
       Given:
           - a list of an indicator
           - ignore_auto_extract set to True
       When
           - creating a CommandResults object with an indicator
           - using Ignore Auto Extract

       Then
           - the IgnoreAutoExtract field is set to True
       """
        from CommonServerPython import CommandResults

        indicators = ['8.8.8.8']

        results = CommandResults(
            outputs_prefix=None,
            outputs_key_field=None,
            outputs=None,
            raw_response=indicators,
            indicators_timeline=None,
            ignore_auto_extract=True
        )

        assert results.to_context().get('IgnoreAutoExtract') is True


class TestBaseClient:
    from CommonServerPython import BaseClient
    text = {"status": "ok"}
    client = BaseClient('http://example.com/api/v2/', ok_codes=(200, 201))

    RETRIES_POSITIVE_TEST = [
        'get',
        'put',
        'post'
    ]

    @pytest.mark.skip(reason="Test - too long, only manual")
    @pytest.mark.parametrize('method', RETRIES_POSITIVE_TEST)
    def test_http_requests_with_retry_sanity(self, method):
        """
            Given
            - A base client

            When
            - Making http request call with retries configured to a number higher then 0

            Then
            -  Ensure a successful request return response as expected
        """
        url = 'http://httpbin.org/{}'.format(method)
        res = self.client._http_request(method,
                                        '',
                                        full_url=url,
                                        retries=1,
                                        status_list_to_retry=[401])
        assert res['url'] == url

    RETRIES_NEGATIVE_TESTS_INPUT = [
        ('get', 400), ('get', 401), ('get', 500),
        ('put', 400), ('put', 401), ('put', 500),
        ('post', 400), ('post', 401), ('post', 500),
    ]

    @pytest.mark.skip(reason="Test - too long, only manual")
    @pytest.mark.parametrize('method, status', RETRIES_NEGATIVE_TESTS_INPUT)
    def test_http_requests_with_retry_negative_sanity(self, method, status):
        """
            Given
            - A base client

            When
            - Making http request call with retries configured to a number higher then 0

            Then
            -  An unsuccessful request returns a DemistoException regardless the bad status code.
        """
        from CommonServerPython import DemistoException
        with raises(DemistoException, match='{}'.format(status)):
            self.client._http_request(method,
                                      '',
                                      full_url='http://httpbin.org/status/{}'.format(status),
                                      retries=3,
                                      status_list_to_retry=[400, 401, 500])

    def test_http_request_json(self, requests_mock):
        requests_mock.get('http://example.com/api/v2/event', text=json.dumps(self.text))
        res = self.client._http_request('get', 'event')
        assert res == self.text

    def test_http_request_json_negative(self, requests_mock):
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event', text='notjson')
        with raises(DemistoException, match="Failed to parse json"):
            self.client._http_request('get', 'event')

    def test_http_request_text(self, requests_mock):
        requests_mock.get('http://example.com/api/v2/event', text=json.dumps(self.text))
        res = self.client._http_request('get', 'event', resp_type='text')
        assert res == json.dumps(self.text)

    def test_http_request_content(self, requests_mock):
        requests_mock.get('http://example.com/api/v2/event', content=str.encode(json.dumps(self.text)))
        res = self.client._http_request('get', 'event', resp_type='content')
        assert json.loads(res) == self.text

    def test_http_request_response(self, requests_mock):
        requests_mock.get('http://example.com/api/v2/event')
        res = self.client._http_request('get', 'event', resp_type='response')
        assert isinstance(res, requests.Response)

    def test_http_request_not_ok(self, requests_mock):
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event', status_code=500)
        with raises(DemistoException, match="[500]"):
            self.client._http_request('get', 'event')

    def test_http_request_not_ok_but_ok(self, requests_mock):
        requests_mock.get('http://example.com/api/v2/event', status_code=500)
        res = self.client._http_request('get', 'event', resp_type='response', ok_codes=(500,))
        assert res.status_code == 500

    def test_http_request_not_ok_with_json(self, requests_mock):
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event', status_code=500, content=str.encode(json.dumps(self.text)))
        with raises(DemistoException, match="Error in API call"):
            self.client._http_request('get', 'event')

    def test_http_request_not_ok_with_json_parsing(self, requests_mock):
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event', status_code=500, content=str.encode(json.dumps(self.text)))
        with raises(DemistoException) as exception:
            self.client._http_request('get', 'event')
        message = str(exception.value)
        response_json_error = json.loads(message.split('\n')[1])
        assert response_json_error == self.text

    def test_http_request_timeout(self, requests_mock):
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event', exc=requests.exceptions.ConnectTimeout)
        with raises(DemistoException, match="Connection Timeout Error"):
            self.client._http_request('get', 'event')

    def test_http_request_ssl_error(self, requests_mock):
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event', exc=requests.exceptions.SSLError)
        with raises(DemistoException, match="SSL Certificate Verification Failed"):
            self.client._http_request('get', 'event', resp_type='response')

    def test_http_request_proxy_error(self, requests_mock):
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event', exc=requests.exceptions.ProxyError)
        with raises(DemistoException, match="Proxy Error"):
            self.client._http_request('get', 'event', resp_type='response')

    def test_http_request_connection_error(self, requests_mock):
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event', exc=requests.exceptions.ConnectionError)
        with raises(DemistoException, match="Verify that the server URL parameter"):
            self.client._http_request('get', 'event', resp_type='response')

    def test_text_exception_parsing(self, requests_mock):
        from CommonServerPython import DemistoException
        reason = 'Bad Request'
        text = 'additional text'
        requests_mock.get('http://example.com/api/v2/event',
                          status_code=400,
                          reason=reason,
                          text=text)
        with raises(DemistoException, match='- {}\n{}'.format(reason, text)):
            self.client._http_request('get', 'event', resp_type='text')

    def test_json_exception_parsing(self, requests_mock):
        from CommonServerPython import DemistoException
        reason = 'Bad Request'
        json_response = {'error': 'additional text'}
        requests_mock.get('http://example.com/api/v2/event',
                          status_code=400,
                          reason=reason,
                          json=json_response)
        with raises(DemistoException, match='- {}\n.*{}'.format(reason, json_response["error"])):
            self.client._http_request('get', 'event', resp_type='text')

    def test_exception_response_json_parsing_when_ok_code_is_invalid(self, requests_mock):
        from CommonServerPython import DemistoException
        json_response = {'error': 'additional text'}
        requests_mock.get('http://example.com/api/v2/event',
                          status_code=400,
                          json=json_response)
        try:
            self.client._http_request('get', 'event', ok_codes=(200,))
        except DemistoException as e:
            resp_json = e.res.json()
            assert e.res.status_code == 400
            assert resp_json.get('error') == 'additional text'

    def test_exception_response_text_parsing_when_ok_code_is_invalid(self, requests_mock):
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event',
                          status_code=400,
                          text='{"error": "additional text"}')
        try:
            self.client._http_request('get', 'event', ok_codes=(200,))
        except DemistoException as e:
            resp_json = json.loads(e.res.text)
            assert e.res.status_code == 400
            assert resp_json.get('error') == 'additional text'

    def test_is_valid_ok_codes_empty(self):
        from requests import Response
        from CommonServerPython import BaseClient
        new_client = BaseClient('http://example.com/api/v2/')
        response = Response()
        response.status_code = 200
        assert new_client._is_status_code_valid(response, None)

    def test_is_valid_ok_codes_from_function(self):
        from requests import Response
        response = Response()
        response.status_code = 200
        assert self.client._is_status_code_valid(response, (200, 201))

    def test_is_valid_ok_codes_from_self(self):
        from requests import Response
        response = Response()
        response.status_code = 200
        assert self.client._is_status_code_valid(response, None)

    def test_is_valid_ok_codes_empty_false(self):
        from requests import Response
        response = Response()
        response.status_code = 400
        assert not self.client._is_status_code_valid(response, None)

    def test_is_valid_ok_codes_from_function_false(self):
        from requests import Response
        response = Response()
        response.status_code = 400
        assert not self.client._is_status_code_valid(response, (200, 201))

    def test_is_valid_ok_codes_from_self_false(self):
        from requests import Response
        response = Response()
        response.status_code = 400
        assert not self.client._is_status_code_valid(response)


def test_parse_date_string():
    # test unconverted data remains: Z
    assert parse_date_string('2019-09-17T06:16:39Z') == datetime(2019, 9, 17, 6, 16, 39)

    # test unconverted data remains: .22Z
    assert parse_date_string('2019-09-17T06:16:39.22Z') == datetime(2019, 9, 17, 6, 16, 39, 220000)

    # test time data without ms does not match format with ms
    assert parse_date_string('2019-09-17T06:16:39Z', '%Y-%m-%dT%H:%M:%S.%f') == datetime(2019, 9, 17, 6, 16, 39)

    # test time data with timezone Z does not match format with timezone +05:00
    assert parse_date_string('2019-09-17T06:16:39Z', '%Y-%m-%dT%H:%M:%S+05:00') == datetime(2019, 9, 17, 6, 16, 39)

    # test time data with timezone +05:00 does not match format with timezone Z
    assert parse_date_string('2019-09-17T06:16:39+05:00', '%Y-%m-%dT%H:%M:%SZ') == datetime(2019, 9, 17, 6, 16, 39)

    # test time data with timezone -05:00 and with ms does not match format with timezone +02:00 without ms
    assert parse_date_string(
        '2019-09-17T06:16:39.4040+05:00', '%Y-%m-%dT%H:%M:%S+02:00'
    ) == datetime(2019, 9, 17, 6, 16, 39, 404000)


def test_override_print(mocker):
    mocker.patch.object(demisto, 'info')
    int_logger = IntegrationLogger()
    int_logger.set_buffering(False)
    int_logger.print_override("test", "this")
    assert demisto.info.call_count == 1
    assert demisto.info.call_args[0][0] == "test this"
    demisto.info.reset_mock()
    int_logger.print_override("test", "this", file=sys.stderr)
    assert demisto.info.call_count == 1
    assert demisto.info.call_args[0][0] == "test this"
    buf = StringIO()
    # test writing to custom file (not stdout/stderr)
    int_logger.print_override("test", "this", file=buf)
    assert buf.getvalue() == 'test this\n'


def test_http_client_debug(mocker):
    if not IS_PY3:
        pytest.skip("test not supported in py2")
        return
    mocker.patch.object(demisto, 'info')
    debug_log = DebugLogger()
    from http.client import HTTPConnection
    HTTPConnection.debuglevel = 1
    con = HTTPConnection("google.com")
    con.request('GET', '/')
    r = con.getresponse()
    r.read()
    assert demisto.info.call_count > 5
    assert debug_log is not None


def test_http_client_debug_int_logger_sensitive_query_params(mocker):
    if not IS_PY3:
        pytest.skip("test not supported in py2")
        return
    mocker.patch.object(demisto, 'params', return_value={'APIKey': 'dummy'})
    mocker.patch.object(demisto, 'info')
    debug_log = DebugLogger()
    from http.client import HTTPConnection
    HTTPConnection.debuglevel = 1
    con = HTTPConnection("google.com")
    con.request('GET', '?apikey=dummy')
    r = con.getresponse()
    r.read()
    assert debug_log
    for arg in demisto.info.call_args_list:
        assert 'dummy' not in arg[0][0]
        if 'apikey' in arg[0][0]:
            assert 'apikey=<XX_REPLACED>' in arg[0][0]


class TestParseDateRange:
    @staticmethod
    def test_utc_time_sanity():
        utc_now = datetime.utcnow()
        utc_start_time, utc_end_time = parse_date_range('2 days', utc=True)
        # testing UTC date time and range of 2 days
        assert utc_now.replace(microsecond=0) == utc_end_time.replace(microsecond=0)
        assert abs(utc_start_time - utc_end_time).days == 2

    @staticmethod
    def test_local_time_sanity():
        local_now = datetime.now()
        local_start_time, local_end_time = parse_date_range('73 minutes', utc=False)
        # testing local datetime and range of 73 minutes
        assert local_now.replace(microsecond=0) == local_end_time.replace(microsecond=0)
        assert abs(local_start_time - local_end_time).seconds / 60 == 73

    @staticmethod
    def test_with_trailing_spaces():
        utc_now = datetime.utcnow()
        utc_start_time, utc_end_time = parse_date_range('2 days   ', utc=True)
        # testing UTC date time and range of 2 days
        assert utc_now.replace(microsecond=0) == utc_end_time.replace(microsecond=0)
        assert abs(utc_start_time - utc_end_time).days == 2

    @staticmethod
    def test_case_insensitive():
        utc_now = datetime.utcnow()
        utc_start_time, utc_end_time = parse_date_range('2 Days', utc=True)
        # testing UTC date time and range of 2 days
        assert utc_now.replace(microsecond=0) == utc_end_time.replace(microsecond=0)
        assert abs(utc_start_time - utc_end_time).days == 2

    @staticmethod
    def test_error__invalid_input_format(mocker):
        mocker.patch.object(sys, 'exit', side_effect=Exception('mock exit'))
        demisto_results = mocker.spy(demisto, 'results')

        try:
            parse_date_range('2 Days ago', utc=True)
        except Exception as exp:
            assert str(exp) == 'mock exit'
        results = demisto.results.call_args[0][0]
        assert 'date_range must be "number date_range_unit"' in results['Contents']

    @staticmethod
    def test_error__invalid_time_value_not_a_number(mocker):
        mocker.patch.object(sys, 'exit', side_effect=Exception('mock exit'))
        demisto_results = mocker.spy(demisto, 'results')

        try:
            parse_date_range('ten Days', utc=True)
        except Exception as exp:
            assert str(exp) == 'mock exit'
        results = demisto.results.call_args[0][0]
        assert 'The time value is invalid' in results['Contents']

    @staticmethod
    def test_error__invalid_time_value_not_an_integer(mocker):
        mocker.patch.object(sys, 'exit', side_effect=Exception('mock exit'))
        demisto_results = mocker.spy(demisto, 'results')

        try:
            parse_date_range('1.5 Days', utc=True)
        except Exception as exp:
            assert str(exp) == 'mock exit'
        results = demisto.results.call_args[0][0]
        assert 'The time value is invalid' in results['Contents']

    @staticmethod
    def test_error__invalid_time_unit(mocker):
        mocker.patch.object(sys, 'exit', side_effect=Exception('mock exit'))
        demisto_results = mocker.spy(demisto, 'results')

        try:
            parse_date_range('2 nights', utc=True)
        except Exception as exp:
            assert str(exp) == 'mock exit'
        results = demisto.results.call_args[0][0]
        assert 'The unit of date_range is invalid' in results['Contents']


def test_encode_string_results():
    s = "test"
    assert s == encode_string_results(s)
    s2 = u"בדיקה"
    if IS_PY3:
        res = str(s2)
    else:
        res = s2.encode("utf8")
    assert encode_string_results(s2) == res
    not_string = [1, 2, 3]
    assert not_string == encode_string_results(not_string)


class TestReturnOutputs:
    def test_return_outputs(self, mocker):
        mocker.patch.object(demisto, 'results')
        md = 'md'
        outputs = {'Event': 1}
        raw_response = {'event': 1}
        return_outputs(md, outputs, raw_response)
        results = demisto.results.call_args[0][0]
        assert len(demisto.results.call_args[0]) == 1
        assert demisto.results.call_count == 1
        assert raw_response == results['Contents']
        assert 'json' == results['ContentsFormat']
        assert outputs == results['EntryContext']
        assert md == results['HumanReadable']

    def test_return_outputs_only_md(self, mocker):
        mocker.patch.object(demisto, 'results')
        md = 'md'
        return_outputs(md)
        results = demisto.results.call_args[0][0]
        assert len(demisto.results.call_args[0]) == 1
        assert demisto.results.call_count == 1
        assert md == results['HumanReadable']
        assert 'text' == results['ContentsFormat']

    def test_return_outputs_raw_none(self, mocker):
        mocker.patch.object(demisto, 'results')
        md = 'md'
        outputs = {'Event': 1}
        return_outputs(md, outputs, None)
        results = demisto.results.call_args[0][0]
        assert len(demisto.results.call_args[0]) == 1
        assert demisto.results.call_count == 1
        assert outputs == results['Contents']
        assert 'json' == results['ContentsFormat']
        assert outputs == results['EntryContext']
        assert md == results['HumanReadable']

    def test_return_outputs_timeline(self, mocker):
        mocker.patch.object(demisto, 'results')
        md = 'md'
        outputs = {'Event': 1}
        raw_response = {'event': 1}
        timeline = [{'Value': 'blah', 'Message': 'test', 'Category': 'test'}]
        return_outputs(md, outputs, raw_response, timeline)
        results = demisto.results.call_args[0][0]
        assert len(demisto.results.call_args[0]) == 1
        assert demisto.results.call_count == 1
        assert raw_response == results['Contents']
        assert 'json' == results['ContentsFormat']
        assert outputs == results['EntryContext']
        assert md == results['HumanReadable']
        assert timeline == results['IndicatorTimeline']

    def test_return_outputs_timeline_without_category(self, mocker):
        mocker.patch.object(demisto, 'results')
        md = 'md'
        outputs = {'Event': 1}
        raw_response = {'event': 1}
        timeline = [{'Value': 'blah', 'Message': 'test'}]
        return_outputs(md, outputs, raw_response, timeline)
        results = demisto.results.call_args[0][0]
        assert len(demisto.results.call_args[0]) == 1
        assert demisto.results.call_count == 1
        assert raw_response == results['Contents']
        assert 'json' == results['ContentsFormat']
        assert outputs == results['EntryContext']
        assert md == results['HumanReadable']
        assert 'Category' in results['IndicatorTimeline'][0].keys()
        assert results['IndicatorTimeline'][0]['Category'] == 'Integration Update'

    def test_return_outputs_ignore_auto_extract(self, mocker):
        mocker.patch.object(demisto, 'results')
        md = 'md'
        outputs = {'Event': 1}
        raw_response = {'event': 1}
        ignore_auto_extract = True
        return_outputs(md, outputs, raw_response, ignore_auto_extract=ignore_auto_extract)
        results = demisto.results.call_args[0][0]
        assert len(demisto.results.call_args[0]) == 1
        assert demisto.results.call_count == 1
        assert raw_response == results['Contents']
        assert 'json' == results['ContentsFormat']
        assert outputs == results['EntryContext']
        assert md == results['HumanReadable']
        assert ignore_auto_extract == results['IgnoreAutoExtract']

    def test_return_outputs_text_raw_response(self, mocker):
        mocker.patch.object(demisto, 'results')
        md = 'md'
        raw_response = 'string'
        return_outputs(md, raw_response=raw_response)
        results = demisto.results.call_args[0][0]
        assert len(demisto.results.call_args[0]) == 1
        assert demisto.results.call_count == 1
        assert raw_response == results['Contents']
        assert 'text' == results['ContentsFormat']


def test_argToBoolean():
    assert argToBoolean('true') is True
    assert argToBoolean('yes') is True
    assert argToBoolean('TrUe') is True
    assert argToBoolean(True) is True

    assert argToBoolean('false') is False
    assert argToBoolean('no') is False
    assert argToBoolean(False) is False


batch_params = [
    # full batch case
    ([1, 2, 3], 1, [[1], [2], [3]]),
    # empty case
    ([], 1, []),
    # out of index case
    ([1, 2, 3], 5, [[1, 2, 3]]),
    # out of index in end with batches
    ([1, 2, 3, 4, 5], 2, [[1, 2], [3, 4], [5]]),
    ([1] * 100, 2, [[1, 1]] * 50)
]


@pytest.mark.parametrize('iterable, sz, expected', batch_params)
def test_batch(iterable, sz, expected):
    for i, item in enumerate(batch(iterable, sz)):
        assert expected[i] == item


regexes_test = [
    (ipv4Regex, '192.168.1.1', True),
    (ipv4Regex, '192.168.1.1/24', False),
    (ipv4Regex, '192.168.a.1', False),
    (ipv4Regex, '192.168..1.1', False),
    (ipv4Regex, '192.256.1.1', False),
    (ipv4Regex, '192.256.1.1.1', False),
    (ipv4cidrRegex, '192.168.1.1/32', True),
    (ipv4cidrRegex, '192.168.1.1.1/30', False),
    (ipv4cidrRegex, '192.168.1.b/30', False),
    (ipv4cidrRegex, '192.168.1.12/381', False),
    (ipv6Regex, '2001:db8:a0b:12f0::1', True),
    (ipv6Regex, '2001:db8:a0b:12f0::1/11', False),
    (ipv6Regex, '2001:db8:a0b:12f0::1::1', False),
    (ipv6Regex, '2001:db8:a0b:12f0::98aa5', False),
    (ipv6cidrRegex, '2001:db8:a0b:12f0::1/64', True),
    (ipv6cidrRegex, '2001:db8:a0b:12f0::1/256', False),
    (ipv6cidrRegex, '2001:db8:a0b:12f0::1::1/25', False),
    (ipv6cidrRegex, '2001:db8:a0b:12f0::1aaasds::1/1', False)
]


@pytest.mark.parametrize('pattern, string, expected', regexes_test)
def test_regexes(pattern, string, expected):
    # (str, str, bool) -> None
    # emulates re.fullmatch from py3.4
    assert expected is bool(re.match("(?:" + pattern + r")\Z", string))


IP_TO_INDICATOR_TYPE_PACK = [
    ('192.168.1.1', FeedIndicatorType.IP),
    ('192.168.1.1/32', FeedIndicatorType.CIDR),
    ('2001:db8:a0b:12f0::1', FeedIndicatorType.IPv6),
    ('2001:db8:a0b:12f0::1/64', FeedIndicatorType.IPv6CIDR),
]


@pytest.mark.parametrize('ip, indicator_type', IP_TO_INDICATOR_TYPE_PACK)
def test_ip_to_indicator(ip, indicator_type):
    assert FeedIndicatorType.ip_to_indicator_type(ip) is indicator_type


data_test_b64_encode = [
    (u'test', 'dGVzdA=='),
    ('test', 'dGVzdA=='),
    (b'test', 'dGVzdA=='),
    ('', ''),
    ('%', 'JQ=='),
    (u'§', 'wqc='),
    (u'§t`e§s`t§', 'wqd0YGXCp3NgdMKn'),
]


@pytest.mark.parametrize('_input, expected_output', data_test_b64_encode)
def test_b64_encode(_input, expected_output):
    output = b64_encode(_input)
    assert output == expected_output, 'b64_encode({}) returns: {} instead: {}'.format(_input, output, expected_output)


def test_traceback_in_return_error_debug_mode_on(mocker):
    mocker.patch.object(demisto, 'command', return_value="test-command")
    mocker.spy(demisto, 'results')
    mocker.patch('CommonServerPython.is_debug_mode', return_value=True)
    from CommonServerPython import return_error

    try:
        raise Exception("This is a test string")
    except Exception:
        with pytest.raises(SystemExit):
            return_error("some text")

    assert "This is a test string" in str(demisto.results.call_args)
    assert "Traceback" in str(demisto.results.call_args)
    assert "some text" in str(demisto.results.call_args)


def test_traceback_in_return_error_debug_mode_off(mocker):
    mocker.patch.object(demisto, 'command', return_value="test-command")
    mocker.spy(demisto, 'results')
    mocker.patch('CommonServerPython.is_debug_mode', return_value=False)
    from CommonServerPython import return_error

    try:
        raise Exception("This is a test string")
    except Exception:
        with pytest.raises(SystemExit):
            return_error("some text")

    assert "This is a test string" not in str(demisto.results.call_args)
    assert "Traceback" not in str(demisto.results.call_args)
    assert "some text" in str(demisto.results.call_args)


# append_context unit test
CONTEXT_MOCK = {
    'str_key': 'str_value',
    'dict_key': {
        'key1': 'val1',
        'key2': 'val2'
    },
    'int_key': 1,
    'list_key_str': ['val1', 'val2'],
    'list_key_list': ['val1', 'val2'],
    'list_key_dict': ['val1', 'val2']
}

UPDATED_CONTEXT = {
    'str_key': 'str_data,str_value',
    'dict_key': {
        'key1': 'val1',
        'key2': 'val2',
        'data_key': 'data_val'
    },
    'int_key': [1, 2],
    'list_key_str': ['val1', 'val2', 'str_data'],
    'list_key_list': ['val1', 'val2', 'val1', 'val2'],
    'list_key_dict': ['val1', 'val2', {'data_key': 'data_val'}]
}

DATA_MOCK_STRING = "str_data"
DATA_MOCK_LIST = ['val1', 'val2']
DATA_MOCK_DICT = {
    'data_key': 'data_val'
}
DATA_MOCK_INT = 2

STR_KEY = "str_key"
DICT_KEY = "dict_key"

APPEND_CONTEXT_INPUT = [
    (CONTEXT_MOCK, DATA_MOCK_STRING, STR_KEY, "key = {}, val = {}".format(STR_KEY, UPDATED_CONTEXT[STR_KEY])),
    (CONTEXT_MOCK, DATA_MOCK_LIST, STR_KEY, "TypeError"),
    (CONTEXT_MOCK, DATA_MOCK_DICT, STR_KEY, "TypeError"),

    (CONTEXT_MOCK, DATA_MOCK_STRING, DICT_KEY, "TypeError"),
    (CONTEXT_MOCK, DATA_MOCK_LIST, DICT_KEY, "TypeError"),
    (CONTEXT_MOCK, DATA_MOCK_DICT, DICT_KEY, "key = {}, val = {}".format(DICT_KEY, UPDATED_CONTEXT[DICT_KEY])),

    (CONTEXT_MOCK, DATA_MOCK_STRING, 'list_key_str',
     "key = {}, val = {}".format('list_key_str', UPDATED_CONTEXT['list_key_str'])),
    (CONTEXT_MOCK, DATA_MOCK_LIST, 'list_key_list',
     "key = {}, val = {}".format('list_key_list', UPDATED_CONTEXT['list_key_list'])),
    (CONTEXT_MOCK, DATA_MOCK_DICT, 'list_key_dict',
     "key = {}, val = {}".format('list_key_dict', UPDATED_CONTEXT['list_key_dict'])),

    (CONTEXT_MOCK, DATA_MOCK_INT, 'int_key', "key = {}, val = {}".format('int_key', UPDATED_CONTEXT['int_key'])),
]


def get_set_context(key, val):
    from CommonServerPython import return_error
    return_error("key = {}, val = {}".format(key, val))


@pytest.mark.parametrize('context_mock, data_mock, key, expected_answer', APPEND_CONTEXT_INPUT)
def test_append_context(mocker, context_mock, data_mock, key, expected_answer):
    from CommonServerPython import demisto
    mocker.patch.object(demisto, 'get', return_value=context_mock.get(key))
    mocker.patch.object(demisto, 'setContext', side_effect=get_set_context)
    mocker.patch.object(demisto, 'results')

    if "TypeError" not in expected_answer:
        with raises(SystemExit, match='0'):
            appendContext(key, data_mock)
            assert expected_answer in demisto.results.call_args[0][0]['Contents']

    else:
        with raises(TypeError) as e:
            appendContext(key, data_mock)
            assert expected_answer in e.value


INDICATOR_VALUE_AND_TYPE = [
    ('3fec1b14cea32bbcd97fad4507b06888', "File"),
    ('1c8893f75089a27ca6a8d49801d7aa6b64ea0c6167fe8b1becfe9bc13f47bdc1', 'File'),
    ('castaneda-thornton.com', 'Domain'),
    ('192.0.0.1', 'IP'),
    ('test@gmail.com', 'Email'),
    ('e775eb1250137c0b83d4e7c4549c71d6f10cae4e708ebf0b5c4613cbd1e91087', 'File'),
    ('test@yahoo.com', 'Email'),
    ('http://test.com', 'URL'),
    ('11.111.11.11/11', 'CIDR'),
    ('CVE-0000-0000', 'CVE'),
    ('dbot@demisto.works', 'Email'),
    ('37b6d02m-63e0-495e-kk92-7c21511adc7a@SB2APC01FT091.outlook.com', 'Email'),
    ('dummy@recipient.com', 'Email'),
    ('image003.gif@01CF4D7F.1DF62650', 'Email'),
    ('bruce.wayne@pharmtech.zz', 'Email'),
    ('joe@gmail.com', 'Email'),
    ('koko@demisto.com', 'Email'),
    ('42a5e275559a1651b3df8e15d3f5912499f0f2d3d1523959c56fc5aea6371e59', 'File'),
    ('10676cf66244cfa91567fbc1a937f4cb19438338b35b69d4bcc2cf0d3a44af5e', 'File'),
    ('52483514f07eb14570142f6927b77deb7b4da99f', 'File'),
    ('c8092abd8d581750c0530fa1fc8d8318', 'File'),
    ('fe80:0000:0000:0000:91ba:7558:26d3:acde', 'IPv6'),
    ('fd60:e22:f1b9::2', 'IPv6'),
    ('2001:db8:0000:0000:0000:0000:0000:0000', 'IPv6'),
    ('112.126.94.107', 'IP'),
    ('a', None),
    ('*castaneda-thornton.com', 'DomainGlob'),
    (
        '53e6baa124f54462786f1122e98e38ff1be3de82fe2a96b1849a8637043fd847eec7e0f53307bddf7a066565292d500c36c941f1f3bb9dcac807b2f4a0bfce1b',
        'File')
]


@pytest.mark.parametrize('indicator_value, indicatory_type', INDICATOR_VALUE_AND_TYPE)
def test_auto_detect_indicator_type(indicator_value, indicatory_type):
    """
        Given
            - Indicator value
            - Indicator type

        When
        - Trying to detect the type of an indicator.

        Then
        -  Run the auto_detect_indicator_type and validate that the indicator type the function returns is as expected.
    """
    if sys.version_info.major == 3 and sys.version_info.minor == 8:
        assert auto_detect_indicator_type(indicator_value) == indicatory_type
    else:
        try:
            auto_detect_indicator_type(indicator_value)
        except Exception as e:
            assert str(e) == "Missing tldextract module, In order to use the auto detect function please" \
                             " use a docker image with it installed such as: demisto/jmespath"


def test_handle_proxy(mocker):
    os.environ['REQUESTS_CA_BUNDLE'] = '/test1.pem'
    mocker.patch.object(demisto, 'params', return_value={'insecure': True})
    handle_proxy()
    assert os.getenv('REQUESTS_CA_BUNDLE') is None
    os.environ['REQUESTS_CA_BUNDLE'] = '/test2.pem'
    mocker.patch.object(demisto, 'params', return_value={})
    handle_proxy()
    assert os.environ['REQUESTS_CA_BUNDLE'] == '/test2.pem'  # make sure no change
    mocker.patch.object(demisto, 'params', return_value={'unsecure': True})
    handle_proxy()
    assert os.getenv('REQUESTS_CA_BUNDLE') is None


@pytest.mark.parametrize(argnames="dict_obj, keys, expected, default_return_value",
                         argvalues=[
                             ({'a': '1'}, ['a'], '1', None),
                             ({'a': {'b': '2'}}, ['a', 'b'], '2', None),
                             ({'a': {'b': '2'}}, ['a', 'c'], 'test', 'test'),
                         ])
def test_safe_get(dict_obj, keys, expected, default_return_value):
    from CommonServerPython import dict_safe_get
    assert expected == dict_safe_get(dict_object=dict_obj,
                                     keys=keys,
                                     default_return_value=default_return_value)


MIRRORS = '''
   [{
     "channel_id":"GKQ86DVPH",
     "channel_name": "incident-681",
     "channel_topic": "incident-681",
     "investigation_id":"681",
     "mirror_type":"all",
     "mirror_direction":"both",
     "mirror_to":"group",
     "auto_close":true,
     "mirrored":true
  },
  {
     "channel_id":"GKB19PA3V",
     "channel_name": "group2",
     "channel_topic": "cooltopic",
     "investigation_id":"684",
     "mirror_type":"all",
     "mirror_direction":"both",
     "mirror_to":"group",
     "auto_close":true,
     "mirrored":true
  },
  {
     "channel_id":"GKB19PA3V",
     "channel_name": "group2",
     "channel_topic": "cooltopic",
     "investigation_id":"692",
     "mirror_type":"all",
     "mirror_direction":"both",
     "mirror_to":"group",
     "auto_close":true,
     "mirrored":true
  },
  {
     "channel_id":"GKNEJU4P9",
     "channel_name": "group3",
     "channel_topic": "incident-713",
     "investigation_id":"713",
     "mirror_type":"all",
     "mirror_direction":"both",
     "mirror_to":"group",
     "auto_close":true,
     "mirrored":true
  },
  {
     "channel_id":"GL8GHC0LV",
     "channel_name": "group5",
     "channel_topic": "incident-734",
     "investigation_id":"734",
     "mirror_type":"all",
     "mirror_direction":"both",
     "mirror_to":"group",
     "auto_close":true,
     "mirrored":true
  }]
'''

CONVERSATIONS = '''[{
    "id": "C012AB3CD",
    "name": "general",
    "is_channel": true,
    "is_group": false,
    "is_im": false,
    "created": 1449252889,
    "creator": "U012A3CDE",
    "is_archived": false,
    "is_general": true,
    "unlinked": 0,
    "name_normalized": "general",
    "is_shared": false,
    "is_ext_shared": false,
    "is_org_shared": false,
    "pending_shared": [],
    "is_pending_ext_shared": false,
    "is_member": true,
    "is_private": false,
    "is_mpim": false,
    "topic": {
        "value": "Company-wide announcements and work-based matters",
        "creator": "",
        "last_set": 0
    },
    "purpose": {
        "value": "This channel is for team-wide communication and announcements. All team members are in this channel.",
        "creator": "",
        "last_set": 0
    },
    "previous_names": [],
    "num_members": 4
},
{
    "id": "C061EG9T2",
    "name": "random",
    "is_channel": true,
    "is_group": false,
    "is_im": false,
    "created": 1449252889,
    "creator": "U061F7AUR",
    "is_archived": false,
    "is_general": false,
    "unlinked": 0,
    "name_normalized": "random",
    "is_shared": false,
    "is_ext_shared": false,
    "is_org_shared": false,
    "pending_shared": [],
    "is_pending_ext_shared": false,
    "is_member": true,
    "is_private": false,
    "is_mpim": false,
    "topic": {
        "value": "Non-work banter and water cooler conversation",
        "creator": "",
        "last_set": 0
    },
    "purpose": {
        "value": "A place for non-work-related flimflam.",
        "creator": "",
        "last_set": 0
    },
    "previous_names": [],
    "num_members": 4
}]'''

OBJECTS_TO_KEYS = {
    'mirrors': 'investigation_id',
    'questions': 'entitlement',
    'users': 'id'
}


def set_integration_context_versioned(integration_context, version=-1, sync=False):
    global INTEGRATION_CONTEXT_VERSIONED

    try:
        if not INTEGRATION_CONTEXT_VERSIONED:
            INTEGRATION_CONTEXT_VERSIONED = {'context': '{}', 'version': 0}
    except NameError:
        INTEGRATION_CONTEXT_VERSIONED = {'context': '{}', 'version': 0}

    current_version = INTEGRATION_CONTEXT_VERSIONED['version']
    if version != -1 and version <= current_version:
        raise ValueError('DB Insert version {} does not match version {}'.format(current_version, version))

    INTEGRATION_CONTEXT_VERSIONED = {'context': integration_context, 'version': current_version + 1}


def get_integration_context_versioned(refresh=False):
    return INTEGRATION_CONTEXT_VERSIONED


def test_merge_lists():
    from CommonServerPython import merge_lists

    # Set
    original = [{'id': '1', 'updated': 'n'}, {'id': '2', 'updated': 'n'}, {'id': '11', 'updated': 'n'}]
    updated = [{'id': '1', 'updated': 'y'}, {'id': '3', 'updated': 'y'}, {'id': '11', 'updated': 'n', 'remove': True}]
    expected = [{'id': '1', 'updated': 'y'}, {'id': '2', 'updated': 'n'}, {'id': '3', 'updated': 'y'}]

    # Arrange
    result = merge_lists(original, updated, 'id')

    # Assert
    assert len(result) == len(expected)
    for obj in result:
        assert obj in expected


@pytest.mark.parametrize('version, expected',
                         [
                             ({'version': '5.5.0'}, False),
                             ({'version': '6.0.0'}, True),
                         ]
                         )
def test_is_versioned_context_available(mocker, version, expected):
    from CommonServerPython import is_versioned_context_available
    # Set
    mocker.patch.object(demisto, 'demistoVersion', return_value=version)

    # Arrange
    result = is_versioned_context_available()
    get_demisto_version._version = None

    # Assert
    assert expected == result


def test_update_context_merge(mocker):
    import CommonServerPython

    # Set
    set_integration_context_versioned({
        'mirrors': MIRRORS,
        'conversations': CONVERSATIONS
    })

    mocker.patch.object(demisto, 'getIntegrationContextVersioned', return_value=get_integration_context_versioned())
    mocker.patch.object(demisto, 'setIntegrationContextVersioned', side_effecet=set_integration_context_versioned)
    mocker.patch.object(CommonServerPython, 'is_versioned_context_available', return_value=True)

    new_mirror = {
        'channel_id': 'new_group',
        'channel_name': 'incident-999',
        'channel_topic': 'incident-999',
        'investigation_id': '999',
        'mirror_type': 'all',
        'mirror_direction': 'both',
        'mirror_to': 'group',
        'auto_close': True,
        'mirrored': False
    }

    mirrors = json.loads(MIRRORS)
    mirrors.extend([new_mirror])

    # Arrange
    context, version = CommonServerPython.update_integration_context({'mirrors': [new_mirror]}, OBJECTS_TO_KEYS, True)
    new_mirrors = json.loads(context['mirrors'])

    # Assert
    assert len(mirrors) == len(new_mirrors)
    for mirror in mirrors:
        assert mirror in new_mirrors

    assert version == get_integration_context_versioned()['version']


def test_update_context_no_merge(mocker):
    import CommonServerPython

    # Set
    set_integration_context_versioned({
        'mirrors': MIRRORS,
        'conversations': CONVERSATIONS
    })

    mocker.patch.object(demisto, 'getIntegrationContextVersioned', return_value=get_integration_context_versioned())
    mocker.patch.object(demisto, 'setIntegrationContextVersioned', side_effecet=set_integration_context_versioned)
    mocker.patch.object(CommonServerPython, 'is_versioned_context_available', return_value=True)

    new_conversation = {
        'id': 'A0123456',
        'name': 'general'
    }

    conversations = json.loads(CONVERSATIONS)
    conversations.extend([new_conversation])

    # Arrange
    context, version = CommonServerPython.update_integration_context({'conversations': conversations}, OBJECTS_TO_KEYS,
                                                                     True)
    new_conversations = json.loads(context['conversations'])

    # Assert
    assert conversations == new_conversations
    assert version == get_integration_context_versioned()['version']


@pytest.mark.parametrize('versioned_available', [True, False])
def test_get_latest_integration_context(mocker, versioned_available):
    import CommonServerPython

    # Set
    set_integration_context_versioned({
        'mirrors': MIRRORS,
        'conversations': CONVERSATIONS
    })

    mocker.patch.object(demisto, 'getIntegrationContextVersioned', return_value=get_integration_context_versioned())
    mocker.patch.object(demisto, 'setIntegrationContextVersioned', side_effecet=set_integration_context_versioned)
    mocker.patch.object(CommonServerPython, 'is_versioned_context_available', return_value=versioned_available)
    mocker.patch.object(demisto, 'getIntegrationContext',
                        return_value={'mirrors': MIRRORS, 'conversations': CONVERSATIONS})

    # Arrange
    context, ver = CommonServerPython.get_integration_context_with_version(True)

    # Assert
    assert context == get_integration_context_versioned()['context']
    assert ver == get_integration_context_versioned()['version'] if versioned_available else -1


def test_set_latest_integration_context(mocker):
    import CommonServerPython

    # Set
    set_integration_context_versioned({
        'mirrors': MIRRORS,
        'conversations': CONVERSATIONS,
    })

    mocker.patch.object(demisto, 'getIntegrationContextVersioned', return_value=get_integration_context_versioned())
    mocker.patch.object(demisto, 'setIntegrationContextVersioned', side_effecet=set_integration_context_versioned)
    int_context = get_integration_context_versioned()
    mocker.patch.object(CommonServerPython, 'update_integration_context',
                        side_effect=[(int_context['context'], int_context['version']),
                                     (int_context['context'], int_context['version'] + 1)])
    mocker.patch.object(CommonServerPython, 'set_integration_context', side_effect=[ValueError, int_context['context']])

    # Arrange
    CommonServerPython.set_to_integration_context_with_retries({}, OBJECTS_TO_KEYS)
    int_context_calls = CommonServerPython.set_integration_context.call_count
    int_context_args_1 = CommonServerPython.set_integration_context.call_args_list[0][0]
    int_context_args_2 = CommonServerPython.set_integration_context.call_args_list[1][0]

    # Assert
    assert int_context_calls == 2
    assert int_context_args_1 == (int_context['context'], True, int_context['version'])
    assert int_context_args_2 == (int_context['context'], True, int_context['version'] + 1)


def test_set_latest_integration_context_es(mocker):
    import CommonServerPython

    # Set
    mocker.patch.object(demisto, 'getIntegrationContextVersioned', return_value=get_integration_context_versioned())
    mocker.patch.object(demisto, 'setIntegrationContextVersioned', side_effecet=set_integration_context_versioned)
    es_inv_context_version_first = {'version': 5, 'sequenceNumber': 807, 'primaryTerm': 1}
    es_inv_context_version_second = {'version': 7, 'sequenceNumber': 831, 'primaryTerm': 1}
    mocker.patch.object(CommonServerPython, 'update_integration_context',
                        side_effect=[({}, es_inv_context_version_first),
                                     ({}, es_inv_context_version_second)])
    mocker.patch.object(CommonServerPython, 'set_integration_context', side_effect=[ValueError, {}])

    # Arrange
    CommonServerPython.set_to_integration_context_with_retries({})
    int_context_calls = CommonServerPython.set_integration_context.call_count
    int_context_args_1 = CommonServerPython.set_integration_context.call_args_list[0][0]
    int_context_args_2 = CommonServerPython.set_integration_context.call_args_list[1][0]

    # Assert
    assert int_context_calls == 2
    assert int_context_args_1[1:] == (True, es_inv_context_version_first)
    assert int_context_args_2[1:] == (True, es_inv_context_version_second)


def test_set_latest_integration_context_fail(mocker):
    import CommonServerPython

    # Set
    set_integration_context_versioned({
        'mirrors': MIRRORS,
        'conversations': CONVERSATIONS,
    })

    mocker.patch.object(demisto, 'getIntegrationContextVersioned', return_value=get_integration_context_versioned())
    mocker.patch.object(demisto, 'setIntegrationContextVersioned', side_effecet=set_integration_context_versioned)
    int_context = get_integration_context_versioned()
    mocker.patch.object(CommonServerPython, 'update_integration_context', return_value=(
        int_context['context'], int_context['version']
    ))
    mocker.patch.object(CommonServerPython, 'set_integration_context', side_effect=ValueError)

    # Arrange
    with pytest.raises(Exception):
        CommonServerPython.set_to_integration_context_with_retries({}, OBJECTS_TO_KEYS)

    int_context_calls = CommonServerPython.set_integration_context.call_count

    # Assert
    assert int_context_calls == CommonServerPython.CONTEXT_UPDATE_RETRY_TIMES


def test_get_x_content_info_headers(mocker):
    test_license = 'TEST_LICENSE_ID'
    test_brand = 'TEST_BRAND'
    mocker.patch.object(
        demisto,
        'getLicenseID',
        return_value=test_license
    )
    mocker.patch.object(
        demisto,
        'callingContext',
        new_callable=mocker.PropertyMock(return_value={'context': {
            'IntegrationBrand': test_brand,
            'IntegrationInstance': 'TEST_INSTANCE',
        }})
    )
    headers = get_x_content_info_headers()
    assert headers['X-Content-LicenseID'] == test_license
    assert headers['X-Content-Name'] == test_brand


def test_return_results_multiple_command_results(mocker):
    """
    Given:
      - List of 2 CommandResult
    When:
      - Calling return_results()
    Then:
      - demisto.results() is called 2 times (with the list items)
    """
    from CommonServerPython import CommandResults, return_results
    demisto_results_mock = mocker.patch.object(demisto, 'results')
    mock_command_results = []
    for i in range(2):
        mock_output = {'MockContext': i}
        mock_command_results.append(CommandResults(outputs_prefix='Mock', outputs=mock_output))
    return_results(mock_command_results)
    assert demisto_results_mock.call_count == 2


def test_return_results_multiple_dict_results(mocker):
    """
    Given:
      - List of 2 dictionaries
    When:
      - Calling return_results()
    Then:
      - demisto.results() is called 1 time (with the list as an argument)
    """
    from CommonServerPython import return_results
    demisto_results_mock = mocker.patch.object(demisto, 'results')
    mock_command_results = [{'MockContext': 0}, {'MockContext': 1}]
    return_results(mock_command_results)
    args, kwargs = demisto_results_mock.call_args_list[0]
    assert demisto_results_mock.call_count == 1
    assert [{'MockContext': 0}, {'MockContext': 1}] in args


def test_arg_to_int__valid_numbers():
    """
    Given
        valid numbers
    When
        converting them to int
    Then
        ensure proper int returned
    """
    from CommonServerPython import arg_to_number

    result = arg_to_number(
        arg='5',
        arg_name='foo')

    assert result == 5

    result = arg_to_number(
        arg='2.0',
        arg_name='foo')

    assert result == 2

    result = arg_to_number(
        arg=3,
        arg_name='foo')

    assert result == 3

    result = arg_to_number(
        arg=4,
        arg_name='foo',
        required=True)

    assert result == 4

    result = arg_to_number(
        arg=5,
        required=True)

    assert result == 5


def test_arg_to_int__invalid_numbers():
    """
    Given
        invalid numbers
    When
        converting them to int
    Then
        raise ValueError
    """
    from CommonServerPython import arg_to_number

    try:
        arg_to_number(
            arg='aa',
            arg_name='foo')

        assert False

    except ValueError as e:
        assert 'Invalid number' in str(e)


def test_arg_to_int_required():
    """
    Given
        argument foo which with value None

    When
        converting the arg to number via required flag as True

    Then
        ensure ValueError raised
    """
    from CommonServerPython import arg_to_number

    # required set to false
    result = arg_to_number(
        arg=None,
        arg_name='foo',
        required=False)

    assert result is None

    try:
        arg_to_number(
            arg=None,
            arg_name='foo',
            required=True)

        assert False

    except ValueError as e:
        assert 'Missing' in str(e)

    try:
        arg_to_number(
            arg='',
            arg_name='foo',
            required=True)

        assert False

    except ValueError as e:
        assert 'Missing' in str(e)

    try:
        arg_to_number(arg='goo')

        assert False

    except ValueError as e:
        assert '"goo" is not a valid number' in str(e)


def test_arg_to_timestamp_valid_inputs():
    """
    Given
        valid dates provided

    When
        converting dates into timestamp

    Then
        ensure returned int which represents timestamp in milliseconds
    """
    if sys.version_info.major == 2:
        # skip for python 2 - date
        assert True
        return

    from CommonServerPython import arg_to_datetime
    from datetime import datetime, timezone

    # hard coded date
    result = arg_to_datetime(
        arg='2020-11-10T21:43:43Z',
        arg_name='foo'
    )

    assert result == datetime(2020, 11, 10, 21, 43, 43, tzinfo=timezone.utc)

    # relative dates also work
    result = arg_to_datetime(
        arg='2 hours ago',
        arg_name='foo'
    )

    assert result > datetime(2020, 11, 10, 21, 43, 43)

    # relative dates also work
    result = arg_to_datetime(
        arg=1581982463,
        arg_name='foo'
    )

    assert int(result.timestamp()) == 1581982463

    result = arg_to_datetime(
        arg='2 hours ago'
    )

    assert result > datetime(2020, 11, 10, 21, 43, 43)


def test_arg_to_timestamp_invalid_inputs():
    """
    Given
        invalid date like 'aaaa' or '2010-32-01'

    When
        when converting date to timestamp

    Then
        ensure ValueError is raised
    """
    from CommonServerPython import arg_to_datetime
    if sys.version_info.major == 2:
        # skip for python 2 - date
        assert True
        return

    try:
        arg_to_datetime(
            arg=None,
            arg_name='foo',
            required=True)

        assert False

    except ValueError as e:
        assert 'Missing' in str(e)

    try:
        arg_to_datetime(
            arg='aaaa',
            arg_name='foo')

        assert False

    except ValueError as e:
        assert 'Invalid date' in str(e)

    try:
        arg_to_datetime(
            arg='2010-32-01',
            arg_name='foo')

        assert False

    except ValueError as e:
        assert 'Invalid date' in str(e)

    try:
        arg_to_datetime(
            arg='2010-32-01')

        assert False

    except ValueError as e:
        assert '"2010-32-01" is not a valid date' in str(e)
