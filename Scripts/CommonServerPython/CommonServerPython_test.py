# -*- coding: utf-8 -*-
import demistomock as demisto
from CommonServerPython import xml2json, json2xml, entryTypes, formats, tableToMarkdown, underscoreToCamelCase, \
    flattenCell, date_to_timestamp, datetime, camelize, pascalToSpace, argToList, \
    remove_nulls_from_dictionary, is_error, get_error, hash_djb2, fileResult, is_ip_valid, get_demisto_version, \
    IntegrationLogger

import copy
import os
import sys
import pytest

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
    },
]


def test_tbl_to_md_only_data():
    # sanity
    table = tableToMarkdown('tableToMarkdown test', DATA)
    expected_table = '''### tableToMarkdown test
|header_1|header_2|header_3|
|---|---|---|
|a1|b1|c1|
|a2|b2|c2|
|a3|b3|c3|
'''
    assert table == expected_table


def test_tbl_to_md_header_transform_underscoreToCamelCase():
    # header transform
    table = tableToMarkdown('tableToMarkdown test with headerTransform', DATA,
                            headerTransform=underscoreToCamelCase)
    expected_table = '''### tableToMarkdown test with headerTransform
|Header1|Header2|Header3|
|---|---|---|
|a1|b1|c1|
|a2|b2|c2|
|a3|b3|c3|
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
|a1|b1.1<br>b1.2|c1\|1|
|a2|b2.1<br>b2.2|c2\|1|
|a3|b3.1<br>b3.2|c3\|1|
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
|a1||[url](https:\\demisto.com)|
|a2||[url](https:\\demisto.com)|
|a3||[url](https:\\demisto.com)|
'''
    assert table_url_missing_info == expected_table_url_missing_info


def test_tbl_to_md_single_column():
    # single column table
    table_single_column = tableToMarkdown('tableToMarkdown test with single column', DATA, ['header_1'])
    expected_table_single_column = '''### tableToMarkdown test with single column
|header_1|
|---|
|a1|
|a2|
|a3|
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
|a1|hi|1,<br>second item|
|a2|hi|2,<br>second item|
|a3|hi|3,<br>second item|
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
||||
||||
||||
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
|a1|b1||
|a2|b2|sample|
|a3|b3||
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
|a1|b1||
|a2|b2|sample: qwerty<br>sample2: asdf|
|a3|b3||
'''
    assert table_dict_record == expected_dict_record


def test_tbl_to_md_string_header():
    # string header (instead of list)
    table_string_header = tableToMarkdown('tableToMarkdown string header', DATA, 'header_1')
    expected_string_header_tbl = '''### tableToMarkdown string header
|header_1|
|---|
|a1|
|a2|
|a3|
'''
    assert table_string_header == expected_string_header_tbl


def test_tbl_to_md_list_of_strings_instead_of_dict():
    # list of string values instead of list of dict objects
    table_string_array = tableToMarkdown('tableToMarkdown test with string array', ['foo', 'bar', 'katz'], ['header_1'])
    expected_string_array_tbl = '''### tableToMarkdown test with string array
|header_1|
|---|
|foo|
|bar|
|katz|
'''
    assert table_string_array == expected_string_array_tbl


def test_tbl_to_md_list_of_strings_instead_of_dict_and_string_header():
    # combination: string header + string values list
    table_string_array_string_header = tableToMarkdown('tableToMarkdown test with string array and string header',
                                                       ['foo', 'bar', 'katz'], 'header_1')
    expected_string_array_string_header_tbl = '''### tableToMarkdown test with string array and string header
|header_1|
|---|
|foo|
|bar|
|katz|
'''
    assert table_string_array_string_header == expected_string_array_string_header_tbl


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


def test_argToList():
    expected = ['a', 'b', 'c']
    test1 = ['a', 'b', 'c']
    test2 = 'a,b,c'
    test3 = '["a","b","c"]'
    test4 = 'a;b;c'

    results = [argToList(test1), argToList(test2), argToList(test2, ','), argToList(test3), argToList(test4, ';')]

    for result in results:
        assert expected == result, 'argToList test failed, {} is not equal to {}'.format(str(result), str(expected))


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


@pytest.mark.parametrize('data,data_expected', [
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


def test_return_error_long_running_execution(mocker):
    from CommonServerPython import return_error
    err_msg = "Testing unicode Ё"

    # Test fetch-incidents
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
    with pytest.raises(SystemExit, match='0'):
        return_error("Message", error=ValueError("Error!"))
    results = demisto.results.call_args[0][0]
    assert expected == results
    # IntegrationLogger = LOG (2 times if exception supplied)
    assert IntegrationLogger.__call__.call_count == 2


def test_get_demisto_version(mocker):

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
