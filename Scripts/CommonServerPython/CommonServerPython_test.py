# -*- coding: utf-8 -*-
from CommonServerPython import xml2json, json2xml, entryTypes, formats, tableToMarkdown, underscoreToCamelCase, \
    flattenCell, date_to_timestamp, datetime, camelize, pascalToSpace, argToList, \
    remove_nulls_from_dictionary, is_error, get_error, hash_djb2

import copy
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

    xml = "<work><employee><id>100</id><name>foo</name></employee><employee><id>200</id><name>goo</name>" \
          "</employee></work>"
    jsonExpected = '{"work": {"employee": [{"id": "100", "name": "foo"}, {"id": "200", "name": "goo"}]}}'

    jsonActual = xml2json(xml)
    assert jsonActual == jsonExpected, "expected\n" + jsonExpected + "\n to equal \n" + jsonActual

    jsonDict = json.loads(jsonActual)
    assert jsonDict['work']['employee'][0]['id'] == "100", 'id of first employee must be 100'
    assert jsonDict['work']['employee'][1]['name'] == "goo", 'name of second employee must be goo'

    xmlActual = json2xml(jsonActual)
    assert xmlActual == xml, "expected\n" + xml + "\n to equal \n" + xmlActual


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
|header_2|header_3|header_1|
|---|---|---|
|b1|c1|a1|
|b2|c2|a2|
|b3|c3|a3|
'''
    assert table == expected_table


def test_tbl_to_md_header_transform_underscoreToCamelCase():
    # header transform
    table = tableToMarkdown('tableToMarkdown test with headerTransform', DATA,
                            headerTransform=underscoreToCamelCase)
    expected_table = '''### tableToMarkdown test with headerTransform
|Header2|Header3|Header1|
|---|---|---|
|b1|c1|a1|
|b2|c2|a2|
|b3|c3|a3|
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
|header_2|header_3|header_1|
|---|---|---|
|b1.1<br>b1.2|c1\|1|a1|
|b2.1<br>b2.2|c2\|1|a2|
|b3.1<br>b3.2|c3\|1|a3|
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
|header_2|header_3|header_1|
|---|---|---|
||[url](https:\\demisto.com)|a1|
||[url](https:\\demisto.com)|a2|
||[url](https:\\demisto.com)|a3|
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


def test_tbl_to_md_list_values():
    # list values
    data = copy.deepcopy(DATA)
    for i, d in enumerate(data):
        d['header_3'] = [i + 1, 'second item']
        d['header_2'] = 'hi'

    table_list_field = tableToMarkdown('tableToMarkdown test with list field', data)
    expected_table_list_field = '''### tableToMarkdown test with list field
|header_2|header_3|header_1|
|---|---|---|
|hi|1,<br>second item|a1|
|hi|2,<br>second item|a2|
|hi|3,<br>second item|a3|
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
|a|c|b|
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
    utf8_to_flatten = 'abcdefghijklmnopqrstuvwxyz1234567890!'.decode('utf8')
    flatten_text = flattenCell(utf8_to_flatten)
    expected_string = 'abcdefghijklmnopqrstuvwxyz1234567890!'

    assert flatten_text == expected_string

    # list of uft8 and string to flatten
    str_a = 'abcdefghijklmnopqrstuvwxyz1234567890!'
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
    expected_output = "[{u'ChookityBop': 'asdasd'}, {u'AbC': 'd e', u'Nop': 'qr_st', u'FghIjk': 'lm'}]"
    assert str(camelize(non_camalized, '_')) == expected_output

    non_camalized2 = {'ab_c': 'd e', 'fgh_ijk': 'lm', 'nop': 'qr_st'}
    expected_output2 = "{u'AbC': 'd e', u'Nop': 'qr_st', u'FghIjk': 'lm'}"
    assert str(camelize(non_camalized2, '_')) == expected_output2


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
    with pytest.raises(ValueError) as exception:
        get_error(execute_command_results)

    assert "execute_command_result has no error entry. before using get_error use is_error" in str(exception)


def test_logger():
    from CommonServerPython import LOG
    LOG(u'€')
    LOG(Exception(u'€'))
