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
import warnings

from CommonServerPython import set_to_integration_context_with_retries, xml2json, json2xml, entryTypes, formats, tableToMarkdown, underscoreToCamelCase, \
    flattenCell, date_to_timestamp, datetime, camelize, pascalToSpace, argToList, \
    remove_nulls_from_dictionary, is_error, get_error, hash_djb2, fileResult, is_ip_valid, get_demisto_version, \
    IntegrationLogger, parse_date_string, IS_PY3, PY_VER_MINOR, DebugLogger, b64_encode, parse_date_range, return_outputs, \
    argToBoolean, ipv4Regex, ipv4cidrRegex, ipv6cidrRegex, urlRegex, ipv6Regex, batch, FeedIndicatorType, \
    encode_string_results, safe_load_json, remove_empty_elements, aws_table_to_markdown, is_demisto_version_ge, \
    appendContext, auto_detect_indicator_type, handle_proxy, get_demisto_version_as_str, get_x_content_info_headers, \
    url_to_clickable_markdown, WarningsHandler, DemistoException, SmartGetDict, JsonTransformer
import CommonServerPython

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


@pytest.fixture(autouse=True)
def handle_calling_context(mocker):
    mocker.patch.object(CommonServerPython, 'get_integration_name', return_value='Test')


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

DATA_WITH_URLS = [(
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


class TestTableToMarkdown:
    @pytest.mark.parametrize('data, expected_table', TABLE_TO_MARKDOWN_ONLY_DATA_PACK)
    def test_sanity(self, data, expected_table):
        """
        Given:
          - list of objects.
        When:
          - calling tableToMarkdown.
        Then:
          - return a valid table.
        """
        table = tableToMarkdown('tableToMarkdown test', data)

        assert table == expected_table

    @staticmethod
    def test_header_transform_underscoreToCamelCase():
        """
        Given:
          - list of objects.
          - an header transformer.
        When:
          - calling tableToMarkdown.
        Then:
          - return a valid table with updated headers.
        """
        # header transform
        table = tableToMarkdown('tableToMarkdown test with headerTransform', DATA,
                                headerTransform=underscoreToCamelCase)
        expected_table = (
            '### tableToMarkdown test with headerTransform\n'
            '|Header1|Header2|Header3|\n'
            '|---|---|---|\n'
            '| a1 | b1 | c1 |\n'
            '| a2 | b2 | c2 |\n'
            '| a3 | b3 | c3 |\n'
        )
        assert table == expected_table

    @staticmethod
    def test_multiline():
        """
        Given:
          - list of objects.
          - some values contains a new line and the "|" sign.
        When:
          - calling tableToMarkdown.
        Then:
          - return a valid table with "br" tags instead of new lines and escaped pipe sign.
        """
        data = copy.deepcopy(DATA)
        for i, d in enumerate(data):
            d['header_2'] = 'b%d.1\nb%d.2' % (i + 1, i + 1,)
            d['header_3'] = 'c%d|1' % (i + 1,)

        table = tableToMarkdown('tableToMarkdown test with multiline', data)
        expected_table = (
            '### tableToMarkdown test with multiline\n'
            '|header_1|header_2|header_3|\n'
            '|---|---|---|\n'
            '| a1 | b1.1<br>b1.2 | c1\|1 |\n'
            '| a2 | b2.1<br>b2.2 | c2\|1 |\n'
            '| a3 | b3.1<br>b3.2 | c3\|1 |\n'
        )
        assert table == expected_table

    @staticmethod
    def test_url():
        """
        Given:
          - list of objects.
          - some values contain a URL.
          - some values are missing.
        When:
          - calling tableToMarkdown.
        Then:
          - return a valid table.
        """
        data = copy.deepcopy(DATA)
        for d in data:
            d['header_2'] = None
            d['header_3'] = '[url](https:\\demisto.com)'
        table_url_missing_info = tableToMarkdown('tableToMarkdown test with url and missing info', data)
        expected_table_url_missing_info = (
            '### tableToMarkdown test with url and missing info\n'
            '|header_1|header_2|header_3|\n'
            '|---|---|---|\n'
            '| a1 |  | [url](https:\demisto.com) |\n'
            '| a2 |  | [url](https:\demisto.com) |\n'
            '| a3 |  | [url](https:\demisto.com) |\n'
        )
        assert table_url_missing_info == expected_table_url_missing_info

    @staticmethod
    def test_single_column():
        """
        Given:
          - list of objects.
          - a single header.
        When:
          - calling tableToMarkdown.
        Then:
          - return a valid column style table.
        """
        # single column table
        table_single_column = tableToMarkdown('tableToMarkdown test with single column', DATA, ['header_1'])
        expected_table_single_column = (
            '### tableToMarkdown test with single column\n'
            '|header_1|\n'
            '|---|\n'
            '| a1 |\n'
            '| a2 |\n'
            '| a3 |\n'
        )
        assert table_single_column == expected_table_single_column

    @staticmethod
    def test_list_values():
        """
        Given:
          - list of objects.
          - some values are lists.
        When:
          - calling tableToMarkdown.
        Then:
          - return a valid table where the list values are comma-separated and each item in a new line.
        """
        # list values
        data = copy.deepcopy(DATA)
        for i, d in enumerate(data):
            d['header_3'] = [i + 1, 'second item']
            d['header_2'] = 'hi'

        table_list_field = tableToMarkdown('tableToMarkdown test with list field', data)
        expected_table_list_field = (
            '### tableToMarkdown test with list field\n'
            '|header_1|header_2|header_3|\n'
            '|---|---|---|\n'
            '| a1 | hi | 1,<br>second item |\n'
            '| a2 | hi | 2,<br>second item |\n'
            '| a3 | hi | 3,<br>second item |\n'
        )
        assert table_list_field == expected_table_list_field

    @staticmethod
    def test_empty_fields():
        """
        Given:
          - list of objects.
          - all values are empty.
        When:
          - calling tableToMarkdown with removeNull=false.
          - calling tableToMarkdown with removeNull=true.
        Then:
          - return an empty table.
          - return a "no results" message.
        """
        data = [
            {
                'a': None,
                'b': None,
                'c': None,
            } for _ in range(3)
        ]
        table_all_none = tableToMarkdown('tableToMarkdown test with all none fields', data)
        expected_table_all_none = (
            '### tableToMarkdown test with all none fields\n'
            '|a|b|c|\n'
            '|---|---|---|\n'
            '|  |  |  |\n'
            '|  |  |  |\n'
            '|  |  |  |\n'
        )
        assert table_all_none == expected_table_all_none

        # all fields are empty - removed
        table_all_none2 = tableToMarkdown('tableToMarkdown test with all none fields2', data, removeNull=True)
        expected_table_all_none2 = '''### tableToMarkdown test with all none fields2
**No entries.**
'''
        assert table_all_none2 == expected_table_all_none2

    @staticmethod
    def test_header_not_on_first_object():
        """
        Given:
          - list of objects
          - list of headers with header that doesn't appear in the first object.
        When:
          - calling tableToMarkdown.
        Then:
          - return a valid table with the extra header.
        """
        # header not on first object
        data = copy.deepcopy(DATA)
        data[1]['extra_header'] = 'sample'
        table_extra_header = tableToMarkdown('tableToMarkdown test with extra header', data,
                                             headers=['header_1', 'header_2', 'extra_header'])
        expected_table_extra_header = (
            '### tableToMarkdown test with extra header\n'
            '|header_1|header_2|extra_header|\n'
            '|---|---|---|\n'
            '| a1 | b1 |  |\n'
            '| a2 | b2 | sample |\n'
            '| a3 | b3 |  |\n'
        )
        assert table_extra_header == expected_table_extra_header

    @staticmethod
    def test_no_header():
        """
        Given:
          - list of objects.
          - a list with non-existing headers.
        When:
          - calling tableToMarkdown.
        Then:
          - return a "no result" message.
        """
        # no header
        table_no_headers = tableToMarkdown('tableToMarkdown test with no headers', DATA,
                                           headers=['no', 'header', 'found'], removeNull=True)
        expected_table_no_headers = (
            '### tableToMarkdown test with no headers\n'
            '**No entries.**\n'
        )
        assert table_no_headers == expected_table_no_headers

    @staticmethod
    def test_dict_value():
        """
        Given:
          - list of objects.
          - some values are lists.
        When:
          - calling tableToMarkdown.
        Then:
          - return a valid table.
        """
        # dict value
        data = copy.deepcopy(DATA)
        data[1]['extra_header'] = {'sample': 'qwerty', 'sample2': '`asdf'}
        table_dict_record = tableToMarkdown('tableToMarkdown test with dict record', data,
                                            headers=['header_1', 'header_2', 'extra_header'])
        expected_dict_record = (
            '### tableToMarkdown test with dict record\n'
            '|header_1|header_2|extra_header|\n'
            '|---|---|---|\n'
            '| a1 | b1 |  |\n'
            '| a2 | b2 | sample: qwerty<br>sample2: \\`asdf |\n'
            '| a3 | b3 |  |\n'
        )
        assert table_dict_record == expected_dict_record

    @staticmethod
    def test_string_header():
        """
        Given:
          - list of objects.
          - a single header as a string.
        When:
          - calling tableToMarkdown.
        Then:
          - return a valid table.
        """
        # string header (instead of list)
        table_string_header = tableToMarkdown('tableToMarkdown string header', DATA, 'header_1')
        expected_string_header_tbl = (
            '### tableToMarkdown string header\n'
            '|header_1|\n'
            '|---|\n'
            '| a1 |\n'
            '| a2 |\n'
            '| a3 |\n'
        )
        assert table_string_header == expected_string_header_tbl

    @staticmethod
    def test_list_of_strings_instead_of_dict():
        """
        Given:
          - list of strings.
          - a single header as a list.
        When:
          - calling tableToMarkdown.
        Then:
          - return a valid table.
        """
        # list of string values instead of list of dict objects
        table_string_array = tableToMarkdown('tableToMarkdown test with string array', ['foo', 'bar', 'katz'],
                                             ['header_1'])
        expected_string_array_tbl = (
            '### tableToMarkdown test with string array\n'
            '|header_1|\n'
            '|---|\n'
            '| foo |\n'
            '| bar |\n'
            '| katz |\n'
        )
        assert table_string_array == expected_string_array_tbl

    @staticmethod
    def test_list_of_strings_instead_of_dict_and_string_header():
        """
        Given:
          - list of strings.
          - a single header as a string.
        When:
          - calling tableToMarkdown.
        Then:
          - return a valid table.
        """
        # combination: string header + string values list
        table_string_array_string_header = tableToMarkdown('tableToMarkdown test with string array and string header',
                                                           ['foo', 'bar', 'katz'], 'header_1')

        expected_string_array_string_header_tbl = (
            '### tableToMarkdown test with string array and string header\n'
            '|header_1|\n'
            '|---|\n'
            '| foo |\n'
            '| bar |\n'
            '| katz |\n'
        )

        assert table_string_array_string_header == expected_string_array_string_header_tbl

    @staticmethod
    def test_single_key_dict():
        # combination: string header + string values list
        table_single_key_dict = tableToMarkdown('tableToMarkdown test with single key dict',
                                                {'single': ['Arthur', 'Blob', 'Cactus']})
        expected_single_key_dict_tbl = (
            '### tableToMarkdown test with single key dict\n'
            '|single|\n'
            '|---|\n'
            '| Arthur |\n'
            '| Blob |\n'
            '| Cactus |\n'
        )
        assert table_single_key_dict == expected_single_key_dict_tbl

    @staticmethod
    def test_dict_with_special_character():
        """
        When:
          - calling tableToMarkdown.
        Given:
          - list of objects.
          - some values contain special characters.
        Then:
          - return a valid table.
        """
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

    @staticmethod
    def test_title_with_special_character():
        """
        When:
          - calling tableToMarkdown.
        Given:
          - a title with a special character.
        Then:
          - return a valid table.
        """
        data = {
            'header_1': u'foo'
        }
        table_with_character = tableToMarkdown('tableToMarkdown test with special character Ù', data)
        expected_string_with_special_character = (
            '### tableToMarkdown test with special character Ù\n'
            '|header_1|\n'
            '|---|\n'
            '| foo |\n'
        )
        assert table_with_character == expected_string_with_special_character

    @pytest.mark.parametrize('data, expected_table', DATA_WITH_URLS)
    def test_clickable_url(self, data, expected_table):
        """
        Given:
          - list of objects.
          - some values are URLs.
        When:
          - calling tableToMarkdown.
        Then:
          - return a valid table with clickable URLs.
        """
        table = tableToMarkdown('tableToMarkdown test', data, url_keys=['url1', 'url2'])
        assert table == expected_table

    @staticmethod
    def test_keep_headers_list():
        """
        Given:
          - list of objects.
        When:
          - calling tableToMarkdown.
        Then:
          - return a valid table.
          - the given headers list is not modified.
        """
        headers = ['header_1', 'header_2']
        data = {
            'header_1': 'foo',
        }
        table = tableToMarkdown('tableToMarkdown test', data, removeNull=True, headers=headers)
        assert 'header_2' not in table
        assert headers == ['header_1', 'header_2']

    @staticmethod
    def test_date_fields_param():
        """
        Given:
          - List of objects with date fields in epoch format.
        When:
          - Calling tableToMarkdown with the given date fields.
        Then:
          - Return the date data in the markdown table in human-readable format.
        """
        data = [
            {
                "docker_image": "demisto/python3",
                "create_time": '1631521313466'
            },
            {
                "docker_image": "demisto/python2",
                "create_time": 1631521521466
            }
        ]

        table = tableToMarkdown('tableToMarkdown test', data, headers=["docker_image", "create_time"],
                                date_fields=['create_time'])

        expected_md_table = '''### tableToMarkdown test
|docker_image|create_time|
|---|---|
| demisto/python3 | 2021-09-13 08:21:53 |
| demisto/python2 | 2021-09-13 08:25:21 |
'''
        assert table == expected_md_table

    @staticmethod
    def test_with_json_transformers_default():
        """
        Given:
          - Nested json table.
        When:
          - Calling tableToMarkdown with `is_auto_transform_json` set to True.
        Then:
          - Parse the json table to the default format which supports nesting.
        """
        with open('test_data/nested_data_example.json') as f:
            nested_data_example = json.load(f)
        table = tableToMarkdown("tableToMarkdown test", nested_data_example,
                                headers=['name', 'changelog', 'nested'],
                                is_auto_json_transform=True)
        if IS_PY3:
            expected_table = """### tableToMarkdown test
|name|changelog|nested|
|---|---|---|
| Active Directory Query | **1.0.4**:<br>	***path***: <br>	***releaseNotes***: <br>#### Integrations<br>##### Active Directory Query v2<br>Fixed an issue where the ***ad-get-user*** command caused performance issues because the *limit* argument was not defined.<br><br>	***displayName***: 1.0.4 - R124496<br>	***released***: 2020-09-23T17:43:26Z<br>**1.0.5**:<br>	***path***: <br>	***releaseNotes***: <br>#### Integrations<br>##### Active Directory Query v2<br>- Fixed several typos.<br>- Updated the Docker image to: *demisto/ldap:1.0.0.11282*.<br><br>	***displayName***: 1.0.5 - 132259<br>	***released***: 2020-10-01T17:48:31Z<br>**1.0.6**:<br>	***path***: <br>	***releaseNotes***: <br>#### Integrations<br>##### Active Directory Query v2<br>- Fixed an issue where the DN parameter within query in the ***search-computer*** command was incorrect.<br>- Updated the Docker image to *demisto/ldap:1.0.0.12410*.<br><br>	***displayName***: 1.0.6 - 151676<br>	***released***: 2020-10-19T14:35:15Z | **item1**:<br>	***a***: 1<br>	***b***: 2<br>	***c***: 3<br>	***d***: 4 |
"""
        else:
            expected_table = u"""### tableToMarkdown test
|name|changelog|nested|
|---|---|---|
| Active Directory Query | **1.0.4**:<br>	***path***: <br>	***releaseNotes***: <br>#### Integrations<br>##### Active Directory Query v2<br>Fixed an issue where the ***ad-get-user*** command caused performance issues because the *limit* argument was not defined.<br><br>	***displayName***: 1.0.4 - R124496<br>	***released***: 2020-09-23T17:43:26Z<br>**1.0.5**:<br>	***path***: <br>	***releaseNotes***: <br>#### Integrations<br>##### Active Directory Query v2<br>- Fixed several typos.<br>- Updated the Docker image to: *demisto/ldap:1.0.0.11282*.<br><br>	***displayName***: 1.0.5 - 132259<br>	***released***: 2020-10-01T17:48:31Z<br>**1.0.6**:<br>	***path***: <br>	***releaseNotes***: <br>#### Integrations<br>##### Active Directory Query v2<br>- Fixed an issue where the DN parameter within query in the ***search-computer*** command was incorrect.<br>- Updated the Docker image to *demisto/ldap:1.0.0.12410*.<br><br>	***displayName***: 1.0.6 - 151676<br>	***released***: 2020-10-19T14:35:15Z | **item1**:<br>	***a***: 1<br>	***c***: 3<br>	***b***: 2<br>	***d***: 4 |
"""
        assert table == expected_table

    @staticmethod
    def test_with_json_transformer_simple():
        with open('test_data/simple_data_example.json') as f:
            simple_data_example = json.load(f)
        name_transformer = JsonTransformer(keys=['first', 'second'])
        json_transformer_mapping = {'name': name_transformer}
        table = tableToMarkdown("tableToMarkdown test", simple_data_example,
                                json_transform_mapping=json_transformer_mapping)
        if IS_PY3:
            expected_table = """### tableToMarkdown test
|name|value|
|---|---|
| **first**:<br>	***a***: val<br><br>***second***: b | val1 |
| **first**:<br>	***a***: val2<br><br>***second***: d | val2 |
"""
        else:
            expected_table = u"""### tableToMarkdown test
|name|value|
|---|---|
| <br>***second***: b<br>**first**:<br>	***a***: val | val1 |
| <br>***second***: d<br>**first**:<br>	***a***: val2 | val2 |
"""
        assert expected_table == table

    @staticmethod
    def test_with_json_transformer_nested():
        """
        Given:
          - Nested json table.
        When:
          - Calling tableToMarkdown with JsonTransformer with only `keys` given.
        Then:
          - The header key which is transformed will parsed with the relevant keys.
        """

        with open('test_data/nested_data_example.json') as f:
            nested_data_example = json.load(f)
        changelog_transformer = JsonTransformer(keys=['releaseNotes', 'released'], is_nested=True)
        table_json_transformer = {'changelog': changelog_transformer}
        table = tableToMarkdown("tableToMarkdown test", nested_data_example, headers=['name', 'changelog'],
                                json_transform_mapping=table_json_transformer)
        expected_table = """### tableToMarkdown test
|name|changelog|
|---|---|
| Active Directory Query | **1.0.4**:<br>	***releaseNotes***: <br>#### Integrations<br>##### Active Directory Query v2<br>Fixed an issue where the ***ad-get-user*** command caused performance issues because the *limit* argument was not defined.<br><br>	***released***: 2020-09-23T17:43:26Z<br>**1.0.5**:<br>	***releaseNotes***: <br>#### Integrations<br>##### Active Directory Query v2<br>- Fixed several typos.<br>- Updated the Docker image to: *demisto/ldap:1.0.0.11282*.<br><br>	***released***: 2020-10-01T17:48:31Z<br>**1.0.6**:<br>	***releaseNotes***: <br>#### Integrations<br>##### Active Directory Query v2<br>- Fixed an issue where the DN parameter within query in the ***search-computer*** command was incorrect.<br>- Updated the Docker image to *demisto/ldap:1.0.0.12410*.<br><br>	***released***: 2020-10-19T14:35:15Z |
"""
        assert expected_table == table

    @staticmethod
    def test_with_json_transformer_nested_complex():
        """
        Given:
          - Double nested json table.
        When:
          - Calling tableToMarkdown with JsonTransformer with only `keys_lst` given and `is_nested` set to True.
        Then:
          - The header key which is transformed will parsed with the relevant keys.
        """
        with open('test_data/complex_nested_data_example.json') as f:
            complex_nested_data_example = json.load(f)
        changelog_transformer = JsonTransformer(keys=['releaseNotes', 'c'], is_nested=True)
        table_json_transformer = {'changelog': changelog_transformer}
        table = tableToMarkdown('tableToMarkdown test', complex_nested_data_example, headers=['name', 'changelog'],
                                json_transform_mapping=table_json_transformer)
        expected_table = """### tableToMarkdown test
|name|changelog|
|---|---|
| Active Directory Query | **1.0.4**:<br>	**path**:<br>		**a**:<br>			**b**:<br>				***c***: we should see this value<br>**1.0.4**:<br>	***releaseNotes***: <br>#### Integrations<br>##### Active Directory Query v2<br>Fixed an issue where the ***ad-get-user*** command caused performance issues because the *limit* argument was not defined.<br><br>**1.0.5**:<br>	**path**:<br>		**a**:<br>			**b**:<br>				***c***: we should see this value<br>**1.0.5**:<br>	***releaseNotes***: <br>#### Integrations<br>##### Active Directory Query v2<br>- Fixed several typos.<br>- Updated the Docker image to: *demisto/ldap:1.0.0.11282*.<br><br>**1.0.6**:<br>	**path**:<br>		**a**:<br>			**b**:<br>				***c***: we should see this value<br>**1.0.6**:<br>	***releaseNotes***: <br>#### Integrations<br>##### Active Directory Query v2<br>- Fixed an issue where the DN parameter within query in the ***search-computer*** command was incorrect.<br>- Updated the Docker image to *demisto/ldap:1.0.0.12410*.<br> |
"""

        assert expected_table == table

    @staticmethod
    def test_with_json_transformer_func():

        def changelog_to_str(json_input):
            return ', '.join(json_input.keys())

        with open('test_data/nested_data_example.json') as f:
            nested_data_example = json.load(f)
        changelog_transformer = JsonTransformer(func=changelog_to_str)
        table_json_transformer = {'changelog': changelog_transformer}
        table = tableToMarkdown("tableToMarkdown test", nested_data_example, headers=['name', 'changelog'],
                                json_transform_mapping=table_json_transformer)
        expected_table = """### tableToMarkdown test
|name|changelog|
|---|---|
| Active Directory Query | 1.0.4, 1.0.5, 1.0.6 |
"""
        assert expected_table == table


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
    expected_output_upper_camel = [{'ChookityBop': 'asdasd'}, {'AbC': 'd e', 'Nop': 'qr_st', 'FghIjk': 'lm'}]
    expected_output_lower_camel = [{'chookityBop': 'asdasd'}, {'abC': 'd e', 'nop': 'qr_st', 'fghIjk': 'lm'}]
    assert camelize(non_camalized, '_') == expected_output_upper_camel
    assert camelize(non_camalized, '_', upper_camel=True) == expected_output_upper_camel
    assert camelize(non_camalized, '_', upper_camel=False) == expected_output_lower_camel

    non_camalized2 = {'ab_c': 'd e', 'fgh_ijk': 'lm', 'nop': 'qr_st'}
    expected_output2_upper_camel = {'AbC': 'd e', 'Nop': 'qr_st', 'FghIjk': 'lm'}
    expected_output2_lower_camel = {'abC': 'd e', 'nop': 'qr_st', 'fghIjk': 'lm'}
    assert camelize(non_camalized2, '_') == expected_output2_upper_camel
    assert camelize(non_camalized2, '_', upper_camel=True) == expected_output2_upper_camel
    assert camelize(non_camalized2, '_', upper_camel=False) == expected_output2_lower_camel


def test_camelize_string():
    from CommonServerPython import camelize_string
    non_camalized = ['chookity_bop', 'ab_c', 'fgh_ijk', 'nop']
    expected_output_upper_camel = ['ChookityBop', 'AbC', 'FghIjk', 'Nop']
    expected_output_lower_camel = ['chookityBop', 'abC', 'fghIjk', 'nop']
    for i in range(len(non_camalized)):
        assert camelize_string(non_camalized[i], '_') == expected_output_upper_camel[i]
        assert camelize_string(non_camalized[i], '_', upper_camel=True) == expected_output_upper_camel[i]
        assert camelize_string(non_camalized[i], '_', upper_camel=False) == expected_output_lower_camel[i]


def test_underscoreToCamelCase():
    from CommonServerPython import underscoreToCamelCase
    non_camalized = ['chookity_bop', 'ab_c', 'fgh_ijk', 'nop']
    expected_output_upper_camel = ['ChookityBop', 'AbC', 'FghIjk', 'Nop']
    expected_output_lower_camel = ['chookityBop', 'abC', 'fghIjk', 'nop']
    for i in range(len(non_camalized)):
        assert underscoreToCamelCase(non_camalized[i]) == expected_output_upper_camel[i]
        assert underscoreToCamelCase(non_camalized[i], upper_camel=True) == expected_output_upper_camel[i]
        assert underscoreToCamelCase(non_camalized[i], upper_camel=False) == expected_output_lower_camel[i]


# Note this test will fail when run locally (in pycharm/vscode) as it assumes the machine (docker image) has UTC timezone set
def test_date_to_timestamp():
    assert date_to_timestamp('2018-11-06T08:56:41') == 1541494601000
    assert date_to_timestamp(datetime.strptime('2018-11-06T08:56:41', "%Y-%m-%dT%H:%M:%S")) == 1541494601000


PASCAL_TO_SPACE_USE_CASES = [
    ('Validate', 'Validate'),
    ('validate', 'Validate'),
    ('TCP', 'TCP'),
    ('eventType', 'Event Type'),
    ('eventID', 'Event ID'),
    ('eventId', 'Event Id'),
    ('IPAddress', 'IP Address'),
    ('isDisabled', 'Is Disabled'),
    ('device-group', 'Device - Group'),
]


@pytest.mark.parametrize('s, expected', PASCAL_TO_SPACE_USE_CASES)
def test_pascalToSpace(s, expected):
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
    ilog.add_replace_strs('special_str', 'ZAQ!@#$%&*', '')  # also check that empty string is not added by mistake
    ilog('my_apikey is special_str and b64: ' + b64_encode('my_apikey'))
    ilog('special chars like ZAQ!@#$%&* should be replaced even when url-encoded like ZAQ%21%40%23%24%25%26%2A')
    assert ('' not in ilog.replace_strs)
    assert ilog.messages[0] == '<XX_REPLACED> is <XX_REPLACED> and b64: <XX_REPLACED>'
    assert ilog.messages[1] == \
           'special chars like <XX_REPLACED> should be replaced even when url-encoded like <XX_REPLACED>'


TEST_SSH_KEY_ESC = '-----BEGIN OPENSSH PRIVATE KEY-----\\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFw' \
                   'AAAAdzc2gtcn\\n-----END OPENSSH PRIVATE KEY-----'

TEST_SSH_KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFw' \
               'AAAAdzc2gtcn\n-----END OPENSSH PRIVATE KEY-----'

TEST_PASS_JSON_CHARS = 'json_chars'

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
    'password': TEST_PASS_JSON_CHARS + '\\"',
}


def test_logger_replace_strs_credentials(mocker):
    mocker.patch.object(demisto, 'params', return_value=SENSITIVE_PARAM)
    basic_auth = b64_encode(
        '{}:{}'.format(SENSITIVE_PARAM['authentication']['identifier'], SENSITIVE_PARAM['authentication']['password']))
    ilog = IntegrationLogger()
    # log some secrets
    ilog('my cred pass: cred_pass. my ssh key: ssh_key_secret. my ssh key: {}.'
         'my ssh key: {}. my ssh pass: ssh_key_secret_pass. ident: ident_pass.'
         ' basic auth: {}'.format(TEST_SSH_KEY, TEST_SSH_KEY_ESC, basic_auth))

    for s in ('cred_pass', TEST_SSH_KEY, TEST_SSH_KEY_ESC, 'ssh_key_secret_pass', 'ident_pass', basic_auth):
        assert s not in ilog.messages[0]


def test_debug_logger_replace_strs(mocker):
    mocker.patch.object(demisto, 'params', return_value=SENSITIVE_PARAM)
    debug_logger = DebugLogger()
    debug_logger.int_logger.set_buffering(True)
    debug_logger.log_start_debug()
    msg = debug_logger.int_logger.messages[0]
    assert 'debug-mode started' in msg
    assert 'Params:' in msg
    for s in ('cred_pass', 'ssh_key_secret', 'ssh_key_secret_pass', 'ident_pass', TEST_SSH_KEY,
              TEST_SSH_KEY_ESC, TEST_PASS_JSON_CHARS):
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
        '--noproxy "*" -d \'{"data": "value"}\''
    ]


def test_build_curl_post_xml():
    """
    Given:
       - HTTP client log messages of POST query with XML body
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
    ilog.build_curl("send: b'<?xml version=\"1.0\" encoding=\"utf-8\"?>'")
    assert ilog.curl == [
        'curl -X POST https://demisto.com/api -H "Authorization: TOKEN" -H "Content-Type: application/json" '
        '--noproxy "*" -d \'<?xml version="1.0" encoding="utf-8"?>\''
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
        '--noproxy "*" -d \'{"postdata": "value"}\'',
        'curl -X GET https://demisto.com/api/get -H "Authorization: TOKEN" -H "Content-Type: application/json" '
        '--noproxy "*" -d \'{"getdata": "value"}\''
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


def test_return_error_fetch_credentials(mocker):
    from CommonServerPython import return_error
    err_msg = "Testing unicode Ё"

    # Test fetch-credentials
    mocker.patch.object(demisto, 'command', return_value="fetch-credentials")
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
    mocker.patch.object(IntegrationLogger, '__call__', return_value='Message')
    with raises(SystemExit, match='0'):
        return_error("Message", error=ValueError("Error!"))
    results = demisto.results.call_args[0][0]
    assert expected == results
    # IntegrationLogger = LOG (2 times if exception supplied)
    assert IntegrationLogger.__call__.call_count == 2


def test_return_error_get_modified_remote_data(mocker):
    from CommonServerPython import return_error
    mocker.patch.object(demisto, 'command', return_value='get-modified-remote-data')
    mocker.patch.object(demisto, 'results')
    err_msg = 'Test Error'
    with raises(SystemExit):
        return_error(err_msg)
    assert demisto.results.call_args[0][0]['Contents'] == 'skip update. error: ' + err_msg


def test_return_error_get_modified_remote_data_not_implemented(mocker):
    from CommonServerPython import return_error
    mocker.patch.object(demisto, 'command', return_value='get-modified-remote-data')
    mocker.patch.object(demisto, 'results')
    err_msg = 'Test Error'
    with raises(SystemExit):
        try:
            raise NotImplementedError('Command not implemented')
        except:
            return_error(err_msg)
    assert demisto.results.call_args[0][0]['Contents'] == err_msg


def test_indicator_type_by_server_version_under_6_1(mocker, clear_version_cache):
    """
    Given
    - demisto version mock under 6.2

    When
    - demisto version mock under 6.2

    Then
    - Do not remove the STIX indicator type prefix.
    """
    mocker.patch.object(
        demisto,
        'demistoVersion',
        return_value={
            'version': '6.1.0',
        }
    )
    assert FeedIndicatorType.indicator_type_by_server_version("STIX Attack Pattern") == "STIX Attack Pattern"


def test_indicator_type_by_server_version_6_2(mocker, clear_version_cache):
    """
    Given
    - demisto version mock set to 6.2

    When
    - demisto version mock set to 6.2

    Then
    - Return the STIX indicator type with the STIX prefix
    """
    mocker.patch.object(
        demisto,
        'demistoVersion',
        return_value={
            'version': '6.2.0',
        }
    )
    assert FeedIndicatorType.indicator_type_by_server_version("STIX Attack Pattern") == "Attack Pattern"


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
    def test_outputs_without_outputs_prefix(self):
        """
        Given
        - outputs as a list without output_prefix

        When
        - Returins results

        Then
        - Validate a ValueError is raised.
        """
        from CommonServerPython import CommandResults
        with pytest.raises(ValueError, match='outputs_prefix'):
            CommandResults(outputs=[])

    def test_dbot_score_is_in_to_context_ip(self):
        """
        Given
        - IP indicator

        When
        - Creating a reputation

        Then
        - Validate the DBOT Score and IP output exists in entry context.
        """
        from CommonServerPython import Common, DBotScoreType, CommandResults
        indicator_id = '1.1.1.1'
        raw_response = {'id': indicator_id}
        indicator = Common.IP(
            indicator_id,
            dbot_score=Common.DBotScore(
                indicator_id,
                DBotScoreType.IP,
                'VirusTotal',
                score=Common.DBotScore.BAD,
                malicious_description='malicious!'
            )
        )
        entry_context = CommandResults(
            indicator=indicator,
            readable_output='Indicator!',
            outputs={'Indicator': raw_response},
            raw_response=raw_response
        ).to_context()['EntryContext']
        assert Common.DBotScore.CONTEXT_PATH in entry_context
        assert Common.IP.CONTEXT_PATH in entry_context

    def test_dbot_score_is_in_to_context_file(self):
        """
        Given
        - File indicator

        When
        - Creating a reputation

        Then
        - Validate the DBOT Score and File output exists in entry context.
        """
        from CommonServerPython import Common, DBotScoreType, CommandResults
        indicator_id = '63347f5d946164a23faca26b78a91e1c'
        raw_response = {'id': indicator_id}
        indicator = Common.File(
            md5=indicator_id,
            dbot_score=Common.DBotScore(
                indicator_id,
                DBotScoreType.FILE,
                'Indicator',
                score=Common.DBotScore.BAD,
                malicious_description='malicious!'
            )
        )
        entry_context = CommandResults(
            indicator=indicator,
            readable_output='output!',
            outputs={'Indicator': raw_response},
            raw_response=raw_response
        ).to_context()['EntryContext']
        assert Common.DBotScore.CONTEXT_PATH in entry_context
        assert Common.File.CONTEXT_PATH in entry_context

    def test_dbot_score_is_in_to_context_domain(self):
        """
        Given
        - domain indicator

        When
        - Creating a reputation

        Then
        - Validate the DBOT Score and File output exists in entry context.
        """
        from CommonServerPython import Common, DBotScoreType, CommandResults
        indicator_id = 'example.com'
        raw_response = {'id': indicator_id}
        indicator = Common.Domain(
            indicator_id,
            dbot_score=Common.DBotScore(
                indicator_id,
                DBotScoreType.DOMAIN,
                'VirusTotal',
                score=Common.DBotScore.BAD,
                malicious_description='malicious!'
            )
        )
        entry_context = CommandResults(
            indicator=indicator,
            readable_output='output!',
            outputs={'Indicator': raw_response},
            raw_response=raw_response
        ).to_context()['EntryContext']
        assert Common.DBotScore.CONTEXT_PATH in entry_context
        assert Common.Domain.CONTEXT_PATH in entry_context

    def test_dbot_score_is_in_to_context_url(self):
        """
        Given
        - domain indicator

        When
        - Creating a reputation

        Then
        - Validate the DBOT Score and File output exists in entry context.
        """
        from CommonServerPython import Common, DBotScoreType, CommandResults
        indicator_id = 'https://example.com'
        raw_response = {'id': indicator_id}
        indicator = Common.URL(
            indicator_id,
            dbot_score=Common.DBotScore(
                indicator_id,
                DBotScoreType.URL,
                'VirusTotal',
                score=Common.DBotScore.BAD,
                malicious_description='malicious!'
            )
        )
        entry_context = CommandResults(
            indicator=indicator,
            readable_output='output!',
            outputs={'Indicator': raw_response},
            raw_response=raw_response
        ).to_context()['EntryContext']
        assert Common.DBotScore.CONTEXT_PATH in entry_context
        assert Common.URL.CONTEXT_PATH in entry_context

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
               'File(val.sha1 && val.sha1 == obj.sha1 && val.sha256 && val.sha256 == obj.sha256 && val.md5 && val.md5 == obj.md5)'

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

    @pytest.mark.parametrize('score, expected_readable',
                             [(CommonServerPython.Common.DBotScore.NONE, 'Unknown'),
                              (CommonServerPython.Common.DBotScore.GOOD, 'Good'),
                              (CommonServerPython.Common.DBotScore.SUSPICIOUS, 'Suspicious'),
                              (CommonServerPython.Common.DBotScore.BAD, 'Bad')])
    def test_dbot_readable(self, score, expected_readable):
        from CommonServerPython import Common, DBotScoreType
        dbot_score = Common.DBotScore(
            indicator='8.8.8.8',
            integration_name='Test',
            indicator_type=DBotScoreType.IP,
            score=score
        )
        assert dbot_score.to_readable() == expected_readable

    def test_dbot_readable_invalid(self):
        from CommonServerPython import Common, DBotScoreType
        dbot_score = Common.DBotScore(
            indicator='8.8.8.8',
            integration_name='Test',
            indicator_type=DBotScoreType.IP,
            score=0
        )
        dbot_score.score = 7
        assert dbot_score.to_readable() == 'Undefined'
        dbot_score.score = None
        assert dbot_score.to_readable() == 'Undefined'

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
            integration_name='Test',
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
                        'Vendor': 'Test',
                        'Score': 1,
                        'Type': 'ip'
                    }
                ]
            },
            'IndicatorTimeline': [],
            'Relationships': [],
            'IgnoreAutoExtract': False,
            'Note': False
        }

    def test_multiple_indicators(self, clear_version_cache):
        from CommonServerPython import Common, CommandResults, EntryFormat, EntryType, DBotScoreType
        dbot_score1 = Common.DBotScore(
            indicator='8.8.8.8',
            integration_name='Test',
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
            integration_name='Test',
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
                        'Vendor': 'Test',
                        'Score': 1,
                        'Type': 'ip'
                    },
                    {
                        'Indicator': '5.5.5.5',
                        'Vendor': 'Test',
                        'Score': 1,
                        'Type': 'ip'
                    }
                ]
            },
            'IndicatorTimeline': [],
            'Relationships': [],
            'IgnoreAutoExtract': False,
            'Note': False
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
                'Jira.Ticket(val.ticket_id && val.ticket_id == obj.ticket_id)': tickets
            },
            'IndicatorTimeline': [],
            'Relationships': [],
            'IgnoreAutoExtract': False,
            'Note': False
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
            'Relationships': [],
            'IgnoreAutoExtract': False,
            'Note': False
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

    def test_create_dbot_score_with_invalid_reliability(self):
        """
        Given:
            -  an invalid reliability value.
        When
            - creating a DBotScore entry
        Then
            - an error should be raised
        """
        from CommonServerPython import Common, DBotScoreType

        try:
            Common.DBotScore(
                indicator='8.8.8.8',
                integration_name='Virus Total',
                score=0,
                indicator_type=DBotScoreType.IP,
                reliability='Not a reliability'
            )
            assert False
        except TypeError:
            assert True

    def test_create_dbot_score_with_valid_reliability(self):
        """
        Given:
            -  a valid reliability value
        When
            - creating a DBotScore entry
        Then
            - the proper entry is created
        """
        from CommonServerPython import Common, DBotScoreType, DBotScoreReliability, CommandResults

        dbot_score = Common.DBotScore(
            indicator='8.8.8.8',
            integration_name='Test',
            score=Common.DBotScore.GOOD,
            indicator_type=DBotScoreType.IP,
            reliability=DBotScoreReliability.B,
        )

        ip = Common.IP(
            ip='8.8.8.8',
            dbot_score=dbot_score,
        )

        results = CommandResults(
            indicator=ip,
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
                    'Vendor': 'Test',
                    'Score': 1,
                    'Reliability': 'B - Usually reliable'
                }
            ]
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
            integration_name='Test',
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
                    'Vendor': 'Test',
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

    def test_entry_as_note(self):
        """
        Given:
        - mark_as_note set to True

        When:
        - creating a CommandResults object

        Then:
        - the Note field is set to True
        """
        from CommonServerPython import CommandResults

        results = CommandResults(
            outputs_prefix='Test',
            outputs_key_field='value',
            outputs=None,
            mark_as_note=True
        )

        assert results.to_context().get('Note') is True


def test_http_request_ssl_ciphers_insecure():
    if IS_PY3 and PY_VER_MINOR >= 10:
        from CommonServerPython import BaseClient

        client = BaseClient('https://www.google.com', ok_codes=(200, 201), verify=False)
        adapter = client._session.adapters.get('https://')
        ssl_context = adapter.poolmanager.connection_pool_kw['ssl_context']
        ciphers_list = ssl_context.get_ciphers()

        assert len(ciphers_list) == 42
        assert next(cipher for cipher in ciphers_list if cipher['name'] == 'AES128-GCM-SHA256')
    else:
        assert True

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
        text = 'notjson'
        requests_mock.get('http://example.com/api/v2/event', text=text)
        with raises(DemistoException, match="Failed to parse json") as exception:
            self.client._http_request('get', 'event')
        assert exception.value.res
        assert exception.value.res.text == text

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

    def test_http_request_proxy_false(self):
        from CommonServerPython import BaseClient
        import requests_mock

        os.environ['http_proxy'] = 'http://testproxy:8899'
        os.environ['https_proxy'] = 'https://testproxy:8899'

        os.environ['REQUESTS_CA_BUNDLE'] = '/test1.pem'
        client = BaseClient('http://example.com/api/v2/', ok_codes=(200, 201), proxy=False, verify=True)

        with requests_mock.mock() as m:
            m.get('http://example.com/api/v2/event')

            res = client._http_request('get', 'event', resp_type='response')

            assert m.last_request.verify == '/test1.pem'
            assert not m.last_request.proxies
            assert m.called is True

    def test_http_request_proxy_true(self):
        from CommonServerPython import BaseClient
        import requests_mock

        os.environ['http_proxy'] = 'http://testproxy:8899'
        os.environ['https_proxy'] = 'https://testproxy:8899'

        os.environ['REQUESTS_CA_BUNDLE'] = '/test1.pem'
        client = BaseClient('http://example.com/api/v2/', ok_codes=(200, 201), proxy=True, verify=True)

        with requests_mock.mock() as m:
            m.get('http://example.com/api/v2/event')

            res = client._http_request('get', 'event', resp_type='response')

            assert m.last_request.verify == '/test1.pem'
            assert m.last_request.proxies == {
                'http': 'http://testproxy:8899',
                'https': 'https://testproxy:8899'
            }
            assert m.called is True

    def test_http_request_proxy_without_http_prefix(self):
        """
            Given
                - proxy param is set to true
                - proxy configs are without http/https prefix

            When
            - run an http get request

            Then
            -  the request will run and will use proxy configs that will include http:// prefix.
        """
        from CommonServerPython import BaseClient
        import requests_mock

        os.environ['http_proxy'] = 'testproxy:8899'
        os.environ['https_proxy'] = 'testproxy:8899'

        os.environ['REQUESTS_CA_BUNDLE'] = '/test1.pem'
        client = BaseClient('http://example.com/api/v2/', ok_codes=(200, 201), proxy=True, verify=True)

        with requests_mock.mock() as m:
            m.get('http://example.com/api/v2/event')

            res = client._http_request('get', 'event', resp_type='response')

            assert m.last_request.verify == '/test1.pem'
            assert m.last_request.proxies == {
                'http': 'http://testproxy:8899',
                'https': 'http://testproxy:8899'
            }
            assert m.called is True

    def test_http_request_proxy_empty_proxy(self):
        """
            Given
                - proxy param is set to true
                - proxy configs are empty

            When
            - run an http get request

            Then
            -  the request will run and will use empty proxy configs and will not add https prefixes
        """
        from CommonServerPython import BaseClient
        import requests_mock

        os.environ['http_proxy'] = ''
        os.environ['https_proxy'] = ''

        os.environ['REQUESTS_CA_BUNDLE'] = '/test1.pem'
        client = BaseClient('http://example.com/api/v2/', ok_codes=(200, 201), proxy=True, verify=True)

        with requests_mock.mock() as m:
            m.get('http://example.com/api/v2/event')

            res = client._http_request('get', 'event', resp_type='response')

            assert m.last_request.verify == '/test1.pem'
            assert m.last_request.proxies == {}
            assert m.called is True

    def test_http_request_verify_false(self):
        from CommonServerPython import BaseClient
        import requests_mock

        os.environ['REQUESTS_CA_BUNDLE'] = '/test1.pem'
        client = BaseClient('http://example.com/api/v2/', ok_codes=(200, 201), proxy=True, verify=False)

        with requests_mock.mock() as m:
            m.get('http://example.com/api/v2/event')

            res = client._http_request('get', 'event', resp_type='response')

            assert m.last_request.verify is False
            assert m.called is True

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

    def test_http_request_ssl_error_insecure(cls, requests_mock):
        requests_mock.get('http://example.com/api/v2/event', exc=requests.exceptions.SSLError('test ssl'))
        client = cls.BaseClient('http://example.com/api/v2/', ok_codes=(200, 201), verify=False)
        with raises(requests.exceptions.SSLError, match="^test ssl$"):
            client._http_request('get', 'event', resp_type='response')

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

    def test_http_request_timeout_default(self, requests_mock):
        requests_mock.get('http://example.com/api/v2/event', text=json.dumps(self.text))
        self.client._http_request('get', 'event')
        assert requests_mock.last_request.timeout == self.client.REQUESTS_TIMEOUT

    def test_http_request_timeout_given_func(self, requests_mock):
        requests_mock.get('http://example.com/api/v2/event', text=json.dumps(self.text))
        timeout = 120
        self.client._http_request('get', 'event', timeout=timeout)
        assert requests_mock.last_request.timeout == timeout

    def test_http_request_timeout_given_class(self, requests_mock):
        from CommonServerPython import BaseClient
        requests_mock.get('http://example.com/api/v2/event', text=json.dumps(self.text))
        timeout = 44
        new_client = BaseClient('http://example.com/api/v2/', timeout=timeout)
        new_client._http_request('get', 'event')
        assert requests_mock.last_request.timeout == timeout

    def test_http_request_timeout_environ_system(self, requests_mock, mocker):
        from CommonServerPython import BaseClient
        requests_mock.get('http://example.com/api/v2/event', text=json.dumps(self.text))
        timeout = 10
        mocker.patch.dict(os.environ, {'REQUESTS_TIMEOUT': str(timeout)})
        new_client = BaseClient('http://example.com/api/v2/')
        new_client._http_request('get', 'event')
        assert requests_mock.last_request.timeout == timeout

    def test_http_request_timeout_environ_integration(self, requests_mock, mocker):
        requests_mock.get('http://example.com/api/v2/event', text=json.dumps(self.text))
        timeout = 180.1
        # integration name is set to Test in the fixture handle_calling_context
        mocker.patch.dict(os.environ, {'REQUESTS_TIMEOUT.Test': str(timeout)})
        from CommonServerPython import BaseClient
        new_client = BaseClient('http://example.com/api/v2/')
        new_client._http_request('get', 'event')
        assert requests_mock.last_request.timeout == timeout

    def test_http_request_timeout_environ_script(self, requests_mock, mocker):
        requests_mock.get('http://example.com/api/v2/event', text=json.dumps(self.text))
        timeout = 23.4
        script_name = 'TestScript'
        mocker.patch.dict(os.environ, {'REQUESTS_TIMEOUT.' + script_name: str(timeout)})
        mocker.patch.dict(demisto.callingContext, {'context': {'ScriptName': script_name}})
        mocker.patch.object(CommonServerPython, 'get_integration_name', return_value='')
        from CommonServerPython import BaseClient
        new_client = BaseClient('http://example.com/api/v2/')
        new_client._http_request('get', 'event')
        assert requests_mock.last_request.timeout == timeout

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
    # not using 'with' because its not compatible with all python versions
    con = HTTPConnection("google.com")
    con.request('GET', '/')
    with con.getresponse() as r:
        r.read()
    con.close()
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
    # not using 'with' because its not compatible with all python versions
    with con.getresponse() as r:
        r.read()
    con.close()
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


def test_auto_detect_indicator_type_tldextract(mocker):
    """
        Given
            tldextract version is lower than 3.0.0

        When
            Trying to detect the type of an indicator.

        Then
            Run the auto_detect_indicator_type and validate that tldextract using `cache_file` arg and not `cache_dir`
    """
    if sys.version_info.major == 3 and sys.version_info.minor >= 8:
        import tldextract as tlde
        tlde.__version__ = '2.2.7'

        mocker.patch.object(tlde, 'TLDExtract')

        auto_detect_indicator_type('8')

        res = tlde.TLDExtract.call_args
        assert 'cache_file' in res[1].keys()


VALID_URL_INDICATORS = [
    '3.21.32.65/path',
    '19.117.63.253:28/other/path',
    '19.117.63.253:28/path',
    '1.1.1.1/7/server/somestring/something.php?fjjasjkfhsjasofds=sjhfhdsfhasld',
    'flake8.pycqa.org/en/latest',
    '2001:db8:85a3:8d3:1319:8a2e:370:7348/path/path',
    '2001:db8:85a3:8d3:1319:8a2e:370:7348/32/path/path',
    'https://google.com/sdlfdshfkle3247239elkxszmcdfdstgk4e5pt0/path/path/oatdsfk/sdfjjdf',
    'www.123.43.6.89/path',
    'https://15.12.76.123',
    'www.google.com/path',
    'wwW.GooGle.com/path',
    '2001:db8:85a3:8d3:1319:8a2e:370:7348/65/path/path',
    '2001:db8:3333:4444:5555:6666:7777:8888/32/path/path',
    '2001:db8:85a3:8d3:1319:8a2e:370:7348/h'
    '1.1.1.1/7/server',
    "1.1.1.1/32/path",
    'http://evil.tld/',
    'https://evil.tld/evil.html',
    'ftp://foo.bar/',
    'www.evil.tld/evil.aspx',
    'https://www.evil.tld/',
    'www.evil.tld/resource',
    'hxxps://google[.]com',
    'hxxps://google[.]com:443',
    'hxxps://google[.]com:443/path'
    'www.1.2.3.4/?user=test%Email=demisto',
    'www.1.2.3.4:8080/user=test%Email=demisto'
    'http://xn--e1v2i3l4.tld/evilagain.aspx',
    'https://www.xn--e1v2i3l4.tld',
    'https://0330.0072.0307.0116',
    'https://0563.2437.2623.2222',  # IP as octal number
    'https://2467.1461.3567.1434:443',
    'https://3571.3633.2222.3576:443/path',
    'https://4573.2436.1254.7423:443/p',
    'https://0563.2437.2623.2222:443/path/path',
    'hxxps://www.xn--e1v2i3l4.tld',
    'hxxp://www.xn--e1v2i3l4.tld',
    'www.evil.tld:443/path/to/resource.html',
    'WWW.evil.tld:443/path/to/resource.html',
    'wWw.Evil.tld:443/path/to/resource.html',
    'Https://wWw.Evil.tld:443/path/to/resource.html',
    'https://1.2.3.4/path/to/resource.html',
    'HTTPS://1.2.3.4/path/to/resource.html',
    '1.2.3.4/path',
    '1.2.3.4/path/to/resource.html',
    'http://1.2.3.4:8080/',
    'http://1.2.3.4:8080/resource.html',
    'HTTP://1.2.3.4',
    'HTTP://1.2.3.4:80/path',
    'ftp://foo.bar/resource',
    'FTP://foo.bar/resource',
    'http://☺.evil.tld/',
    'ftps://foo.bar/resource',
    'ftps://foo.bar/Resource'
    '5.6.7.8/fdsfs',
    'https://serverName.com/deepLinkAction.do?userName=peter%40nable%2Ecom&password=Hello',
    'http://serverName.org/deepLinkAction.do?userName=peter%40nable%2Ecom&password=Hello',
    'https://1.1.1.1/deepLinkAction.do?userName=peter%40nable%2Ecom&password=Hello',
    'https://google.com/deepLinkAction.do?userName=peter%40nable%2Ecom&password=Hello',
    'www.google.com/deepLinkAction.do?userName=peter%40nable%2Ecom&password=Hello',
    'www.63.4.6.1/integrations/test-playbooks',
    'https://xsoar.pan.dev/docs/welcome',
    '5.6.7.8/user/',
    'http://www.example.com/and%26here.html',
    'https://1234',  # IP as integer 1234 = '0.0.4.210'
    'https://4657624',
    'https://64123/path',
    'https://0.0.0.1/path',
    'https://1',  # same as 0.0.0.1
    'hXXps://isc.sans[.]edu/',
    'hXXps://1.1.1.1[.]edu/',
    'hxxp://0[x]455e8c6f/0s19ef206s18s2f2s567s49a8s91f7s4s19fd61a',  # defanged hexa-decimal IP.
    'hxxp://0x325e5c7f/34823jdsasjfd/asdsafgf/324',  # hexa-decimal IP.
    'hxxps://0xAA268BF1:8080/',
    'hxxps://0xAB268DC1:8080/path',
    'hxxps://0xAB268DC1/',
    'hxxps://0xAB268DC1/p',
    'hxxps://0xAB268DC1/32',
    'http://www.google.com:8080',
    'http://www[.]google.com:8080',  # defanged Domain
    'http://www.google[.]com:8080/path',
    'http://www[.]google.com:8080/path',
    'www[.]google.com:8080/path',
    'www.google[.]com:8080/path',
    'google[.]com/path',
    'google[.]com:443/path',
    'hXXps://1.1.1.1[.]edu/path',
]


@pytest.mark.parametrize('indicator_value', VALID_URL_INDICATORS)
def test_valid_url_indicator_types(indicator_value):
    """
    Given
    - Valid URL indicators.
    When
    - Trying to match those indicators with the URL regex.
    Then
    - The indicators are classified as URL indicators.
    """
    assert re.match(urlRegex, indicator_value)


INVALID_URL_INDICATORS = [
    'test',
    'httn://bla.com/path',
    'google.com*',
    '1.1.1.1',
    '1.1.1.1/',
    '1.1.1.1/32',
    '1.1.1.1/32/',
    'path/path',
    '1.1.1.1:8080',
    '1.1.1.1:8080/',
    '1.1.1.1:111112243245/path',
    '3.4.6.92:8080:/test',
    '1.1.1.1:4lll/',
    '2001:db8:85a3:8d3:1319:8a2e:370:7348/64/',
    '2001:db8:85a3:8d3:1319:8a2e:370:7348/64',
    '2001:db8:85a3:8d3:1319:8a2e:370:7348/32',
    '2001:db8:85a3:8d3:1319:8a2e:370:7348/32',
    '2001:db8:85a3:8d3:1319:8a2e:370:7348/80',
    '2001:db8:3333:4444:5555:6666:7777:8888/',
    'flake8.pycqa.org',
    'google.com',
    'https://test',
    'ftp://test',
    'ftps:test',
    'a.a.a.a',
    'b.b.b',
    'https:/1.1.1.1.1/path',
    'wwww.test',
    'help.test.com',
    'help-test/com'
    'wwww.path.com/path',
    'fnvfdsbf/path',
    '65.23.7.2',
    'k.f.a.f',
    'test/test/test/test',
    'http://www.example.com/ %20here.html'
    'http ://www.example.com/ %20here.html',
    'http://www.example .com/%20here.html'
    'http://wwww.example.com/%20here.html',
    'FTP://Google.test:',
    '',
    'somestring'
    'dsjfshjdfgkjldsh32423123^^&*#@$#@$@!#4',
    'aaa/1.1.1.1/path',
    'domain*com/1.1.1.1/path',
    'http:1.1.1.1/path',
    'kfer93420932/path/path',
    '1.1.1.1.1/24',
    '2.2.2.2.2/3sad',
    'http://fdsfesd',
    'http://fdsfesd:8080',  # no tld
    'FLAKE8.dds.asdfd/',
    'FTP://Google.',
    'https://www.',
    '1.1.1.1.1/path',
    '2.2.2.2.2/3sad',
    'HTTPS://1.1.1.1..1.1.1.1/path',
    'https://1.1.1.1.1.1.1.1.1.1.1/path'
    '1.1.1.1 .1/path',
    '123.6.2.2/ path',
    'hxxps://0xAB26:8080/path',  # must be 8 hexa-decimal chars
    'hxxps://34543645356432234e:8080/path',  # too large integer IP
    'https://35.12.5677.143423:443',  # invalid IP address
    'https://4578.2436.1254.7423',  # invalid octal address (must be numbers between 0-7)
    'https://4578.2436.1254.7423:443/p'
]


@pytest.mark.parametrize('indicator_value', INVALID_URL_INDICATORS)
def test_invalid_url_indicator_types(indicator_value):
    """
    Given
    - invalid URL indicators.
    When
    - Trying to match those indicators with the URL regex.
    Then
    - The indicators are not classified as URL indicators.
    """
    assert not re.match(urlRegex, indicator_value)



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


def test_handle_proxy_without_http_prefix():
    """
        Given
            proxy is configured in environment vars without http/https prefixes

        When
            run handle_proxy()

        Then
            the function will return proxies with http:// prefix
    """
    os.environ['HTTP_PROXY'] = 'testproxy:8899'
    os.environ['HTTPS_PROXY'] = 'testproxy:8899'
    proxies = handle_proxy(checkbox_default_value=True)
    assert proxies['http'] == 'http://testproxy:8899'
    assert proxies['https'] == 'http://testproxy:8899'


def test_handle_proxy_with_http_prefix():
    """
        Given
            proxy is configured in environment vars with http/https prefixes

        When
            run handle_proxy()

        Then
            the function will return proxies unchanged
    """
    os.environ['HTTP_PROXY'] = 'http://testproxy:8899'
    os.environ['HTTPS_PROXY'] = 'https://testproxy:8899'
    proxies = handle_proxy(checkbox_default_value=True)
    assert proxies['http'] == 'http://testproxy:8899'
    assert proxies['https'] == 'https://testproxy:8899'


def test_handle_proxy_with_socks5_prefix():
    """
        Given
            proxy is configured in environment vars with socks5 (socks proxy) prefixes

        When
            run handle_proxy()

        Then
            the function will return proxies unchanged
    """
    os.environ['HTTP_PROXY'] = 'socks5://testproxy:8899'
    os.environ['HTTPS_PROXY'] = 'socks5://testproxy:8899'
    proxies = handle_proxy(checkbox_default_value=True)
    assert proxies['http'] == 'socks5://testproxy:8899'
    assert proxies['https'] == 'socks5://testproxy:8899'


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
    args, _ = demisto_results_mock.call_args_list[0]
    assert demisto_results_mock.call_count == 1
    assert [{'MockContext': 0}, {'MockContext': 1}] in args


def test_return_results_mixed_results(mocker):
    """
    Given:
      - List containing a CommandResult object and two dictionaries (representing a demisto result entries)
    When:
      - Calling return_results()
    Then:
      - Assert that demisto.results() is called 2 times .
      - Assert that the first call was with the CommandResult object.
      - Assert that the second call was with the two demisto results dicts.
    """
    from CommonServerPython import CommandResults, return_results
    demisto_results_mock = mocker.patch.object(demisto, 'results')
    mock_command_results_object = CommandResults(outputs_prefix='Mock', outputs={'MockContext': 0})
    mock_demisto_results_entry = [{'MockContext': 1}, {'MockContext': 2}]
    return_results([mock_command_results_object] + mock_demisto_results_entry)

    assert demisto_results_mock.call_count == 2
    assert demisto_results_mock.call_args_list[0][0][0] == mock_command_results_object.to_context()
    assert demisto_results_mock.call_args_list[1][0][0] == mock_demisto_results_entry


class TestExecuteCommand:
    @staticmethod
    def test_sanity(mocker):
        """
        Given:
            - A successful command with a single entry as output.
        When:
            - Calling execute_command.
        Then:
            - Assert that only the Contents value is returned.
        """
        from CommonServerPython import execute_command, EntryType
        demisto_execute_mock = mocker.patch.object(demisto, 'executeCommand',
                                                   return_value=[{'Type': EntryType.NOTE,
                                                                  'Contents': {'hello': 'world'}}])
        res = execute_command('command', {'arg1': 'value'})
        execute_command_args = demisto_execute_mock.call_args_list[0][0]
        assert demisto_execute_mock.call_count == 1
        assert execute_command_args[0] == 'command'
        assert execute_command_args[1] == {'arg1': 'value'}
        assert res == {'hello': 'world'}

    @staticmethod
    def test_multiple_results(mocker):
        """
        Given:
            - A successful command with several entries as output.
        When:
            - Calling execute_command.
        Then:
            - Assert that the "Contents" values of all entries are returned.
        """
        from CommonServerPython import execute_command, EntryType
        entries = [
            {'Type': EntryType.NOTE, 'Contents': {'hello': 'world'}},
            {'Type': EntryType.NOTE, 'Context': 'no contents here'},
            {'Type': EntryType.NOTE, 'Contents': {'entry': '2'}},
        ]
        demisto_execute_mock = mocker.patch.object(demisto, 'executeCommand',
                                                   return_value=entries)
        res = execute_command('command', {'arg1': 'value'})
        assert demisto_execute_mock.call_count == 1
        assert isinstance(res, list)
        assert len(res) == 3
        assert res[0] == {'hello': 'world'}
        assert res[1] == {}
        assert res[2] == {'entry': '2'}

    @staticmethod
    def test_raw_results(mocker):
        """
        Given:
            - A successful command with several entries as output.
        When:
            - Calling execute_command.
        Then:
            - Assert that the entire entries are returned.
        """
        from CommonServerPython import execute_command, EntryType
        entries = [
            {'Type': EntryType.NOTE, 'Contents': {'hello': 'world'}},
            {'Type': EntryType.NOTE, 'Context': 'no contents here'},
            'text',
            1337,
        ]
        demisto_execute_mock = mocker.patch.object(demisto, 'executeCommand',
                                                   return_value=entries)
        res = execute_command('command', {'arg1': 'value'}, extract_contents=False)
        assert demisto_execute_mock.call_count == 1
        assert isinstance(res, list)
        assert len(res) == 4
        assert res[0] == {'Type': EntryType.NOTE, 'Contents': {'hello': 'world'}}
        assert res[1] == {'Type': EntryType.NOTE, 'Context': 'no contents here'}
        assert res[2] == 'text'
        assert res[3] == 1337

    @staticmethod
    def test_failure(mocker):
        """
        Given:
            - A command that fails.
        When:
            - Calling execute_command.
        Then:
            - Assert that the original error is returned to War-Room (using demisto.results).
            - Assert an error is returned to the War-Room.
            - Function ends the run using SystemExit.
        """
        from CommonServerPython import execute_command, EntryType
        error_entries = [
            {'Type': EntryType.ERROR, 'Contents': 'error number 1'},
            {'Type': EntryType.NOTE, 'Contents': 'not an error'},
            {'Type': EntryType.ERROR, 'Contents': 'error number 2'},
        ]
        demisto_execute_mock = mocker.patch.object(demisto, 'executeCommand',
                                                   return_value=error_entries)
        demisto_results_mock = mocker.patch.object(demisto, 'results')

        with raises(SystemExit, match='0'):
            execute_command('bad', {'arg1': 'value'})

        assert demisto_execute_mock.call_count == 1
        assert demisto_results_mock.call_count == 1
        # first call, args (not kwargs), first argument
        error_text = demisto_results_mock.call_args_list[0][0][0]['Contents']
        assert 'Failed to execute bad.' in error_text
        assert 'error number 1' in error_text
        assert 'error number 2' in error_text
        assert 'not an error' not in error_text

    @staticmethod
    def test_failure_integration(monkeypatch):
        from CommonServerPython import execute_command, EntryType
        monkeypatch.delattr(demisto, 'executeCommand')

        with raises(DemistoException, match=r'Cannot run demisto.executeCommand\(\) from integrations.'):
            execute_command('bad', {'arg1': 'value'})

    @staticmethod
    def test_multiple_results_fail_on_error_false(mocker):
        """
        Given:
            - A successful command with several entries as output.
            - fail_on_error set to False.
        When:
            - Calling execute_command.
        Then:
            - Assert that the status of the execution is True for successful run.
            - Assert that the "Contents" values of all entries are returned.
        """
        from CommonServerPython import execute_command, EntryType
        entries = [
            {'Type': EntryType.NOTE, 'Contents': {'hello': 'world'}},
            {'Type': EntryType.NOTE, 'Context': 'no contents here'},
            {'Type': EntryType.NOTE, 'Contents': {'entry': '2'}},
        ]
        demisto_execute_mock = mocker.patch.object(demisto, 'executeCommand',
                                                   return_value=entries)
        status, res = execute_command('command', {'arg1': 'value'}, fail_on_error=False)
        assert demisto_execute_mock.call_count == 1
        assert isinstance(res, list)
        assert len(res) == 3
        assert status
        assert res[0] == {'hello': 'world'}
        assert res[1] == {}
        assert res[2] == {'entry': '2'}

    @staticmethod
    def test_raw_results_fail_on_error_false(mocker):
        """
        Given:
            - A successful command with several entries as output.
            - fail_on_error set to False.
        When:
            - Calling execute_command.
        Then:
            - Assert that the status of the execution is True for successful run.
            - Assert that the entire entries are returned.
        """
        from CommonServerPython import execute_command, EntryType
        entries = [
            {'Type': EntryType.NOTE, 'Contents': {'hello': 'world'}},
            {'Type': EntryType.NOTE, 'Context': 'no contents here'},
            'text',
            1337,
        ]
        demisto_execute_mock = mocker.patch.object(demisto, 'executeCommand',
                                                   return_value=entries)
        status, res = execute_command('command', {'arg1': 'value'}, extract_contents=False, fail_on_error=False)
        assert demisto_execute_mock.call_count == 1
        assert isinstance(res, list)
        assert len(res) == 4
        assert status
        assert res[0] == {'Type': EntryType.NOTE, 'Contents': {'hello': 'world'}}
        assert res[1] == {'Type': EntryType.NOTE, 'Context': 'no contents here'}
        assert res[2] == 'text'
        assert res[3] == 1337

    @staticmethod
    def test_failure_fail_on_error_false(mocker):
        """
        Given:
            - A command that fails.
            - fail_on_error set to False.
        When:
            - Calling execute_command.
        Then:
            - Assert that the status of the execution is False for failed run.
            - Assert that the original errors are returned as a value, and not to the war-room.
        """
        from CommonServerPython import execute_command, EntryType
        error_entries = [
            {'Type': EntryType.ERROR, 'Contents': 'error number 1'},
            {'Type': EntryType.NOTE, 'Contents': 'not an error'},
            {'Type': EntryType.ERROR, 'Contents': 'error number 2'},
        ]
        demisto_execute_mock = mocker.patch.object(demisto, 'executeCommand',
                                                   return_value=error_entries)
        demisto_results_mock = mocker.patch.object(demisto, 'results')

        status, error_text = execute_command('bad', {'arg1': 'value'}, fail_on_error=False)

        assert demisto_execute_mock.call_count == 1
        assert demisto_results_mock.call_count == 0
        assert not status
        assert 'error number 1' in error_text
        assert 'error number 2' in error_text
        assert 'not an error' not in error_text


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


def test_warnings_handler(mocker):
    mocker.patch.object(demisto, 'info')
    # need to initialize WarningsHandler as pytest over-rides the handler
    with pytest.warns(RuntimeWarning) as r:
        warnings.warn("without handler", RuntimeWarning)
        handler = WarningsHandler()  # noqa
        warnings.warn("This is a test", RuntimeWarning)
        assert len(r) == 1
        assert str(r[0].message) == "without handler"

    # call_args is tuple (args list, kwargs). we only need the args
    msg = demisto.info.call_args[0][0]
    assert 'This is a test' in msg
    assert 'python warning' in msg


def test_get_schedule_metadata():
    """
        Given
            - case 1: no parent entry
            - case 2: parent entry with schedule metadata
            - case 3: parent entry without schedule metadata

        When
            querying the schedule metadata

        Then
            ensure scheduled_metadata is returned correctly
            - case 1: no data (empty dict)
            - case 2: schedule metadata with all details
            - case 3: empty schedule metadata (dict with polling: false)
    """
    from CommonServerPython import get_schedule_metadata

    # case 1
    context = {'ParentEntry': None}
    actual_scheduled_metadata = get_schedule_metadata(context=context)
    assert actual_scheduled_metadata == {}

    # case 2
    parent_entry = {
        'polling': True,
        'pollingCommand': 'foo',
        'pollingArgs': {'name': 'foo'},
        'timesRan': 5,
        'startDate': '2021-04-28T14:20:56.03728+03:00',
        'endingDate': '2021-04-28T14:25:35.976244+03:00'
    }
    context = {
        'ParentEntry': parent_entry
    }
    actual_scheduled_metadata = get_schedule_metadata(context=context)
    assert actual_scheduled_metadata.get('is_polling') is True
    assert actual_scheduled_metadata.get('polling_command') == parent_entry.get('pollingCommand')
    assert actual_scheduled_metadata.get('polling_args') == parent_entry.get('pollingArgs')
    assert actual_scheduled_metadata.get('times_ran') == (parent_entry.get('timesRan') + 1)
    assert actual_scheduled_metadata.get('startDate') == parent_entry.get('start_date')
    assert actual_scheduled_metadata.get('startDate') == parent_entry.get('start_date')

    # case 3
    parent_entry = {
        'polling': False
    }
    context = {
        'ParentEntry': parent_entry
    }
    actual_scheduled_metadata = get_schedule_metadata(context=context)
    assert actual_scheduled_metadata == {'is_polling': False, 'times_ran': 1}


class TestCommonTypes:
    def test_create_domain(self):
        from CommonServerPython import CommandResults, Common, EntryType, EntryFormat, DBotScoreType

        dbot_score = Common.DBotScore(
            indicator='somedomain.com',
            integration_name='Test',
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
            ],
            tags=['tag1', 'tag2'],
            malware_family=['malware_family1', 'malware_family2'],
            feed_related_indicators=[Common.FeedRelatedIndicators(
                value='8.8.8.8',
                indicator_type="IP",
                description='test'
            )],
            domain_idn_name='domain_idn_name',
            port='port',
            internal="False",
            category='category',
            campaign='campaign',
            traffic_light_protocol='traffic_light_protocol',
            threat_types=[Common.ThreatTypes(threat_category='threat_category',
                                             threat_category_confidence='threat_category_confidence')],
            community_notes=[Common.CommunityNotes(note='note', timestamp='2019-01-01T00:00:00')],
            publications=[Common.Publications(title='title', source='source', timestamp='2019-01-01T00:00:00',
                                              link='link')],
            geo_location='geo_location',
            geo_country='geo_country',
            geo_description='geo_description',
            tech_country='tech_country',
            tech_name='tech_name',
            tech_organization='tech_organization',
            tech_email='tech_email',
            billing='billing'
        )

        results = CommandResults(
            outputs_key_field=None,
            outputs_prefix=None,
            outputs=None,
            indicators=[domain]
        )

        assert results.to_context() == {
            'Type': 1,
            'ContentsFormat': 'json',
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
                        "Tags": ["tag1", "tag2"],
                        "FeedRelatedIndicators": [{"value": "8.8.8.8", "type": "IP", "description": "test"}],
                        "MalwareFamily": ["malware_family1", "malware_family2"],
                        "DomainIDNName": "domain_idn_name",
                        "Port": "port",
                        "Internal": "False",
                        "Category": "category",
                        "Campaign": "campaign",
                        "TrafficLightProtocol": "traffic_light_protocol",
                        "ThreatTypes": [{
                            "threatcategory": "threat_category",
                            "threatcategoryconfidence": "threat_category_confidence"
                        }],
                        "CommunityNotes": [{
                            "note": "note",
                            "timestamp": "2019-01-01T00:00:00"
                        }],
                        "Publications": [{
                            "source": "source",
                            "title": "title",
                            "link": "link",
                            "timestamp": "2019-01-01T00:00:00"
                        }],
                        "Geo": {
                            "Location": "geo_location",
                            "Country": "geo_country",
                            "Description": "geo_description"
                        },
                        "Tech": {
                            "Country": "tech_country",
                            "Name": "tech_name",
                            "Organization": "tech_organization",
                            "Email": "tech_email"
                        },
                        "Billing": "billing",
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
                        'Type': 'domain',
                        'Vendor': 'Test',
                        'Score': 1
                    }
                ]
            },
            'IndicatorTimeline': [],
            'IgnoreAutoExtract': False,
            'Note': False,
            'Relationships': []
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
            integration_name='Test',
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
                    "Vendor": "Test",
                    "Score": 0
                }]
            },
            'IndicatorTimeline': [],
            'Relationships': [],
            'IgnoreAutoExtract': False,
            'Note': False
        }

    def test_email_indicator_type(self, mocker):
        """
        Given:
            - a single email indicator entry
        When
           - creating an Common.EMAIL object
       Then
           - The context created matches the data entry
       """
        from CommonServerPython import Common, DBotScoreType
        mocker.patch.object(demisto, 'params', return_value={'insecure': True})
        dbot_score = Common.DBotScore(
            indicator='user@example.com',
            integration_name='Test',
            indicator_type=DBotScoreType.EMAIL,
            score=Common.DBotScore.GOOD
        )
        dbot_context = {'DBotScore(val.Indicator && val.Indicator == obj.Indicator && '
                        'val.Vendor == obj.Vendor && val.Type == obj.Type)':
                            {'Indicator': 'user@example.com', 'Type': 'email', 'Vendor': 'Test', 'Score': 1}}

        assert dbot_context == dbot_score.to_context()

        email_context = Common.EMAIL(
            domain='example.com',
            address='user@example.com',
            dbot_score=dbot_score
        )
        assert email_context.to_context()[email_context.CONTEXT_PATH] == {'Address': 'user@example.com',
                                                                          'Domain': 'example.com'}


class TestIndicatorsSearcher:
    def mock_search_after_output(self, fromDate='', toDate='', query='', size=0, value='', page=0, searchAfter='',
                                 populateFields=None):
        if not searchAfter:
            searchAfter = 0

        iocs = [{'value': 'mock{}'.format(searchAfter)}]

        if searchAfter < 6:
            searchAfter += 1

        else:
            # mock the end of indicators
            searchAfter = None

        if page and page >= 17:
            # checking a unique case when trying to reach a certain page and not all the indicators
            iocs = []
            searchAfter = None

        return {'searchAfter': searchAfter, 'iocs': iocs, 'total': 7}

    def mock_search_indicators_search_after(self, fromDate='', toDate='', query='', size=0, value='', page=0,
                                            searchAfter=None, populateFields=None):
        """
        Mocks search indicators returning different results for searchAfter value:
          - None: {searchAfter: 0, iocs: [...]}
          - 0-2: {searchAfter: i+1, iocs: [...]}
          - 3+: {searchAfter: None, iocs: []}

        total of 4 iocs available
        """
        search_after_options = (0, 1, 2)
        if searchAfter is None:
            search_after_value = search_after_options[0]
        else:
            if searchAfter in search_after_options:
                search_after_value = searchAfter + 1
            else:
                return {'searchAfter': None, 'iocs': []}
        iocs = [{'value': 'mock{}'.format(search_after_value)}]
        return {'searchAfter': search_after_value, 'iocs': iocs, 'total': 4}

    def test_search_indicators_by_page(self, mocker):
        """
        Given:
          - Searching indicators couple of times
          - Server version in less than 6.1.0
        When:
          - Mocking search indicators using paging
        Then:
          - The page number is rising
        """
        from CommonServerPython import IndicatorsSearcher
        mocker.patch.object(demisto, 'searchIndicators', side_effect=self.mock_search_after_output)

        search_indicators_obj_paging = IndicatorsSearcher()
        search_indicators_obj_paging._can_use_search_after = False

        for n in range(5):
            search_indicators_obj_paging.search_indicators_by_version()

        assert search_indicators_obj_paging._page == 5

    def test_search_indicators_by_search_after(self, mocker):
        """
        Given:
          - Searching indicators couple of times
          - Server version in equal or higher than 6.1.0
        When:
          - Mocking search indicators using the searchAfter parameter
        Then:
          - The search after param is rising
          - The page param is rising
        """
        from CommonServerPython import IndicatorsSearcher
        mocker.patch.object(demisto, 'searchIndicators', side_effect=self.mock_search_after_output)

        search_indicators_obj_search_after = IndicatorsSearcher()
        search_indicators_obj_search_after._can_use_search_after = True
        try:
            for n in range(5):
                search_indicators_obj_search_after.search_indicators_by_version()
        except Exception as e:
            print(e)

        assert search_indicators_obj_search_after._search_after_param == 5
        assert search_indicators_obj_search_after._page == 5

    def test_search_all_indicators_by_search_after(self, mocker):
        """
        Given:
          - Searching indicators couple of times
          - Server version in equal or higher than 6.1.0
        When:
          - Mocking search indicators using the searchAfter parameter until there are no more indicators
          so search_after is None
        Then:
          - The search after param is None
          - The page param is rising
        """
        from CommonServerPython import IndicatorsSearcher
        mocker.patch.object(demisto, 'searchIndicators', side_effect=self.mock_search_after_output)

        search_indicators_obj_search_after = IndicatorsSearcher()
        search_indicators_obj_search_after._can_use_search_after = True
        for n in range(7):
            search_indicators_obj_search_after.search_indicators_by_version()
        assert search_indicators_obj_search_after._search_after_param is None
        assert search_indicators_obj_search_after._page == 7

    def test_search_indicators_in_certain_page(self, mocker):
        """
        Given:
          - Searching indicators in a specific page that is not 0
          - Server version in less than 6.1.0
        When:
          - Mocking search indicators in this specific page
          so search_after is None
        Then:
          - The search after param is not None
          - The page param is 17
        """
        from CommonServerPython import IndicatorsSearcher
        mocker.patch.object(demisto, 'searchIndicators', side_effect=self.mock_search_after_output)

        search_indicators_obj_search_after = IndicatorsSearcher(page=17)
        search_indicators_obj_search_after._can_use_search_after = False
        search_indicators_obj_search_after.search_indicators_by_version()

        assert search_indicators_obj_search_after._search_after_param is None
        assert search_indicators_obj_search_after._page == 18

    def test_iterator__pages(self, mocker):
        """
        Given:
          - Searching indicators from page 1
          - Total available indicators == 6
        When:
          - Searching indicators using iterator
        Then:
          - Get 6 indicators
          - Advance page to 7
          - is_search_done returns True
        """
        from CommonServerPython import IndicatorsSearcher
        mocker.patch.object(demisto, 'searchIndicators', side_effect=self.mock_search_after_output)

        search_indicators = IndicatorsSearcher(page=1, size=1)
        search_indicators._can_use_search_after = False
        results = []
        for res in search_indicators:
            results.append(res)
        assert len(results) == 6
        assert search_indicators.page == 7
        assert search_indicators.is_search_done() is True

    def test_iterator__search_after(self, mocker):
        """
        Given:
          - Searching indicators from first page
          - Total available indicators == 7
          - Limit is set to 10
        When:
          - Searching indicators using iterator
          - search_after is supported
        Then:
          - Get 7 indicators
        """
        from CommonServerPython import IndicatorsSearcher
        mocker.patch.object(demisto, 'searchIndicators', side_effect=self.mock_search_indicators_search_after)
        search_indicators = IndicatorsSearcher(limit=10)
        search_indicators._can_use_search_after = True
        results = []
        for res in search_indicators:
            results.append(res)
        assert len(results) == 4

    def test_iterator__empty_page(self, mocker):
        """
        Given:
          - Searching indicators from page 18
          - Total available indicators from page 10-16 == 7
          - No available indicators from page 17
        When:
          - Searching indicators using iterator (search_after is not supported)
        Then:
          - Get 0 indicators
          - page doesn't advance (set to 18)
        """
        from CommonServerPython import IndicatorsSearcher
        mocker.patch.object(demisto, 'searchIndicators', side_effect=self.mock_search_after_output)

        search_indicators = IndicatorsSearcher(page=18)
        results = []
        for res in search_indicators:
            results.append(res)
        assert len(results) == 0
        assert search_indicators.page == 19

    def test_iterator__research_flow(self, mocker):
        from CommonServerPython import IndicatorsSearcher
        mocker.patch.object(demisto, 'searchIndicators', side_effect=self.mock_search_indicators_search_after)
        # fetch first 3
        search_indicators = IndicatorsSearcher(limit=3)
        search_indicators._can_use_search_after = True
        results = []
        for res in search_indicators:
            results.append(res)
        assert len(results) == 3
        # fetch 1 more (limit set to 2, but only 1 available)
        search_indicators.limit += 2
        results = []
        for res in search_indicators:
            results.append(res)
        assert len(results) == 1


class TestAutoFocusKeyRetriever:
    def test_instantiate_class_with_param_key(self, mocker, clear_version_cache):
        """
        Given:
            - giving the api_key parameter
        When:
            - Mocking getAutoFocusApiKey
            - Mocking server version to be 6.2.0
        Then:
            - The Auto Focus API Key is the one given to the class
        """
        from CommonServerPython import AutoFocusKeyRetriever
        mocker.patch.object(demisto, 'getAutoFocusApiKey', return_value='test')
        mocker.patch.object(demisto, 'demistoVersion', return_value={'version': '6.2.0', 'buildNumber': '62000'})
        auto_focus_key_retriever = AutoFocusKeyRetriever(api_key='1234')
        assert auto_focus_key_retriever.key == '1234'

    def test_instantiate_class_pre_6_2_failed(self, mocker, clear_version_cache):
        """
        Given:
            - not giving the api_key parameter
        When:
            - Mocking getAutoFocusApiKey
            - Mocking server version to be 6.1.0
        Then:
            - Validate an exception with appropriate error message is raised.
        """
        from CommonServerPython import AutoFocusKeyRetriever
        mocker.patch.object(demisto, 'getAutoFocusApiKey', return_value='test')
        mocker.patch.object(demisto, 'demistoVersion', return_value={'version': '6.1.0', 'buildNumber': '61000'})
        with raises(DemistoException, match='For versions earlier than 6.2.0, configure an API Key.'):
            AutoFocusKeyRetriever(api_key='')

    def test_instantiate_class_without_param_key(self, mocker, clear_version_cache):
        """
        Given:
            - not giving the api_key parameter
        When:
            - Mocking getAutoFocusApiKey
            - Mocking server version to be 6.2.0
        Then:
            - The Auto Focus API Key is the one given by the getAutoFocusApiKey method
        """
        from CommonServerPython import AutoFocusKeyRetriever
        mocker.patch.object(demisto, 'getAutoFocusApiKey', return_value='test')
        mocker.patch.object(demisto, 'demistoVersion', return_value={'version': '6.2.0', 'buildNumber': '62000'})
        auto_focus_key_retriever = AutoFocusKeyRetriever(api_key='')
        assert auto_focus_key_retriever.key == 'test'


class TestEntityRelationship:
    """Global vars for all of the tests"""
    name = 'related-to'
    reverse_name = 'related-to'
    relationship_type = 'IndicatorToIndicator'
    entity_a = 'test1'
    entity_a_family = 'Indicator'
    entity_a_type = 'Domain'
    entity_b = 'test2'
    entity_b_family = 'Indicator'
    entity_b_type = 'Domain'
    source_reliability = 'F - Reliability cannot be judged'

    def test_entity_relations_context(self):
        """
        Given
        - an EntityRelationship object.

        When
        - running to_context function of the object

        Then
        - Validate that the expected context is created
        """
        from CommonServerPython import EntityRelationship
        relationship = EntityRelationship(name='related-to',
                                          relationship_type='IndicatorToIndicator',
                                          entity_a='test1',
                                          entity_a_family='Indicator',
                                          entity_a_type='Domain',
                                          entity_b='test2',
                                          entity_b_family='Indicator',
                                          entity_b_type='Domain',
                                          source_reliability='F - Reliability cannot be judged',
                                          brand='test')

        expected_context = {
            "Relationship": 'related-to',
            "EntityA": 'test1',
            "EntityAType": 'Domain',
            "EntityB": 'test2',
            "EntityBType": 'Domain',
        }
        assert relationship.to_context() == expected_context

    def test_entity_relations_to_entry(self):
        """
        Given
        - an EntityRelationship object.

        When
        - running to_entry function of the object

        Then
        - Validate that the expected context is created
        """
        from CommonServerPython import EntityRelationship
        relationship = EntityRelationship(name=TestEntityRelationship.name,
                                          relationship_type=TestEntityRelationship.relationship_type,
                                          entity_a=TestEntityRelationship.entity_a,
                                          entity_a_family=TestEntityRelationship.entity_a_family,
                                          entity_a_type=TestEntityRelationship.entity_a_type,
                                          entity_b=TestEntityRelationship.entity_b,
                                          entity_b_family=TestEntityRelationship.entity_b_family,
                                          entity_b_type=TestEntityRelationship.entity_b_type,
                                          source_reliability=TestEntityRelationship.source_reliability
                                          )

        expected_entry = {
            "name": TestEntityRelationship.name,
            "reverseName": TestEntityRelationship.reverse_name,
            "type": TestEntityRelationship.relationship_type,
            "entityA": TestEntityRelationship.entity_a,
            "entityAFamily": TestEntityRelationship.entity_a_family,
            "entityAType": TestEntityRelationship.entity_a_type,
            "entityB": TestEntityRelationship.entity_b,
            "entityBFamily": TestEntityRelationship.entity_b_family,
            "entityBType": TestEntityRelationship.entity_b_type,
            "fields": {},
            "reliability": TestEntityRelationship.source_reliability
        }
        assert relationship.to_entry() == expected_entry

    def test_entity_relations_to_indicator(self):
        """
        Given
        - an EntityRelationship object.

        When
        - running to_indicator function of the object

        Then
        - Validate that the expected context is created
        """
        from CommonServerPython import EntityRelationship
        relationship = EntityRelationship(name=TestEntityRelationship.name,
                                          relationship_type=TestEntityRelationship.relationship_type,
                                          entity_a=TestEntityRelationship.entity_a,
                                          entity_a_family=TestEntityRelationship.entity_a_family,
                                          entity_a_type=TestEntityRelationship.entity_a_type,
                                          entity_b=TestEntityRelationship.entity_b,
                                          entity_b_family=TestEntityRelationship.entity_b_family,
                                          entity_b_type=TestEntityRelationship.entity_b_type,
                                          )

        expected_to_indicator = {
            "name": TestEntityRelationship.name,
            "reverseName": TestEntityRelationship.reverse_name,
            "type": TestEntityRelationship.relationship_type,
            "entityA": TestEntityRelationship.entity_a,
            "entityAFamily": TestEntityRelationship.entity_a_family,
            "entityAType": TestEntityRelationship.entity_a_type,
            "entityB": TestEntityRelationship.entity_b,
            "entityBFamily": TestEntityRelationship.entity_b_family,
            "entityBType": TestEntityRelationship.entity_b_type,
            "fields": {},
        }
        assert relationship.to_indicator() == expected_to_indicator

    def test_invalid_name_init(self):
        """
        Given
        - an EntityRelation object which has a invalid relation name.

        When
        - Creating the EntityRelation object.

        Then
        - Validate a ValueError is raised.
        """
        from CommonServerPython import EntityRelationship
        try:
            EntityRelationship(name='ilegal',
                               relationship_type=TestEntityRelationship.relationship_type,
                               entity_a=TestEntityRelationship.entity_a,
                               entity_a_family=TestEntityRelationship.entity_a_family,
                               entity_a_type=TestEntityRelationship.entity_a_type,
                               entity_b=TestEntityRelationship.entity_b,
                               entity_b_family=TestEntityRelationship.entity_b_family,
                               entity_b_type=TestEntityRelationship.entity_b_type
                               )
        except ValueError as exception:
            assert "Invalid relationship: ilegal" in str(exception)

    def test_invalid_relation_type_init(self):
        """
        Given
        - an EntityRelation object which has a invalid relation type.

        When
        - Creating the EntityRelation object.

        Then
        - Validate a ValueError is raised.
        """
        from CommonServerPython import EntityRelationship
        try:
            EntityRelationship(name=TestEntityRelationship.name,
                               relationship_type='TestRelationshipType',
                               entity_a=TestEntityRelationship.entity_a,
                               entity_a_family=TestEntityRelationship.entity_a_family,
                               entity_a_type=TestEntityRelationship.entity_a_type,
                               entity_b=TestEntityRelationship.entity_b,
                               entity_b_family=TestEntityRelationship.entity_b_family,
                               entity_b_type=TestEntityRelationship.entity_b_type
                               )
        except ValueError as exception:
            assert "Invalid relationship type: TestRelationshipType" in str(exception)

    def test_invalid_a_family_init(self):
        """
        Given
        - an EntityRelation object which has a invalid family type of the source.

        When
        - Creating the EntityRelation object.

        Then
        - Validate a ValueError is raised.
        """
        from CommonServerPython import EntityRelationship
        try:
            EntityRelationship(name=TestEntityRelationship.name,
                               relationship_type=TestEntityRelationship.relationship_type,
                               entity_a=TestEntityRelationship.entity_a,
                               entity_a_family='IndicatorIlegal',
                               entity_a_type=TestEntityRelationship.entity_a_type,
                               entity_b=TestEntityRelationship.entity_b,
                               entity_b_family=TestEntityRelationship.entity_b_family,
                               entity_b_type=TestEntityRelationship.entity_b_type
                               )
        except ValueError as exception:
            assert "Invalid entity A Family type: IndicatorIlegal" in str(exception)

    def test_invalid_a_type_init(self):
        """
        Given
        - an EntityRelation object which has a invalid type of the source.

        When
        - Creating the EntityRelation object.

        Then
        - Validate a ValueError is raised.
        """
        from CommonServerPython import EntityRelationship
        try:
            EntityRelationship(name=TestEntityRelationship.name,
                               relationship_type=TestEntityRelationship.relationship_type,
                               entity_a=TestEntityRelationship.entity_a,
                               entity_a_family=TestEntityRelationship.entity_a_family,
                               entity_a_type='DomainTest',
                               entity_b=TestEntityRelationship.entity_b,
                               entity_b_family=TestEntityRelationship.entity_b_family,
                               entity_b_type=TestEntityRelationship.entity_b_type
                               )
        except ValueError as exception:
            assert "Invalid entity A type: DomainTest" in str(exception)

    def test_invalid_b_family_init(self):
        """
        Given
        - an EntityRelation object which has a invalid family type of the destination.

        When
        - Creating the EntityRelation object.

        Then
        - Validate a ValueError is raised.
        """
        from CommonServerPython import EntityRelationship
        try:
            EntityRelationship(name=TestEntityRelationship.name,
                               relationship_type=TestEntityRelationship.relationship_type,
                               entity_a=TestEntityRelationship.entity_a,
                               entity_a_family=TestEntityRelationship.entity_a_family,
                               entity_a_type=TestEntityRelationship.entity_a_type,
                               entity_b=TestEntityRelationship.entity_b,
                               entity_b_family='IndicatorIlegal',
                               entity_b_type=TestEntityRelationship.entity_b_type
                               )
        except ValueError as exception:
            assert "Invalid entity B Family type: IndicatorIlegal" in str(exception)

    def test_invalid_b_type_init(self):
        """
        Given
        - an EntityRelation object which has a invalid type of the destination.

        When
        - Creating the EntityRelation object.

        Then
        - Validate a ValueError is raised.
        """
        from CommonServerPython import EntityRelationship
        try:
            EntityRelationship(name=TestEntityRelationship.name,
                               relationship_type=TestEntityRelationship.relationship_type,
                               entity_a=TestEntityRelationship.entity_a,
                               entity_a_family=TestEntityRelationship.entity_a_family,
                               entity_a_type=TestEntityRelationship.entity_a_type,
                               entity_b=TestEntityRelationship.entity_b,
                               entity_b_family=TestEntityRelationship.entity_b_family,
                               entity_b_type='DomainTest'
                               )
        except ValueError as exception:
            assert "Invalid entity B type: DomainTest" in str(exception)


class TestSetAndGetLastRun:

    def test_get_last_run_in_6_2_when_get_last_run_has_results(self, mocker):
        """
        Given: 6.2.0 environment and getLastRun returns results
        When: Fetch indicators
        Then: Returning all indicators from demisto.getLastRun object
        """
        import demistomock as demisto
        from CommonServerPython import get_feed_last_run
        mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
        mocker.patch.object(demisto, 'getLastRun', return_value={1: "first indicator"})
        result = get_feed_last_run()
        assert result == {1: "first indicator"}

    def test_get_last_run_in_6_1_when_get_integration_context_has_results(self, mocker):
        """
        Given: 6.1.0 environment and getIntegrationContext return results
        When: Fetch indicators
                This can happen when updating XSOAR version to 6.2.0 while a feed instance is already set.
        Then: Returning all indicators from demisto.getIntegrationContext object
        """
        import demistomock as demisto
        from CommonServerPython import get_feed_last_run
        mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.1.0"})
        mocker.patch.object(demisto, 'getIntegrationContext', return_value={1: "first indicator"})
        result = get_feed_last_run()
        assert result == {1: "first indicator"}

    def test_get_last_run_in_6_2_when_get_last_run_has_no_results(self, mocker):
        """
        Given: 6.2.0 environment and getLastRun and getIntegrationContext are empty
        When: Fetch indicators
        Then: function will return empty dict
        """
        import demistomock as demisto
        from CommonServerPython import get_feed_last_run
        mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
        mocker.patch.object(demisto, 'getIntegrationContext', return_value={})
        mocker.patch.object(demisto, 'getLastRun', return_value={})
        result = get_feed_last_run()
        assert result == {}

    def test_get_last_run_in_6_2_when_get_last_is_empty_and_get_integration_is_not(self, mocker):
        """
        Given: 6.2.0 environment and getLastRun is empty and getIntegrationContext has results.
        When: Fetch indicators
        Then: function will return empty dict
        """
        import demistomock as demisto
        from CommonServerPython import get_feed_last_run
        mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
        mocker.patch.object(demisto, 'getIntegrationContext', return_value={1: "first indicator"})
        mocker.patch.object(demisto, 'getLastRun', return_value={})
        set_last_run = mocker.patch.object(demisto, 'setLastRun', return_value={})
        set_integration_context = mocker.patch.object(demisto, 'setIntegrationContext', return_value={})
        result = get_feed_last_run()
        assert result == {1: "first indicator"}
        set_last_run.assert_called_with({1: "first indicator"})
        set_integration_context.assert_called_with({})

    def test_set_last_run_in_6_2(self, mocker):
        """
        Given: 6.2.0 environment
        When: Fetch indicators
        Then: Using demisto.setLastRun to save results
        """
        import demistomock as demisto
        from CommonServerPython import set_feed_last_run
        mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
        set_last_run = mocker.patch.object(demisto, 'setLastRun', return_value={})
        set_integration_context = mocker.patch.object(demisto, 'setIntegrationContext', return_value={})
        set_feed_last_run({1: "first indicator"})
        assert set_integration_context.called is False
        set_last_run.assert_called_with({1: "first indicator"})

    def test_set_last_run_in_6_1(self, mocker):
        """
        Given: 6.1.0 environment
        When: Fetch indicators
        Then: Using demisto.setIntegrationContext to save results
        """
        import demistomock as demisto
        from CommonServerPython import set_feed_last_run
        mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.1.0"})
        set_last_run = mocker.patch.object(demisto, 'setLastRun', return_value={})
        set_integration_context = mocker.patch.object(demisto, 'setIntegrationContext', return_value={})
        set_feed_last_run({1: "first indicator"})
        set_integration_context.assert_called_with({1: "first indicator"})
        assert set_last_run.called is False


class TestIsDemistoServerGE:
    @classmethod
    @pytest.fixture(scope='function', autouse=True)
    def clear_cache(cls):
        get_demisto_version._version = None

    def test_get_demisto_version(self, mocker):
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

    def test_is_demisto_version_ge_4_5(self, mocker):
        get_version_patch = mocker.patch('CommonServerPython.get_demisto_version')
        get_version_patch.side_effect = AttributeError('simulate missing demistoVersion')
        assert not is_demisto_version_ge('5.0.0')
        assert not is_demisto_version_ge('6.0.0')
        with raises(AttributeError, match='simulate missing demistoVersion'):
            is_demisto_version_ge('4.5.0')

    def test_is_demisto_version_ge_dev_version(self, mocker):
        mocker.patch.object(
            demisto,
            'demistoVersion',
            return_value={
                'version': '6.0.0',
                'buildNumber': '50000'
            }
        )
        assert is_demisto_version_ge('6.0.0', '1-dev')

    @pytest.mark.parametrize('version, build', [
        ('6.0.0', '49999'),
        ('6.0.0', '50000'),
        ('6.0.0', '6'),  # Added with the fix of https://github.com/demisto/etc/issues/36876
        ('5.5.0', '50001')
    ])
    def test_is_demisto_version_build_ge(self, mocker, version, build):
        mocker.patch.object(
            demisto,
            'demistoVersion',
            return_value={
                'version': '6.0.0',
                'buildNumber': '50000'
            }
        )
        assert is_demisto_version_ge(version, build)

    @pytest.mark.parametrize('version, build', [
        ('6.0.0', '50001'),
        ('6.1.0', '49999')
    ])
    def test_is_demisto_version_build_ge_negative(self, mocker, version, build):
        mocker.patch.object(
            demisto,
            'demistoVersion',
            return_value={
                'version': '6.0.0',
                'buildNumber': '50000'
            }
        )
        assert not is_demisto_version_ge(version, build)


def test_smart_get_dict():
    d = {'t1': None, "t2": 1}
    # before we remove the dict will return null which is unexpected by a lot of users
    assert d.get('t1', 2) is None
    s = SmartGetDict(d)
    assert s.get('t1', 2) == 2
    assert s.get('t2') == 1
    assert s.get('t3') is None


class TestCustomIndicator:
    def test_custom_indicator_init_success(self):
        """
        Given: Data needed for creating a custom indicator
        When: Data is valid
        Then: Create a valid custom indicator
        """
        from CommonServerPython import Common, DBotScoreType
        dbot_score = Common.DBotScore(
            'test',
            DBotScoreType.CUSTOM,
            'VirusTotal',
            score=Common.DBotScore.BAD,
            malicious_description='malicious!'
        )
        indicator = Common.CustomIndicator('test', 'test_value', dbot_score, {'param': 'value'}, 'prefix')
        assert indicator.CONTEXT_PATH == 'prefix(val.value && val.value == obj.value)'
        assert indicator.param == 'value'
        assert indicator.value == 'test_value'

    def test_custom_indicator_init_existing_type(self):
        """
        Given: Data needed for creating a custom indicator
        When: Type already exists
        Then: raise a Value Error
        """
        with pytest.raises(ValueError):
            from CommonServerPython import Common, DBotScoreType
            dbot_score = Common.DBotScore(
                'test',
                DBotScoreType.CUSTOM,
                'VirusTotal',
                score=Common.DBotScore.BAD,
                malicious_description='malicious!'
            )
            Common.CustomIndicator('ip', 'test_value', dbot_score, {'param': 'value'}, 'prefix')

    def test_custom_indicator_init_no_prefix(self):
        """
        Given: Data needed for Custom indicator
        When: Prefix provided is None
        Then: Raise ValueError
        """
        with pytest.raises(ValueError):
            from CommonServerPython import Common, DBotScoreType
            dbot_score = Common.DBotScore(
                'test',
                DBotScoreType.CUSTOM,
                'VirusTotal',
                score=Common.DBotScore.BAD,
                malicious_description='malicious!'
            )
            Common.CustomIndicator('test', 'test_value', dbot_score, {'param': 'value'}, None)

    def test_custom_indicator_init_no_dbot_score(self):
        """
        Given: Data needed for Custom indicator
        When: Dbotscore is not a DBotScore object
        Then: Raise ValueError
        """
        with pytest.raises(ValueError):
            from CommonServerPython import Common
            dbot_score = ''
            Common.CustomIndicator('test', 'test_value', dbot_score, {'param': 'value'}, 'prefix')

    def test_custom_indicator_to_context(self):
        """
        Given: Data needed for Custom indicator
        When: there's a call to to_context
        Then: create a valid context
        """
        from CommonServerPython import Common, DBotScoreType
        dbot_score = Common.DBotScore(
            'test',
            DBotScoreType.CUSTOM,
            'VirusTotal',
            score=Common.DBotScore.BAD,
            malicious_description='malicious!'
        )
        indicator = Common.CustomIndicator('test', 'test_value', dbot_score, {'param': 'value'}, 'prefix')
        context = indicator.to_context()
        assert context['DBotScore(val.Indicator &&'
                       ' val.Indicator == obj.Indicator &&'
                       ' val.Vendor == obj.Vendor && val.Type == obj.Type)']['Indicator'] == 'test'
        assert context['prefix(val.value && val.value == obj.value)']['value'] == 'test_value'
        assert context['prefix(val.value && val.value == obj.value)']['param'] == 'value'

    def test_custom_indicator_no_params(self):
        """
        Given: Data needed for creating a custom indicator
        When: params are None
        Then: Raise an error
        """
        with pytest.raises(TypeError):
            from CommonServerPython import Common, DBotScoreType
            dbot_score = Common.DBotScore(
                'test',
                DBotScoreType.CUSTOM,
                'VirusTotal',
                score=Common.DBotScore.BAD,
                malicious_description='malicious!'
            )
            Common.CustomIndicator('test', 'test_value', dbot_score, None, 'prefix')

    def test_custom_indicator_no_value(self):
        """
        Given: Data needed for creating a custom indicator
        When: value is None
        Then: Raise an error
        """
        with pytest.raises(ValueError):
            from CommonServerPython import Common, DBotScoreType
            dbot_score = Common.DBotScore(
                'test',
                DBotScoreType.CUSTOM,
                'VirusTotal',
                score=Common.DBotScore.BAD,
                malicious_description='malicious!'
            )
            Common.CustomIndicator('test', None, dbot_score, {'param': 'value'}, 'prefix')


@pytest.mark.parametrize(
    "demistoUrls,expected_result",
    [({'server': 'https://localhost:8443:/acc_test_tenant'}, 'acc_test_tenant'),
     ({'server': 'https://localhost:8443'}, '')])
def test_get_tenant_name(mocker, demistoUrls, expected_result):
    """
        Given
        - demistoUrls dictionary
        When
        - Running on multi tenant mode
        - Running on single tenant mode
        Then
        - Return tenant account name if is multi tenant
    """
    from CommonServerPython import get_tenant_account_name
    mocker.patch.object(demisto, 'demistoUrls', return_value=demistoUrls)

    result = get_tenant_account_name()
    assert result == expected_result


IOCS = {'iocs': [{'id': '2323', 'value': 'google.com'},
                 {'id': '5942', 'value': '1.1.1.1'}]}


def test_indicators_value_to_clickable(mocker):
    from CommonServerPython import indicators_value_to_clickable
    from CommonServerPython import IndicatorsSearcher
    mocker.patch.object(IndicatorsSearcher, '__next__', side_effect=[IOCS, StopIteration])
    result = indicators_value_to_clickable(['1.1.1.1', 'google.com'])
    assert result.get('1.1.1.1') == '[1.1.1.1](#/indicator/5942)'
    assert result.get('google.com') == '[google.com](#/indicator/2323)'


def test_indicators_value_to_clickable_invalid(mocker):
    from CommonServerPython import indicators_value_to_clickable
    from CommonServerPython import IndicatorsSearcher
    mocker.patch.object(IndicatorsSearcher, '__next__', side_effect=[StopIteration])
    result = indicators_value_to_clickable(['8.8.8.8', 'abc.com'])
    assert not result
    result = indicators_value_to_clickable(None)
    assert not result


def test_arg_to_number():
    """
    Test if arg_to_number handles unicode object without failing.
    """
    from CommonServerPython import arg_to_number
    result = arg_to_number(u'1')
    assert result == 1


def test_get_message_threads_dump():
    from CommonServerPython import get_message_threads_dump
    result = str(get_message_threads_dump(None, None))
    assert ' Start Threads Dump ' in result
    assert ' End Threads Dump ' in result
    assert 'CommonServerPython.py' in result
    assert 'get_message_threads_dump' in result


def test_get_message_memory_dump():
    from CommonServerPython import get_message_memory_dump
    result = str(get_message_memory_dump(None, None))
    assert ' Start Variables Dump ' in result
    assert ' Start Local Vars ' in result
    assert ' End Local Vars ' in result
    assert ' Start Top ' in result
    assert ' Globals by Size ' in result
    assert ' End Top ' in result
    assert ' End Variables Dump ' in result


def test_shorten_string_for_printing():
    from CommonServerPython import shorten_string_for_printing
    assert shorten_string_for_printing(None, None) is None
    assert shorten_string_for_printing('1', 9) == '1'
    assert shorten_string_for_printing('123456789', 9) == '123456789'
    assert shorten_string_for_printing('1234567890', 9) == '123...890'
    assert shorten_string_for_printing('12345678901', 9) == '123...901'
    assert shorten_string_for_printing('123456789012', 9) == '123...012'

    assert shorten_string_for_printing('1234567890', 10) == '1234567890'
    assert shorten_string_for_printing('12345678901', 10) == '1234...901'
    assert shorten_string_for_printing('123456789012', 10) == '1234...012'


def test_get_size_of_object():
    from CommonServerPython import get_size_of_object

    class Object(object):
        pass

    level_3 = Object()
    level_3.key3 = 'val3'

    level_2 = Object()
    level_2.key2 = 'val2'
    level_2.child = level_3

    level_1 = Object()
    level_1.key1 = 'val1'
    level_1.child = level_2

    level_1_sys_size = sys.getsizeof(level_1)
    level_1_deep_size = get_size_of_object(level_1)

    # 3 levels, so shoulod be at least 3 times as large
    assert level_1_deep_size > 3 * level_1_sys_size


class TestSetAndGetLastMirrorRun:

    def test_get_last_mirror_run_in_6_6(self, mocker):
        """
        Given: 6.6.0 environment and getLastMirrorRun returns results
        When: Execute mirroring run
        Then: Returning demisto.getLastRun object
        """
        import demistomock as demisto
        from CommonServerPython import get_last_mirror_run
        mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.6.0"})
        mocker.patch.object(demisto, 'getLastMirrorRun', return_value={"lastMirrorRun": "2018-10-24T14:13:20+00:00"})
        result = get_last_mirror_run()
        assert result == {"lastMirrorRun": "2018-10-24T14:13:20+00:00"}

    def test_get_last_mirror_run_in_6_6_when_return_empty_results(self, mocker):
        """
        Given: 6.6.0 environment and getLastMirrorRun returns empty results
        When: Execute mirroring run
        Then: Returning demisto.getLastRun empty object
        """
        import demistomock as demisto
        from CommonServerPython import get_last_mirror_run
        mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.6.0"})
        mocker.patch.object(demisto, 'getLastMirrorRun', return_value={})
        result = get_last_mirror_run()
        assert result == {}

    def test_get_last_run_in_6_5(self, mocker):
        """
        Given: 6.5.0 environment and getLastMirrorRun returns results
        When: Execute mirroring run
        Then: Get a string which represent we can't use this function
        """
        import demistomock as demisto
        from CommonServerPython import get_last_mirror_run
        mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.5.0"})
        get_last_run = mocker.patch.object(demisto, 'getLastMirrorRun')
        with raises(DemistoException, match='You cannot use getLastMirrorRun as your version is below 6.6.0'):
            get_last_mirror_run()
            assert get_last_run.called is False

    def test_set_mirror_last_run_in_6_6(self, mocker):
        """
        Given: 6.6.0 environment
        When: Execute mirroring run
        Then: Using demisto.setLastMirrorRun to save results
        """
        import demistomock as demisto
        from CommonServerPython import set_last_mirror_run
        mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.6.0"})
        set_last_run = mocker.patch.object(demisto, 'setLastMirrorRun', return_value={})
        set_last_mirror_run({"lastMirrorRun": "2018-10-24T14:13:20+00:00"})
        set_last_run.assert_called_with({"lastMirrorRun": "2018-10-24T14:13:20+00:00"})

    def test_set_mirror_last_run_in_6_5(self, mocker):
        """
        Given: 6.5.0 environment
        When: Execute mirroring run
        Then: Don't use demisto.setLastMirrorRun
        """
        import demistomock as demisto
        from CommonServerPython import set_last_mirror_run
        mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.5.0"})
        set_last_run = mocker.patch.object(demisto, 'setLastMirrorRun', return_value={})
        with raises(DemistoException, match='You cannot use setLastMirrorRun as your version is below 6.6.0'):
            set_last_mirror_run({"lastMirrorRun": "2018-10-24T14:13:20+00:00"})
            assert set_last_run.called is False


class TestTracebackLineNumberAdgustment:
    @staticmethod
    def test_module_line_number_mapping():
        from CommonServerPython import _MODULES_LINE_MAPPING
        assert _MODULES_LINE_MAPPING['CommonServerPython']['start'] == 0

    @staticmethod
    def test_register_module_line_sanity():
        """
        Given:
            A module with a start and an end boundries.
        When:
            registering a module.
        Then:
            * module exists in the mapping with valid boundries.
        """
        import CommonServerPython
        CommonServerPython.register_module_line('Sanity', 'start', 5)
        CommonServerPython.register_module_line('Sanity', 'end', 50)
        assert CommonServerPython._MODULES_LINE_MAPPING['Sanity'] == {
            'start': 5,
            'start_wrapper': 5,
            'end': 50,
            'end_wrapper': 50,
        }

    @staticmethod
    def test_register_module_line_single_boundry():
        """
        Given:
            * A module with only an end boundry.
            * A module with only a start boundry.
        When:
            registering a module.
        Then:
            * both modules exists in the mapping.
            * the missing boundry is 0 for start and infinity for end.
        """
        import CommonServerPython
        CommonServerPython.register_module_line('NoStart', 'end', 4)
        CommonServerPython.register_module_line('NoEnd', 'start', 100)

        assert CommonServerPython._MODULES_LINE_MAPPING['NoStart'] == {
            'start': 0,
            'start_wrapper': 0,
            'end': 4,
            'end_wrapper': 4,
        }
        assert CommonServerPython._MODULES_LINE_MAPPING['NoEnd'] == {
            'start': 100,
            'start_wrapper': 100,
            'end': float('inf'),
            'end_wrapper': float('inf'),
        }

    @staticmethod
    def test_register_module_line_invalid_inputs():
        """
        Given:
            * invalid start_end flag.
            * invalid line number.
        When:
            registering a module.
        Then:
            function exits quietly
        """
        import CommonServerPython
        CommonServerPython.register_module_line('Cactus', 'statr', 5)
        CommonServerPython.register_module_line('Cactus', 'start', '5')
        CommonServerPython.register_module_line('Cactus', 'statr', -5)
        CommonServerPython.register_module_line('Cactus', 'statr', 0, -1)


    @staticmethod
    def test_fix_traceback_line_numbers():
        import CommonServerPython
        CommonServerPython._MODULES_LINE_MAPPING = {
            'CommonServerPython': {'start': 200, 'end': 865, 'end_wrapper': 900},
            'TestTracebackLines': {'start': 901, 'end': float('inf'), 'start_wrapper': 901},
            'TestingApiModule': {'start': 1004, 'end': 1032, 'start_wrapper': 1001, 'end_wrapper': 1033},
        }
        traceback = '''Traceback (most recent call last):
  File "<string>", line 1043, in <module>
  File "<string>", line 986, in main
  File "<string>", line 600, in func_wrapper
  File "<string>", line 1031, in api_module_call_script
  File "<string>", line 927, in call_func
Exception: WTF?!!!'''
        expected_traceback = '''Traceback (most recent call last):
  File "<TestTracebackLines>", line 110, in <module>
  File "<TestTracebackLines>", line 85, in main
  File "<CommonServerPython>", line 400, in func_wrapper
  File "<TestingApiModule>", line 27, in api_module_call_script
  File "<TestTracebackLines>", line 26, in call_func
Exception: WTF?!!!'''
        result = CommonServerPython.fix_traceback_line_numbers(traceback)
        assert result == expected_traceback

