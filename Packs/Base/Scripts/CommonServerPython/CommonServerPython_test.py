# -*- coding: utf-8 -*-
import copy
import gzip
import json
import os
import re
import sys
import urllib
import uuid
import warnings

import dateparser
from freezegun import freeze_time
import pytest
import pytz
import requests
from pytest import raises, mark

import CommonServerPython
import demistomock as demisto
from CommonServerPython import (find_and_remove_sensitive_text, xml2json, json2xml, entryTypes, formats, tableToMarkdown, underscoreToCamelCase,
                                flattenCell, date_to_timestamp, datetime, timedelta, camelize, pascalToSpace, argToList,
                                remove_nulls_from_dictionary, is_error, get_error, hash_djb2, fileResult, is_ip_valid,
                                get_demisto_version, IntegrationLogger, parse_date_string, IS_PY3, PY_VER_MINOR, DebugLogger,
                                b64_encode, parse_date_range, return_outputs, is_filename_valid, convert_dict_values_bytes_to_str,
                                argToBoolean, ipv4Regex, ipv4cidrRegex, ipv6cidrRegex, urlRegex, ipv6Regex, domainRegex, batch,
                                FeedIndicatorType, encode_string_results, safe_load_json, remove_empty_elements,
                                aws_table_to_markdown, is_demisto_version_ge, appendContext, auto_detect_indicator_type,
                                handle_proxy, get_demisto_version_as_str, get_x_content_info_headers, url_to_clickable_markdown,
                                WarningsHandler, DemistoException, SmartGetDict, JsonTransformer, remove_duplicates_from_list_arg,
                                DBotScoreType, DBotScoreReliability, Common, send_events_to_xsiam, ExecutionMetrics,
                                response_to_context, is_integration_command_execution, is_xsiam_or_xsoar_saas, is_xsoar,
                                is_xsoar_on_prem, is_xsoar_hosted, is_xsoar_saas, is_xsiam, send_data_to_xsiam,
                                censor_request_logs, censor_request_logs, safe_sleep, get_server_config, b64_decode,
                                get_engine_base_url, is_integration_instance_running_on_engine
                                )

EVENTS_LOG_ERROR = \
    """Error sending new events into XSIAM.
Parameters used:
\tURL: https://api-url
\tHeaders: {{
        "authorization": "TOKEN",
        "format": "json",
        "product": "some product",
        "vendor": "some vendor",
        "content-encoding": "gzip",
        "collector-name": "test_brand",
        "instance-name": "test_integration_instance",
        "final-reporting-device": "www.test_url.com",
        "collector-type": "events"
}}

Response status code: {status_code}
Error received:
\t{error_received}"""

ASSETS_LOG_ERROR = \
    """Error sending new assets into XSIAM.
Parameters used:
\tURL: https://api-url
\tHeaders: {{
        "authorization": "TOKEN",
        "format": "json",
        "product": "some product",
        "vendor": "some vendor",
        "content-encoding": "gzip",
        "collector-name": "test_brand",
        "instance-name": "test_integration_instance",
        "final-reporting-device": "www.test_url.com",
        "collector-type": "assets",
        "snapshot-id": "123000test_integration_instance",
        "total-items-count": "2"
}}

Response status code: {status_code}
Error received:
\t{error_received}"""

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

    # Test fails locally because expected time is in UTC
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
        name_transformer = JsonTransformer(keys=['first', 'second'], is_nested=False)
        json_transformer_mapping = {'name': name_transformer}
        table = tableToMarkdown("tableToMarkdown test", simple_data_example,
                                json_transform_mapping=json_transformer_mapping)
        if IS_PY3:
            expected_table = """### tableToMarkdown test
|name|value|
|---|---|
| **first**:<br>	***a***: val<br>***second***: b | val1 |
| **first**:<br>	***a***: val2<br>***second***: d | val2 |
"""
        else:
            expected_table = u"""### tableToMarkdown test
|name|value|
|---|---|
| ***second***: b<br>**first**:<br>	***a***: val | val1 |
| ***second***: d<br>**first**:<br>	***a***: val2 | val2 |
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
| Active Directory Query | **1.0.4**:<br>	**path**:<br>		**a**:<br>			**b**:<br>				***c***: we should see this value<br>	***releaseNotes***: <br>#### Integrations<br>##### Active Directory Query v2<br>Fixed an issue where the ***ad-get-user*** command caused performance issues because the *limit* argument was not defined.<br><br>**1.0.5**:<br>	**path**:<br>		**a**:<br>			**b**:<br>				***c***: we should see this value<br>	***releaseNotes***: <br>#### Integrations<br>##### Active Directory Query v2<br>- Fixed several typos.<br>- Updated the Docker image to: *demisto/ldap:1.0.0.11282*.<br><br>**1.0.6**:<br>	**path**:<br>		**a**:<br>			**b**:<br>				***c***: we should see this value<br>	***releaseNotes***: <br>#### Integrations<br>##### Active Directory Query v2<br>- Fixed an issue where the DN parameter within query in the ***search-computer*** command was incorrect.<br>- Updated the Docker image to *demisto/ldap:1.0.0.12410*.<br> |
"""
        assert expected_table == table

    @staticmethod
    def test_with_json_transformer_func():
        """
        Given:
          - Double nested json table.
        When:
          - Calling tableToMarkdown with JsonTransformer set to custom function.
        Then:
          - The table constructed with the transforming function.
        """

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

    @staticmethod
    def test_with_json_transform_list():
        """
        Given:
          - Nested json table with a list.
        When:
          - Calling tableToMarkdown with `is_auto_json_transform=True`.
        Then:
          - Create a markdown table with the list
        """
        with open('test_data/nested_data_in_list.json') as f:
            data_with_list = json.load(f)
        table = tableToMarkdown("tableToMarkdown test", data_with_list, is_auto_json_transform=True)
        if IS_PY3:
            expected_table = """### tableToMarkdown test
|Commands|Creation time|Hostname|Machine Action Id|MachineId|Status|
|---|---|---|---|---|---|
| **-**	***startTime***: null<br>	***endTime***: 2022-02-17T08:22:33.823Z<br>	***commandStatus***: Completed<br>	**errors**:<br>		***values***: error1, error2, error3<br>	**command**:<br>		***type***: GetFile<br>		**params**:<br>			**-**	***key***: Path<br>				***value***: test.txt<br>**-**	***startTime***: null<br>	***endTime***: 2022-02-17T08:22:33.823Z<br>	***commandStatus***: Completed<br>	**errors**:<br>		***values***: <br>	**command**:<br>		***type***: GetFile<br>		**params**:<br>			**-**	***key***: Path<br>				***value***: test222.txt | 2022-02-17T08:20:02.6180466Z | desktop-s2455r9 | 5b38733b-ed80-47be-b892-f2ffb52593fd | f70f9fe6b29cd9511652434919c6530618f06606 | Succeeded |
"""
        else:
            expected_table = u"""### tableToMarkdown test
|Commands|Creation time|Hostname|Machine Action Id|MachineId|Status|
|---|---|---|---|---|---|
| **-**	**command**:<br>		**params**:<br>			**-**	***value***: test.txt<br>				***key***: Path<br>		***type***: GetFile<br>	***endTime***: 2022-02-17T08:22:33.823Z<br>	***commandStatus***: Completed<br>	**errors**:<br>		***values***: error1, error2, error3<br>	***startTime***: null<br>**-**	**command**:<br>		**params**:<br>			**-**	***value***: test222.txt<br>				***key***: Path<br>		***type***: GetFile<br>	***endTime***: 2022-02-17T08:22:33.823Z<br>	***commandStatus***: Completed<br>	**errors**:<br>		***values***: <br>	***startTime***: null | 2022-02-17T08:20:02.6180466Z | desktop-s2455r9 | 5b38733b-ed80-47be-b892-f2ffb52593fd | f70f9fe6b29cd9511652434919c6530618f06606 | Succeeded |
"""
        assert expected_table == table

    @staticmethod
    def test_with_json_transform_list_keys():
        """
        Given:
          - Nested json table with a list.
        When:
          - Calling tableToMarkdown with `is_auto_json_transform=True`.
        Then:
          - Create a markdown table with the list only with given keys
        """
        with open('test_data/nested_data_in_list.json') as f:
            data_with_list = json.load(f)
        table = tableToMarkdown("tableToMarkdown test", data_with_list,
                                json_transform_mapping={'Commands': JsonTransformer(keys=('commandStatus', 'command'))})
        if IS_PY3:
            expected_table = """### tableToMarkdown test
|Commands|Creation time|Hostname|Machine Action Id|MachineId|Status|
|---|---|---|---|---|---|
| **-**	***commandStatus***: Completed<br>	**command**:<br>		***type***: GetFile<br>		**params**:<br>			**-**	***key***: Path<br>				***value***: test.txt<br>**-**	***commandStatus***: Completed<br>	**command**:<br>		***type***: GetFile<br>		**params**:<br>			**-**	***key***: Path<br>				***value***: test222.txt | 2022-02-17T08:20:02.6180466Z | desktop-s2455r9 | 5b38733b-ed80-47be-b892-f2ffb52593fd | f70f9fe6b29cd9511652434919c6530618f06606 | Succeeded |
"""
        else:
            expected_table = u"""### tableToMarkdown test
|Commands|Creation time|Hostname|Machine Action Id|MachineId|Status|
|---|---|---|---|---|---|
| **-**	**command**:<br>		**params**:<br>			**-**	***value***: test.txt<br>				***key***: Path<br>		***type***: GetFile<br>	***commandStatus***: Completed<br>**-**	**command**:<br>		**params**:<br>			**-**	***value***: test222.txt<br>				***key***: Path<br>		***type***: GetFile<br>	***commandStatus***: Completed | 2022-02-17T08:20:02.6180466Z | desktop-s2455r9 | 5b38733b-ed80-47be-b892-f2ffb52593fd | f70f9fe6b29cd9511652434919c6530618f06606 | Succeeded |
"""
        assert expected_table == table

    @staticmethod
    def test_no_given_headers_and_sort_headers():
        """
        Given:
            - A list of dictionaries.
        When:
            - Calling tableToMarkdown with no given headers and sort_headers=True by default.
        Then:
            - Validate that the table is sorted by the keys.
        """
        data = [{'c': 1, 'b': 2, 'a': 3}, {'c': 4, 'b': 5, 'a': 6}]
        table = tableToMarkdown("tableToMarkdown test", data)
        assert table == ('### tableToMarkdown test\n'
                         '|a|b|c|\n|---|---|---|\n'
                         '| 3 | 2 | 1 |\n'
                         '| 6 | 5 | 4 |\n')

    @staticmethod
    def test_no_given_headers_and_sort_headers_false():
        """
        Given:
            - A list of dictionaries.
        When:
            - Calling tableToMarkdown with no given headers and sort_headers=False.
        Then:
            - Python 3: Validate that the table is not sorted by the keys.
            - Python 2: Validate that the table is sorted by the keys.
        """
        data = [{'c': 1, 'b': 2, 'a': 3}, {'c': 4, 'b': 5, 'a': 6}]
        table = tableToMarkdown("tableToMarkdown test", data, sort_headers=False)

        if IS_PY3:
            expected_table_unsorted = ('### tableToMarkdown test\n'
                                       '|c|b|a|\n|---|---|---|\n'
                                       '| 1 | 2 | 3 |\n'
                                       '| 4 | 5 | 6 |\n')
            assert table == expected_table_unsorted
        else:  # in python 2 sort_headers=False is not working
            expected_table_sorted = ('### tableToMarkdown test\n'
                                     '|a|b|c|\n|---|---|---|\n'
                                     '| 3 | 2 | 1 |\n'
                                     '| 6 | 5 | 4 |\n')
            assert table == expected_table_sorted


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

    # datetime test
    datetime_value = datetime(2019, 9, 17, 6, 16, 39)
    dict_to_flatten = {'date': datetime_value}
    expected_flatten_dict = '{\n    "date": "2019-09-17 06:16:39"\n}'
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


def test_argToList(mocker):
    expected = ['a', 'b', 'c']
    test1 = ['a', 'b', 'c']
    test2 = 'a,b,c'
    test3 = '["a","b","c"]'
    test4 = 'a;b;c'
    test5 = 1
    test6 = '1'
    test7 = True
    test8 = [1, 2, 3]
    test9 = "[test.com]"

    results = [argToList(test1), argToList(test2), argToList(test2, ','), argToList(test3), argToList(test4, ';')]

    for result in results:
        assert expected == result, 'argToList test failed, {} is not equal to {}'.format(str(result), str(expected))
    mocker.patch.object(demisto, 'debug', return_value=None)
    assert argToList(test5) == [1]
    assert argToList(test5, transform=str) == ['1']
    assert argToList(test6) == ['1']
    assert argToList(test7) == [True]
    assert argToList(test8, transform=str) == ['1', '2', '3']
    assert argToList(test9) == ["[test.com]"]


@pytest.mark.parametrize('args, field, expected_output', [
    ({'ids': "1,2,3"}, 'ids', ["1", "2", "3"]),
    ({'ids': "1,2,1"}, 'ids', ["1", "2"]),
    ({'ids': ""}, 'ids', []),
    ({'ids': ""}, 'name', []),
])
def test_remove_duplicates_from_list_arg(args, field, expected_output):
    assert len(remove_duplicates_from_list_arg(args, field)) == len(expected_output)


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


@mark.parametrize('data,data_expected,filename', [
    ("this is a test", b"this is a test", "test.txt"),
    ("this is a test", b"this is a test", "../../../test.txt"),
    (u"עברית", u"עברית".encode('utf-8'), "test.txt"),
    (b"binary data\x15\x00", b"binary data\x15\x00", "test.txt"),
])  # noqa: E124
def test_fileResult(mocker, request, data, data_expected, filename):
    file_id = str(uuid.uuid4())
    mocker.patch.object(demisto, 'uniqueFile', return_value="fileresult")
    mocker.patch.object(demisto, 'investigation', return_value={'id': file_id})
    file_name = "{}_fileresult".format(file_id)

    def cleanup():
        try:
            os.remove(file_name)
        except OSError:
            pass

    request.addfinalizer(cleanup)
    res = fileResult(filename, data)
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


def test_add_sensitive_log_strs(mocker):
    """
    Given:
       - Debug mode command
    When
       - Adding sensitive strings to the log
    Then
       - Ensure that both LOG and _requests_logger mask the sensitive str
    """
    sensitive_str = '%%This_is_API_key%%'
    from CommonServerPython import add_sensitive_log_strs, LOG
    mocker.patch('CommonServerPython._requests_logger', DebugLogger())
    CommonServerPython._requests_logger.log_start_debug()
    add_sensitive_log_strs(sensitive_str)
    assert sensitive_str not in LOG(sensitive_str)
    assert sensitive_str not in CommonServerPython._requests_logger.int_logger(sensitive_str)


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


def test_return_error_truncated_message(mocker):
    """
    Given
    - invalid error message due to longer than max length (50,000)

    When
    - return_error function is called

    Then
    - Return a truncated message that contains clarification about the truncation
    """
    from CommonServerPython import return_error, MAX_ERROR_MESSAGE_LENGTH
    err_msg = "1" * (MAX_ERROR_MESSAGE_LENGTH + 1)
    results = mocker.spy(demisto, 'results')
    mocker.patch.object(sys, 'exit')
    return_error(err_msg)
    assert len(results.call_args[0][0]["Contents"]) == MAX_ERROR_MESSAGE_LENGTH + \
        len("...This error body was truncated...")
    assert "This error body was truncated" in results.call_args[0][0]["Contents"]


def test_return_error_valid_message(mocker):
    """
    Given
    - A valid error message

    When
    - return_error function is called

    Then
    - Ensure the same message is returned
    - Ensure the error message does not contain clarification about a truncation
    """
    from CommonServerPython import return_error, MAX_ERROR_MESSAGE_LENGTH
    err_msg = "1" * int(MAX_ERROR_MESSAGE_LENGTH * 0.9)
    results = mocker.spy(demisto, 'results')
    mocker.patch.object(sys, 'exit')
    return_error(err_msg)
    assert len(results.call_args[0][0]["Contents"]) == len(err_msg)
    assert "This error body was truncated" not in results.call_args[0][0]["Contents"]


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
    @pytest.mark.parametrize('outputs, prefix', [([], None), ([], ''), ({}, '.')])
    def test_outputs_without_outputs_prefix(self, outputs, prefix):
        """
        Given
        - outputs as a list without output_prefix, or with a period output prefix.

        When
        - Returns results.

        Then
        - Validate a ValueError is raised.
        """
        from CommonServerPython import CommandResults
        with pytest.raises(ValueError, match='outputs_prefix'):
            CommandResults(outputs=outputs, outputs_prefix=prefix)

    def test_with_tags(self):
        from CommonServerPython import CommandResults
        command_results = CommandResults(tags=['tag1', 'tag2'])
        assert command_results.tags == ['tag1', 'tag2']
        assert command_results.to_context()['Tags'] == ['tag1', 'tag2']

    @pytest.mark.parametrize('output', [True, False])
    def test_with_boolean_output(self, output):
        from CommonServerPython import CommandResults
        command_results = CommandResults(
            outputs=output,
            outputs_prefix="BooleanOutput",
            readable_output="Boolean Output: {}".format(output),
        )
        assert command_results.to_context()['Contents'] == output

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
        - url indicator

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

    def test_hashes_array_is_in_to_context_file(self):
        """
        Given
        - A File indicator.

        When
        - Creating a reputation with all existing hashes.

        Then
        - Verify that the hashes array exists in the entry context and includes all the hashes types and values.
        """
        from CommonServerPython import Common, DBotScoreType, CommandResults
        indicator_id = '63347f5d946164a23faca26b78a91e1c'
        raw_response = {'id': indicator_id}
        indicator = Common.File(
            md5=indicator_id,
            sha1='test_sha1',
            sha256='test_sha256',
            sha512='test_sha512',
            ssdeep='test_ssdeep',
            imphash='test_imphash',
            hashes=[Common.Hash('test_type1', 'test_value1'), Common.Hash('test_type2', 'test_value2')],
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

        expected_hashes_array = [
            {'type': 'test_type1', 'value': 'test_value1'},
            {'type': 'test_type2', 'value': 'test_value2'},
            {'type': 'MD5', 'value': '63347f5d946164a23faca26b78a91e1c'},
            {'type': 'SHA1', 'value': 'test_sha1'},
            {'type': 'SHA256', 'value': 'test_sha256'},
            {'type': 'SHA512', 'value': 'test_sha512'},
            {'type': 'SSDeep', 'value': 'test_ssdeep'},
            {'type': 'Imphash', 'value': 'test_imphash'}
        ]

        assert entry_context[Common.File.CONTEXT_PATH][0].get('Hashes') == expected_hashes_array

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
            score=Common.DBotScore.GOOD,
            message='test comment'
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
                        'Type': 'ip',
                        'Message': 'test comment'
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

    def test_empty_readable_outputs(self):
        """
        Given:
        - Outputs as str
        - outputs_prefix is str
        - No readable_output

        When:
        - Returning results

        Then:
        - Validate generated readable_output

        """
        from CommonServerPython import CommandResults
        res = CommandResults(
            outputs="outputs_test",
            outputs_prefix="outputs_prefix_test"
        )
        context = res.to_context()
        assert "outputs_test" == context.get('HumanReadable')

    def test_replace_existing(self):
        """
        Given:
        - replace_existing=True

        When:
        - Returning an object to context that needs to override it's key on each run.

        Then:
        - Return an object with the DT "(true)"
        """
        from CommonServerPython import CommandResults
        res = CommandResults(
            outputs="next_token",
            outputs_prefix="Path.To.Value",
            replace_existing=True
        )
        context = res.to_context()
        assert context["EntryContext"] == {"Path.To(true)": {"Value": "next_token"}}

    def test_replace_existing_not_nested(self):
        """
        Given:
        - replace_existing=True but outputs_prefix is not nested, i.e., does not have a period.

        When:
        - Returning an object to context that needs to override it's key on each run.

        Then:
        - Raise an errror.
        """
        from CommonServerPython import CommandResults
        res = CommandResults(
            outputs="next_token",
            outputs_prefix="PathToValue",
            replace_existing=True
        )
        with pytest.raises(DemistoException, match='outputs_prefix must be a nested path to replace an existing key.'):
            res.to_context()


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

    def test_http_request_connection_error_with_errno(self, requests_mock):
        from CommonServerPython import DemistoException
        err = requests.exceptions.ConnectionError()
        err.errno = 104
        err.strerror = "Connection reset by peer test"
        requests_mock.get('http://example.com/api/v2/event', exc=err)
        with raises(DemistoException, match="Error Number: \[104\]\\nMessage: Connection reset by peer test"):
            self.client._http_request('get', 'event', resp_type='response')

    def test_http_request_connection_error_without_errno(self, requests_mock):
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event', exc=requests.exceptions.ConnectionError("Generic error"))
        with raises(DemistoException, match="Generic error"):
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

    def test_http_request_params_parser_none(self, requests_mock):
        """
            Given
                - query params with spaces without specific quote function.

            When
                - Calling _https_request function.

            Then
                - Verify the spaces in the result is as expected.
        """
        mock_request = requests_mock.get('http://example.com/api/v2/', json={})
        from CommonServerPython import BaseClient
        mock_client = BaseClient('http://example.com/api/v2/')

        mock_client._http_request('get', params={'key': 'value with spaces'})

        assert mock_request.last_request.query == 'key=value+with+spaces'

    def test_http_request_execution_metrics_success(cls, requests_mock):
        """
        Given: A BaseClient object
        When:
        - Calling _http_request function with metrics
        - A successful response.
        Then: Verify the successful execution metrics is incremented.
        """
        requests_mock.get('http://example.com/api/v2/event', text="success")
        client = cls.BaseClient('http://example.com/api/v2/', ok_codes=(200, 201), verify=False)
        client._http_request('get', 'event', resp_type='response', with_metrics=True)
        assert client.execution_metrics.success == 1

    def test_http_request_execution_metrics_success_but_polling_in_progress(cls, requests_mock):
        """
        Given: A BaseClient object
        When:
        - Calling _http_request function with metrics
        - A successful response.
        - Response is determined as polling in progress.
        Then: Verify the successful execution metrics is not incremented.
        """
        requests_mock.get('http://example.com/api/v2/event', text="success")
        client = cls.BaseClient('http://example.com/api/v2/', ok_codes=(200, 201), verify=False)
        client.is_polling_in_progress = lambda _: True
        client._http_request('get', 'event', resp_type='response', with_metrics=True)
        assert client.execution_metrics.success == 0

    def test_http_request_execution_metrics_timeout(cls, requests_mock):
        """
        Given: A BaseClient object
        When:
        - Calling _http_request function with metrics
        - A timeout error is returned.
        Then: Verify the timeout error execution metrics is incremented.
        """
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event', exc=requests.exceptions.ConnectTimeout)
        client = cls.BaseClient('http://example.com/api/v2/', ok_codes=(200, 201), verify=False)
        with raises(DemistoException):
            client._http_request('get', 'event', resp_type='response', with_metrics=True)
        assert client.execution_metrics.timeout_error == 1

    def test_http_request_execution_metrics_ssl_error(cls, requests_mock):
        """
        Given: A BaseClient object
        When:
        - Calling _http_request function with metrics
        - An SSL error is returned.
        Then: Verify the ssl error execution metrics is incremented.
        """
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event', exc=requests.exceptions.SSLError)
        client = cls.BaseClient('http://example.com/api/v2/', ok_codes=(200, 201))
        with raises(DemistoException):
            client._http_request('get', 'event', resp_type='response', with_metrics=True)
        assert client.execution_metrics.ssl_error == 1

    def test_http_request_execution_metrics_proxy_error(cls, requests_mock):
        """
        Given: A BaseClient object
        When:
        - Calling _http_request function with metrics
        - A proxy error is returned.
        Then: Verify the proxy error execution metrics is incremented.
        """
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event', exc=requests.exceptions.ProxyError)
        client = cls.BaseClient('http://example.com/api/v2/', ok_codes=(200, 201), verify=False)
        with raises(DemistoException):
            client._http_request('get', 'event', resp_type='response', with_metrics=True)
        assert client.execution_metrics.proxy_error == 1

    def test_http_request_execution_metrics_connection_error(cls, requests_mock):
        """
        Given: A BaseClient object
        When:
        - Calling _http_request function with metrics
        - A connection error is returned.
        Then: Verify the connection error execution metrics is incremented.
        """
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event', exc=requests.exceptions.ConnectionError)
        client = cls.BaseClient('http://example.com/api/v2/', ok_codes=(200, 201), verify=False)
        with raises(DemistoException):
            client._http_request('get', 'event', resp_type='response', with_metrics=True)
        assert client.execution_metrics.connection_error == 1

    def test_http_request_execution_metrics_retry_error(cls, requests_mock):
        """
        Given: A BaseClient object
        When:
        - Calling _http_request function with metrics
        - A retry error is returned.
        Then: Verify the retry error execution metrics is incremented.
        """
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event', exc=requests.exceptions.RetryError)
        client = cls.BaseClient('http://example.com/api/v2/', ok_codes=(200, 201), verify=False)
        with raises(DemistoException):
            client._http_request('get', 'event', resp_type='response', with_metrics=True)
        assert client.execution_metrics.retry_error == 1

    def test_http_request_execution_metrics_auth_error(cls, requests_mock):
        """
        Given: A BaseClient object
        When:
        - Calling _http_request function with metrics
        - An auth error (401 status code) is returned.
        Then: Verify the auth error execution metrics is incremented.
        """
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event', status_code=401, text="err")
        client = cls.BaseClient('http://example.com/api/v2/', ok_codes=(200, 201), verify=False)
        with raises(DemistoException, match="Error in API call"):
            client._http_request('get', 'event', with_metrics=True)
        assert client.execution_metrics.auth_error == 1

    def test_http_request_execution_metrics_quota_error(cls, requests_mock):
        """
        Given: A BaseClient object
        When:
        - Calling _http_request function with metrics
        - A quota error (429 status code) is returned.
        Then: Verify the quota error execution metrics is incremented.
        """
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event', status_code=429, text="err")
        client = cls.BaseClient('http://example.com/api/v2/', ok_codes=(200, 201), verify=False)
        with raises(DemistoException, match="Error in API call"):
            client._http_request('get', 'event', with_metrics=True)
        assert client.execution_metrics.quota_error == 1

    def test_http_request_execution_metrics_service_error(cls, requests_mock):
        """
        Given: A BaseClient object
        When:
        - Calling _http_request function with metrics
        - A service error (500 status code) is returned.
        Then: Verify the service error execution metrics is incremented.
        """
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event', status_code=500, text="err")
        client = cls.BaseClient('http://example.com/api/v2/', ok_codes=(200, 201), verify=False)
        with raises(DemistoException, match="Error in API call"):
            client._http_request('get', 'event', with_metrics=True)
        assert client.execution_metrics.service_error == 1

    def test_http_request_execution_metrics_general_error(cls, requests_mock):
        """
        Given: A BaseClient object
        When:
        - Calling _http_request function with metrics
        - A general error (400 status code) is returned.
        Then: Verify the general error execution metrics is incremented.
        """
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event', status_code=400, text="err")
        client = cls.BaseClient('http://example.com/api/v2/', ok_codes=(200, 201), verify=False)
        with raises(DemistoException, match="Error in API call"):
            client._http_request('get', 'event', with_metrics=True)
        assert client.execution_metrics.general_error == 1

    def test_http_request_execution_metrics_not_found_error_but_ok(cls, requests_mock):
        """
        Given: A BaseClient object
        When:
        - Calling _http_request function with metrics
        - A not found error (404 status code) is returned.
        - 404 is considered ok
        Then: Verify the success execution metrics is incremented, and not the general error metrics.
        """
        requests_mock.get('http://example.com/api/v2/event', status_code=404, text="err")
        client = cls.BaseClient('http://example.com/api/v2/', ok_codes=(200, 201, 404), verify=False)
        res = client._http_request('get', 'event', resp_type='response', with_metrics=True)
        assert res.status_code == 404
        assert client.execution_metrics.success == 1
        assert client.execution_metrics.general_error == 0

    def test_http_request_execution_metrics_results(cls, requests_mock, mocker):
        """
        Given: A BaseClient object
        When:
        - Calling _http_request function with metrics
        - An general error is returned
        - The client object is then deleted
        Then: Verify an execution metrics entry is sent to demisto.results() accordingly.
        """
        from CommonServerPython import DemistoException, EntryType, ErrorTypes
        requests_mock.get('http://example.com/api/v2/event', status_code=400, text="err")
        demisto_results_mock = mocker.patch.object(demisto, 'results')
        client = cls.BaseClient('http://example.com/api/v2/', ok_codes=(200, 201), verify=False)
        with raises(DemistoException, match="Error in API call"):
            client._http_request('get', 'event', with_metrics=True)
        del client
        demisto_results_mock.assert_called_once
        entry = demisto_results_mock.call_args[0][0]
        assert entry["Type"] == EntryType.EXECUTION_METRICS
        assert entry["APIExecutionMetrics"] == [{
            "Type": ErrorTypes.GENERAL_ERROR,
            "APICallsCount": 1,
        }]

    def test_http_request_no_execution_metrics_results(cls, requests_mock, mocker):
        """
        Given: A BaseClient object
        When:
        - Calling _http_request function without metrics
        - An general error is returned
        - The client object is then deleted
        Then: Verify demisto.results() is not called.
        """
        from CommonServerPython import DemistoException
        requests_mock.get('http://example.com/api/v2/event', status_code=400, text="err")
        demisto_results_mock = mocker.patch.object(demisto, 'results')
        client = cls.BaseClient('http://example.com/api/v2/', ok_codes=(200, 201), verify=False)
        with raises(DemistoException, match="Error in API call"):
            client._http_request('get', 'event')
        del client
        demisto_results_mock.assert_not_called

    def test_base_client_subclass_without_execution_metrics_initialized(self):
        """
        Given: A BaseClient object and a subclass of it that does not initialize execution_metrics
        When: deleting the client object
        Then: Ensure the deletion does not raise any exception
        """
        from CommonServerPython import BaseClient

        class Client(BaseClient):
            def __init__(self):
                pass

        client = Client()
        del client

    @pytest.mark.skipif(not IS_PY3, reason='test not supported in py2')
    def test_http_request_params_parser_quote(self, requests_mock):
        """
            Given
                - query params with spaces with specific quote function.

            When
                - Calling _https_request function.

            Then
                - Verify the spaces in the result is as expected.
        """
        mock_request = requests_mock.get('http://example.com/api/v2/', json={})
        from CommonServerPython import BaseClient
        mock_client = BaseClient('http://example.com/api/v2/')

        mock_client._http_request('get', params={'key': 'value with spaces'}, params_parser=urllib.parse.quote)

        assert mock_request.last_request.query == 'key=value%20with%20spaces'


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
    @freeze_time("2024-01-15 17:00:00 UTC")
    def test_utc_time_sanity():
        utc_now = datetime.utcnow()
        utc_start_time, utc_end_time = parse_date_range('2 days', utc=True)
        # testing UTC date time and range of 2 days
        assert utc_now.replace(microsecond=0) == utc_end_time.replace(microsecond=0)
        assert abs(utc_start_time - utc_end_time).days == 2

    @staticmethod
    @freeze_time("2024-01-15 17:00:00 UTC")
    def test_local_time_sanity():
        local_now = datetime.now()
        local_start_time, local_end_time = parse_date_range('73 minutes', utc=False)
        # testing local datetime and range of 73 minutes
        assert local_now.replace(microsecond=0) == local_end_time.replace(microsecond=0)
        assert abs(local_start_time - local_end_time).seconds / 60 == 73

    @staticmethod
    @freeze_time("2024-01-15 17:00:00 UTC")
    def test_with_trailing_spaces():
        utc_now = datetime.utcnow()
        utc_start_time, utc_end_time = parse_date_range('2 days   ', utc=True)
        # testing UTC date time and range of 2 days
        assert utc_now.replace(microsecond=0) == utc_end_time.replace(microsecond=0)
        assert abs(utc_start_time - utc_end_time).days == 2

    @staticmethod
    @freeze_time("2022-11-03 13:40:00 UTC")
    def test_case_insensitive():
        utc_now = datetime.utcnow()
        utc_start_time, utc_end_time = parse_date_range('2 Days', utc=True)
        # testing UTC date time and range of 2 days
        assert utc_now.replace(microsecond=0) == utc_end_time.replace(microsecond=0)
        assert abs(utc_start_time - utc_end_time).days == 2

    @staticmethod
    @freeze_time("2024-01-15 17:00:00 UTC")
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
    @freeze_time("2024-01-15 17:00:00 UTC")
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
    @freeze_time("2024-01-15 17:00:00 UTC")
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
    @freeze_time("2024-01-15 17:00:00 UTC")
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
    (ipv4Regex, '192.168.1.1:8080', True),
    (ipv4Regex, '192.168.1.1/24', False),
    (ipv4Regex, '192.168.a.1', False),
    (ipv4Regex, '192.168..1.1', False),
    (ipv4Regex, '192.256.1.1', False),
    (ipv4Regex, '192.256.1.1.1', False),
    (ipv4Regex, '192.168.1.1/12', False),
    (ipv4Regex, '', False),
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
    ('192.168.1.1:8080', FeedIndicatorType.IP),
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


B64_STR = 'This is a test!'
DECODED_B64 = b'N\x18\xac\x8a\xc6\xadz\xcb'
CASE_NO_PADDING = (B64_STR, DECODED_B64)
CASE_LESS_PADDING = (B64_STR + '=', DECODED_B64)
CASE_WITH_PADDING = (B64_STR + '==', DECODED_B64)
CASE_TOO_MUCH_PADDING = (B64_STR + '===', DECODED_B64)


@pytest.mark.parametrize('str_to_decode, expected_encoded',
                         (CASE_NO_PADDING, CASE_WITH_PADDING, CASE_LESS_PADDING, CASE_TOO_MUCH_PADDING))
def test_b64_decode(str_to_decode, expected_encoded):
    """
    Given: A base 64 encoded str that represents an image, with different paddings.
    When: Decoding it to an image file.
    Then: The str is decoded to binary.
    """
    encoded = b64_decode(str_to_decode)
    assert encoded == expected_encoded


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
UPDATED_CONTEXT_WITH_LIST = {
    'dict_key': [{
        'key1': 'val1',
        'key2': 'val2',
        'key3': 'val3'
    }],
    'int_key': [1, 2],
    'list_key_str': ['val1', 'val2', 'str_data'],
    'list_key_list': ['val1', 'val2', 'val1', 'val2'],
    'list_key_dict': ['val1', 'val2', {'data_key': 'data_val'}]
}

DATA_MOCK_STRING = "str_data"
DATA_MOCK_LIST = ['val1', 'val2']
DATA_MOCK_LIST_OF_DICT = [{'key3': 'val3'}]
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
    (CONTEXT_MOCK, DATA_MOCK_LIST_OF_DICT, DICT_KEY, "key = {}, val = {}".format(DICT_KEY, UPDATED_CONTEXT_WITH_LIST[DICT_KEY])),
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
    ('test@Demisto.com', 'Email'),
    ('Test@demisto.com', 'Email'),
    ('TEST@demisto.com', 'Email'),
    ('TEST@Demisto.com', 'Email'),
    ('TEST@DEMISTO.Com', 'Email'),
    ('TesT@DEMISTO.Com', 'Email'),
    ('TesT@DemisTO.Com', 'Email'),
    ('TesT@DeMisTo.CoM', 'Email'),
    ('TEST@DEMISTO.COM', 'Email'),
    ('e775eb1250137c0b83d4e7c4549c71d6f10cae4e708ebf0b5c4613cbd1e91087', 'File'),
    ('test@yahoo.com', 'Email'),
    ('http://test.com', 'URL'),
    ('11.111.11.11/11', 'CIDR'),
    ('CVE-0000-0000', 'CVE'),
    ('dbot@demisto.works', 'Email'),
    ('dummy@recipient.com', 'Email'),
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
        'File'),
    ('1[.]1[.]1[.]1', 'IP'),
    ('test[@]test.com', 'Email'),
    ('https[:]//www[.]test[.]com/abc', 'URL'),
    ('test[.]com', 'Domain'),
    ('https://192.168.1.1:8080', 'URL'),
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


VALID_DOMAIN_INDICATORS = ['www.static.attackiqtes.com',
                           'test.com',
                           'www.testö.com',
                           'hxxps://path.test.com/check',
                           'https%3A%2F%2Ftwitter.com%2FPhilipsBeLux&data=02|01||cb2462dc8640484baf7608d638d2a698|1a407a2d7675'
                           '4d178692b3ac285306e4|0|0|636758874714819880&sdata=dnJiphWFhnAKsk5Ps0bj0p%2FvXVo8TpidtGZcW6t8lDQ%3'
                           'D&reserved=0%3E%5bcid:image003.gif@01CF4D7F.1DF62650%5d%3C',
                           'https://emea01.safelinks.protection.outlook.com/',
                           'good.good']


@pytest.mark.parametrize('indicator_value', VALID_DOMAIN_INDICATORS)
def test_valid_domain_indicator_types(indicator_value):
    """
    Given
    - Valid Domain indicators.
    When
    - Trying to match those indicators with the Domain regex.
    Then
    - The indicators are classified as Domain indicators.
    """
    assert re.match(domainRegex, indicator_value)


INVALID_DOMAIN_INDICATORS = ['aaa.2234',
                             '1.1.1.1',
                             'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
                             '1.1',
                             '2001 : db8: 3333 : 4444 : 5555',
                             'test..com',
                             'test/com',
                             '3.21.32.65/path']


@pytest.mark.parametrize('indicator_value', INVALID_DOMAIN_INDICATORS)
def test_invalid_domain_indicator_types(indicator_value):
    """
    Given
    - invalid Domain indicators.
    When
    - Trying to match those indicators with the Domain regex.
    Then
    - The indicators are not classified as Domain indicators.
    """
    assert not re.match(domainRegex, indicator_value)


VALID_URL_INDICATORS = [
    '3.21.32.65/path',
    '19.117.63.253:28/other/path',
    '19.117.63.253:28/path',
    '1.1.1.1/7/server/somestring/something.php?fjjasjkfhsjasofds=sjhfhdsfhasld',
    'flake8.pycqa.org/en/latest',
    '2001:db8:85a3:8d3:1319:8a2e:370:7348/path/path',
    '2001:db8:85a3:8d3:1319:8a2e:370:7348/32/path/path',
    'https://google.com/sdlfdshfkle3247239elkxszmcdfdstgk4e5pt0/path/path/oatdsfk/sdfjjdf',
    'www.google.com/path',
    'wwW.GooGle.com/path',
    '2001:db8:85a3:8d3:1319:8a2e:370:7348/65/path/path',
    '2001:db8:3333:4444:5555:6666:7777:8888/32/path/path',
    '2001:db8:85a3:8d3:1319:8a2e:370:7348/h',
    '1.1.1.1/7/server',
    "1.1.1.1/32/path",
    'https://evil.tld/evil.html',
    'www.evil.tld/evil.aspx',
    'sftp://69.254.57.79:5001/path',
    'sftp://75.26.0.1/path',
    'www.evil.tld/resource',
    'hxxps://google[.]com:443/path',
    'http://xn--e1v2i3l4.tld/evilagain.aspx',
    'www.evil.tld:443/path/to/resource.html',
    'WWW.evil.tld:443/path/to/resource.html',
    'wWw.Evil.tld:443/path/to/resource.html',
    'Https://wWw.Evil.tld:443/path/to/resource.html',
    'https://1.2.3.4/path/to/resource.html',
    'HTTPS://1.2.3.4/path/to/resource.html',
    '1.2.3.4/path',
    '1.2.3.4/path/to/resource.html',
    'http://1.2.3.4:8080/resource.html',
    'HTTP://1.2.3.4:80/path',
    'ftp://foo.bar/resource',
    'FTP://foo.bar/resource',
    'ftps://foo.bar/resource',
    'ftps://foo.bar/Resource',
    '5.6.7.8/fdsfs',
    'https://serverName.com/deepLinkAction.do?userName=peter%40nable%2Ecom&password=Hello',
    'http://serverName.org/deepLinkAction.do?userName=peter%40nable%2Ecom&password=Hello',
    'https://1.1.1.1/deepLinkAction.do?userName=peter%40nable%2Ecom&password=Hello',
    'https://google.com/deepLinkAction.do?userName=peter%40nable%2Ecom&password=Hello',
    'www.google.com/deepLinkAction.do?userName=peter%40nable%2Ecom&password=Hello',
    'https://xsoar.pan.dev/docs/welcome',
    '5.6.7.8/user/',
    'http://www.example.com/and%26here.html',
    'https://0.0.0.1/path',
    'hxxp://0[x]455e8c6f/0s19ef206s18s2f2s567s49a8s91f7s4s19fd61a',  # defanged hexa-decimal IP.
    'hxxp://0x325e5c7f/34823jdsasjfd/asdsafgf/324',  # hexa-decimal IP.
    'hxxps://0xAB268DC1:8080/path',
    'hxxps://0xAB268DC1/p',
    'hxxps://0xAB268DC1/32',
    'http://www.google[.]com:8080/path',
    'http://www[.]google.com:8080/path',
    'www[.]google.com:8080/path',
    'www.google[.]com:8080/path',
    'google[.]com/path',
    'google[.]com:443/path',
    'hXXps://1.1.1.1[.]edu/path',
    '2001:db8:85a3:8d3:1319:8a2e:370:7348/80',
    '2001:0db8:0001:0000:0000:0ab9:C0A8:0102/resource.html',
    '2251:dbc:8fa3:8d3:1f19:8a2e:370:7348/80',
    'https[:]//www.test.com/test',  # defanged colon sign
    "hxxp[:]//1[.]1[.]1[.]1/test[.]php",  # Defanged URL with ip as a domain
    "hxxp[:]//test[.]com/test[.]php",  # Defanged URL with a file extension
    "https://test.com/a/b/c-d-e",  # hyphen in the path
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
    regex_match = re.match(urlRegex, indicator_value)
    assert regex_match.group(0) == indicator_value


INVALID_URL_INDICATORS = [
    'www.google.com',
    'one.two.three.four.com',
    'one.two.three.com',
    'test',
    'httn://bla.com/path',
    'google.com*',
    '1.1.1.1',
    'path/path',
    '1.1.1.1:111112243245/path',
    '3.4.6.92:8080:/test',
    '1.1.1.1:4lll/',
    'flake8.pycqa.org',
    'google.com',
    'HTTPS://dsdffd.c',  # not valid tld
    'https://test',
    'ftp://test',
    'ftps:test',
    'a.a.a.a',
    'b.b.b',
    'https:/1.1.1.1.1/path',
    'wwww.test',
    'help.test.com',
    'help-test/com',
    'fnvfdsbf/path',
    '65.23.7.2',
    'k.f.a.f',
    'test/test/test/test',
    '',
    'somestring',
    'dsjfshjdfgkjldsh32423123^^&*#@$#@$@!#4',
    'aaa/1.1.1.1/path',
    'domain*com/1.1.1.1/path',
    'http:1.1.1.1/path',
    'kfer93420932/path/path',
    '1.1.1.1.1/24',
    '2.2.2.2.2/3sad',
    'http://fdsfesd',
    'http://fdsfesd:8080',  # no tld
    'FTP://Google.',
    'https://www.',
    '1.1.1.1.1/path',
    '2.2.2.2.2/3sad',
    'HTTPS://1.1.1.1..1.1.1.1/path',
    'https://1.1.1.1.1.1.1.1.1.1.1/path',
    '1.1.1.1 .1/path',
    '   test.com',
    'test .com.domain',
    'hxxps://0xAB26:8080/path',  # must be 8 hexa-decimal chars
    'hxxps://34543645356432234e:8080/path',  # too large integer IP
    'https://35.12.5677.143423:443',  # invalid IP address
    'https://4578.2436.1254.7423',  # invalid octal address (must be numbers between 0-7)
    'https://4578.2436.1254.7423:443/p',
    'FTP://foo hXXps://1.1.1.1[.]edu/path',
    'https://216.58.199.78:12345fdsf',
    'https://www.216.58.199.78:sfsdg'
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


def test_script_return_results_execution_metrics_command_results(mocker):
    """
    Given:
      - List of CommandResult and dicts that contains an execution metrics entry
      - The command currently running is a script
    When:
      - Calling return_results()
    Then:
      - demisto.results() is called 1 time (without the execution metrics entry)
    """
    from CommonServerPython import CommandResults, return_results
    mocker.patch.object(demisto, 'callingContext', {'context': {'ExecutedCommands': [{'moduleBrand': 'Scripts'}]}})
    demisto_results_mock = mocker.patch.object(demisto, 'results')
    mock_command_results = [
        CommandResults(outputs_prefix='Mock', outputs={'MockContext': 0}, entry_type=19),
        CommandResults(outputs_prefix='Mock', outputs={'MockContext': 1}),
        {'MockContext': 1, "Type": 19},
        {'MockContext': 1, "Type": 1},
    ]
    return_results(mock_command_results)
    for call_args in demisto_results_mock.call_args_list:
        for args in call_args.args:
            if isinstance(args, list):
                for arg in args:
                    assert arg["Type"] != 19
            else:
                assert args["Type"] != 19
    assert demisto_results_mock.call_count == 2


def test_integration_return_results_execution_metrics_command_results(mocker):
    """
    Given:
      - List of CommandResult and dicts that contains an execution metrics entry
      - The command currently running is an integration command
    When:
      - Calling return_results()
    Then:
      - demisto.results() is called 3 times (with the execution metrics entry included)
    """
    from CommonServerPython import CommandResults, return_results
    mocker.patch.object(demisto, 'callingContext', {'context': {'ExecutedCommands': [{'moduleBrand': 'integration'}]}})
    demisto_results_mock = mocker.patch.object(demisto, 'results')
    mock_command_results = [
        CommandResults(outputs_prefix='Mock', outputs={'MockContext': 0}, entry_type=19),
        CommandResults(outputs_prefix='Mock', outputs={'MockContext': 1}),
        {'MockContext': 1, "Type": 19},
        {'MockContext': 1, "Type": 19},
    ]
    return_results(mock_command_results)
    execution_metrics_entry_found = False
    for call_args in demisto_results_mock.call_args_list:
        if execution_metrics_entry_found:
            break
        for args in call_args.args:
            if execution_metrics_entry_found:
                break
            execution_metrics_entry_found = args["Type"] != 19

    assert execution_metrics_entry_found
    assert demisto_results_mock.call_count == 3


def test_dynamic_section_script_return_results_execution_metrics_command_results(mocker):
    """
    Given:
      - List of CommandResult and dicts that contains execution metrics entries
      - The command currently running is a dynamic-section script
    When:
      - Calling return_results()
    Then:
      - demisto.results() is called 2 times (without the 2 execution metrics entries)
    """
    from CommonServerPython import CommandResults, return_results
    mocker.patch.object(demisto, 'callingContext', {'context': {'ScriptName': 'some_script_name'}})
    demisto_results_mock = mocker.patch.object(demisto, 'results')
    mock_command_results = [
        # CommandResults metrics entry: Should not be returned.
        CommandResults(outputs_prefix='Mock', outputs={'MockContext': 0}, entry_type=19),
        # CommandResults regular entry: Should be returned.
        CommandResults(outputs_prefix='Mock', outputs={'MockContext': 1}),
        # Dict metrics entry: Should not be returned.
        {'MockContext': 1, "Type": 19},
        # Dict regular entry: Should be returned.
        {'MockContext': 1, "Type": 1},
    ]
    return_results(mock_command_results)
    for call_args in demisto_results_mock.call_args_list:
        for args in call_args.args:
            if isinstance(args, list):
                for arg in args:
                    assert arg["Type"] != 19
            else:
                assert args["Type"] != 19

    assert demisto_results_mock.call_count == 2


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
            - Assert that DemistoException is raised with the original error.
        """
        from CommonServerPython import execute_command, EntryType
        error_entries = [
            {'Type': EntryType.ERROR, 'Contents': 'error number 1'},
            {'Type': EntryType.ERROR, 'Contents': 'error number 2'},
        ]

        demisto_execute_mock = mocker.patch.object(demisto, 'executeCommand', return_value=error_entries)

        with raises(DemistoException, match='Failed to execute'):
            execute_command('bad', {'arg1': 'value'})

        assert demisto_execute_mock.call_count == 1

    @staticmethod
    def test_failure_integration(monkeypatch):
        from CommonServerPython import execute_command
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


class TestExecuteCommandsMultipleResults:

    @staticmethod
    def test_sanity(mocker):
        """
        Given:
            - A successful command with a single entry as output.
        When:
            - Calling execute_commands.
        Then:
            - Assert that only the Contents value is returned.
        """
        from CommonServerPython import CommandRunner, EntryType
        demisto_execute_mock = mocker.patch.object(demisto, 'executeCommand',
                                                   return_value=[{'Type': EntryType.NOTE,
                                                                  'ModuleName': 'module',
                                                                  'Brand': 'brand',
                                                                  'Contents': {'hello': 'world'}}])
        command_executer = CommandRunner.Command(commands='command', args_lst={'arg1': 'value'})
        results, errors = CommandRunner.execute_commands(command_executer)
        execute_command_args = demisto_execute_mock.call_args_list[0][0]
        assert demisto_execute_mock.call_count == 1
        assert execute_command_args[0] == 'command'
        assert execute_command_args[1] == {'arg1': 'value'}
        assert isinstance(results, list)
        assert isinstance(errors, list)
        assert len(results) == 1
        assert results[0].brand == 'brand'
        assert results[0].instance == 'module'
        assert results[0].result == {'hello': 'world'}
        assert not errors

    @staticmethod
    def test_multiple_results(mocker):
        """
        Given:
            - A successful command with several entries as output.
        When:
            - Calling execute_commands.
        Then:
            - Assert that the "Contents" values of all entries are returned.
        """
        from CommonServerPython import CommandRunner, EntryType
        entries = [
            {'Type': EntryType.NOTE, 'Contents': {'hello': 'world'}},
            {'Type': EntryType.NOTE, 'Context': 'no contents here'},
            {'Type': EntryType.NOTE, 'Contents': {'entry': '2'}},
            {'Type': EntryType.NOTE, 'Context': 'Content is `None`', 'Contents': None}
        ]
        demisto_execute_mock = mocker.patch.object(demisto, 'executeCommand',
                                                   return_value=entries)
        command_executer = CommandRunner.Command(commands='command', args_lst={'arg1': 'value'})
        results, errors = CommandRunner.execute_commands(command_executer)
        assert demisto_execute_mock.call_count == 1
        assert isinstance(results, list)
        assert isinstance(errors, list)
        assert not errors
        assert len(results) == 4
        assert results[0].result == {'hello': 'world'}
        assert results[1].result == {}
        assert results[2].result == {'entry': '2'}
        assert results[3].result == {}

    @staticmethod
    def test_raw_results(mocker):
        """
        Given:
            - A successful command with several entries as output.
        When:
            - Calling execute_commands.
        Then:
            - Assert that the entire entries are returned.
        """
        from CommonServerPython import EntryType, CommandRunner
        entries = [
            {'Type': EntryType.NOTE, 'Contents': {'hello': 'world'}},
            {'Type': EntryType.NOTE, 'Context': 'no contents here'},
            'text',
            1337,
        ]
        demisto_execute_mock = mocker.patch.object(demisto, 'executeCommand',
                                                   return_value=entries)
        command_executer = CommandRunner.Command(commands='command', args_lst={'arg1': 'value'})
        results, errors = CommandRunner.execute_commands(command_executer, extract_contents=False)
        assert demisto_execute_mock.call_count == 1
        assert isinstance(results, list)
        assert isinstance(errors, list)
        assert not errors
        assert len(results) == 4
        assert results[0].result == {'Type': EntryType.NOTE, 'Contents': {'hello': 'world'}}
        assert results[1].result == {'Type': EntryType.NOTE, 'Context': 'no contents here'}
        assert results[2].result == 'text'
        assert results[3].result == 1337
        assert results[2].brand == results[2].instance == results[3].brand == results[3].instance == 'Unknown'

    @staticmethod
    def test_with_errors(mocker):
        """
        Given:
            - A command that sometimes fails and sometimes not.
        When:
            - Calling execute_command.
        Then:
            - Assert that the results list and the errors list returned as should've been
        """
        from CommonServerPython import CommandRunner, EntryType
        entries = [
            {'Type': EntryType.ERROR, 'Contents': 'error number 1'},
            {'Type': EntryType.NOTE, 'Contents': 'not an error'},
            {'Type': EntryType.ERROR, 'Contents': 'error number 2'}
        ]

        def execute_command_mock(command, args):
            if command == 'unsupported':
                raise ValueError("Command is not supported")
            return entries

        demisto_execute_mock = mocker.patch.object(demisto, 'executeCommand',
                                                   side_effect=execute_command_mock)
        command_executer = CommandRunner.Command(commands=['command', 'unsupported'],
                                                 args_lst=[{'arg1': 'value'}, {}])

        results, errors = CommandRunner.execute_commands(command_executer)

        # validate that errors were found and the unsupported is ignored
        assert demisto_execute_mock.call_count == 2
        assert isinstance(results, list)
        assert isinstance(errors, list)
        assert len(results) == 1
        assert len(errors) == 2
        assert errors[0].result == 'error number 1'
        assert errors[1].result == 'error number 2'
        assert results[0].result == 'not an error'

    @staticmethod
    def get_result_for_multiple_commands_helper(command, args):
        from CommonServerPython import EntryType
        return [{'Type': EntryType.NOTE,
                 'ModuleName': list(args.keys())[0],
                 'Brand': command,
                 'Contents': {'hello': list(args.values())[0]}},
                ]

    @staticmethod
    def test_multiple_commands(mocker):
        """
        Given:
            - List of commands and list of args.
        When:
            - Calling execute_commands with multiple commands to get multiple results.
        Then:
            - Assert that the results list and the errors list returned as should've been
        """
        from CommonServerPython import CommandRunner
        demisto_execute_mock = mocker.patch.object(demisto,
                                                   'executeCommand',
                                                   side_effect=TestExecuteCommandsMultipleResults.get_result_for_multiple_commands_helper)
        command_executer = CommandRunner.Command(commands=['command1', 'command2'],
                                                 args_lst=[{'arg1': 'value1'},
                                                           {'arg2': 'value2'}])

        results, errors = CommandRunner.execute_commands(command_executer)
        assert demisto_execute_mock.call_count == 2
        assert isinstance(results, list)
        assert isinstance(errors, list)
        assert len(results) == 2
        assert results[0].brand == 'command1'
        assert results[0].instance == 'arg1'
        assert results[0].result == {'hello': 'value1'}
        assert results[1].brand == 'command2'
        assert results[1].instance == 'arg2'
        assert results[1].result == {'hello': 'value2'}
        assert not errors

    @staticmethod
    def test_invalid_args():
        """
        Given:
            - List of commands and list of args which is invalid
        When:
            - Calling execute_commands.
        Then:
            - Assert that error is given.
        """
        from CommonServerPython import CommandRunner
        with pytest.raises(DemistoException):
            CommandRunner.execute_commands(
                CommandRunner.Command(commands=['command'],
                                      args_lst=[{'arg': 'val'}, {'arg': 'val'}]))
        with pytest.raises(DemistoException):
            CommandRunner.execute_commands(
                CommandRunner.Command(commands=['command', 'command1'],
                                      args_lst=[{'arg': 'val'}]))

    @staticmethod
    def test_using_brand_instance(mocker):
        """
        Given:
            - Provide instance and brand to command wrapper
        When:
            - Calling execute_commands
        Then:
            - Assert that the `demisto.executeCommand` runned with `using` and `using-brand`.
        """
        from CommonServerPython import CommandRunner
        executer_with_brand = CommandRunner.Command(brand='my brand',
                                                    instance='my instance',
                                                    commands='command',
                                                    args_lst={'arg': 'val'})
        demisto_execute_mock = mocker.patch.object(demisto, 'executeCommand')
        CommandRunner.execute_commands(executer_with_brand)
        assert demisto_execute_mock.called
        args_for_execute_command = demisto_execute_mock.call_args_list[0][0][1]
        assert 'using-brand' in args_for_execute_command
        assert 'using' in args_for_execute_command
        assert args_for_execute_command['using-brand'] == 'my brand'
        assert args_for_execute_command['using'] == 'my instance'


class TestGetResultsWrapper:
    NUM_EXECUTE_COMMAND_CALLED = 0

    @staticmethod
    def execute_command_mock(command_executer, extract_contents):
        from CommonServerPython import CommandRunner
        TestGetResultsWrapper.NUM_EXECUTE_COMMAND_CALLED += 1
        results, errors = [], []

        for command, args in zip(command_executer.commands, command_executer.args_lst):
            result_wrapper = CommandRunner.Result(command=command,
                                                  args=args,
                                                  brand='my-brand{}'.format(
                                                      TestGetResultsWrapper.NUM_EXECUTE_COMMAND_CALLED),
                                                  instance='instance',
                                                  result='Command did not succeeded' if command == 'error-command' else {
                                                      'Contents': 'Good',
                                                      'HumanReadable': 'Good'})
            if command == 'error-command':
                errors.append(result_wrapper)
            elif command != 'unsupported-command':
                results.append(result_wrapper)
        return results, errors

    @staticmethod
    def test_get_wrapper_results(mocker):
        """
        Given:
            - List of CommandWrappers.
        When:
            - Calling get_wrapper_results to give generic results
        Then:
            - Assert that the "good" results are returned, and the summary includes the errors.
            - Assert that the unsupported command is ignored.
        """
        from CommonServerPython import CommandRunner, CommandResults
        command_wrappers = [CommandRunner.Command(brand='my-brand1', commands='my-command', args_lst={'arg': 'val'}),
                            CommandRunner.Command(brand='my-brand2', commands=['command1', 'command2'],
                                                  args_lst=[{'arg1': 'val1'}, {'arg2': 'val2'}]),
                            CommandRunner.Command(brand='my-brand3', commands='error-command',
                                                  args_lst={'bad_arg': 'bad_val'}),
                            CommandRunner.Command(brand='brand-no-exist', commands='unsupported-command',
                                                  args_lst={'arg': 'val'})]
        mocker.patch.object(CommandRunner, 'execute_commands',
                            side_effect=TestGetResultsWrapper.execute_command_mock)
        results = CommandRunner.run_commands_with_summary(command_wrappers)
        assert len(results) == 4  # 1 error (brand3)
        assert results[:-1] == [{'Contents': 'Good', 'HumanReadable': '***my-brand1 (instance)***\nGood'},
                                {'Contents': 'Good', 'HumanReadable': '***my-brand2 (instance)***\nGood'},
                                {'Contents': 'Good', 'HumanReadable': '***my-brand2 (instance)***\nGood'}]

        assert isinstance(results[-1], CommandResults)
        if IS_PY3:
            md_summary = """### Results Summary
|Instance|Command|Result|Comment|
|---|---|---|---|
| ***my-brand1***: instance | ***command***: my-command<br>**args**:<br>	***arg***: val | Success | Good |
| ***my-brand2***: instance | ***command***: command1<br>**args**:<br>	***arg1***: val1 | Success | Good |
| ***my-brand2***: instance | ***command***: command2<br>**args**:<br>	***arg2***: val2 | Success | Good |
| ***my-brand3***: instance | ***command***: error-command<br>**args**:<br>	***bad_arg***: bad_val | Error | Command did not succeeded |
"""
        else:
            md_summary = u"""### Results Summary
|Instance|Command|Result|Comment|
|---|---|---|---|
| ***my-brand1***: instance | **args**:<br>	***arg***: val<br>***command***: my-command | Success | Good |
| ***my-brand2***: instance | **args**:<br>	***arg1***: val1<br>***command***: command1 | Success | Good |
| ***my-brand2***: instance | **args**:<br>	***arg2***: val2<br>***command***: command2 | Success | Good |
| ***my-brand3***: instance | **args**:<br>	***bad_arg***: bad_val<br>***command***: error-command | Error | Command did not succeeded |
"""
        assert results[-1].readable_output == md_summary

    @staticmethod
    def test_get_wrapper_results_error(mocker):
        """
        Given:
            - List of CommandWrappers, which all of them returns errors or ignored
        When:
            - Calling get_wrapper_results to give generic results
        Then:
            - Assert that error returned.
        """
        from CommonServerPython import CommandRunner
        command_wrappers = [CommandRunner.Command(brand='my-brand1',
                                                  commands='error-command',
                                                  args_lst={'arg': 'val'}),
                            CommandRunner.Command(brand='my-brand2',
                                                  commands='error-command',
                                                  args_lst={'bad_arg': 'bad_val'}),
                            CommandRunner.Command(brand='brand-no-exist',
                                                  commands='unsupported-command',
                                                  args_lst={'arg': 'val'}),
                            ]
        mocker.patch.object(CommandRunner, 'execute_commands',
                            side_effect=TestGetResultsWrapper.execute_command_mock)
        with pytest.raises(DemistoException) as e:
            CommandRunner.run_commands_with_summary(command_wrappers)
            assert 'Command did not succeeded' in e.value
            assert 'Script failed. The following errors were encountered:' in e.value


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
    def test_create_ip(self):
        """
            Given:
                - A single IP indicator entry
            When
               - Creating a Common.IP object
           Then
               - The context created matches the data entry
       """
        from CommonServerPython import CommandResults, Common, DBotScoreType

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
            geo_country='geo_country',
            geo_description='geo_description',
            geo_latitude='geo_latitude',
            geo_longitude='geo_longitude',
            positive_engines=5,
            detection_engines=10,
            as_owner=None,
            region='region',
            port='port',
            internal=None,
            updated_date=None,
            registrar_abuse_name='Mr Registrar',
            registrar_abuse_address='Registrar Address',
            registrar_abuse_country='Registrar Country',
            registrar_abuse_network='Registrar Network',
            registrar_abuse_phone=None,
            registrar_abuse_email='registrar@test.com',
            campaign='campaign',
            traffic_light_protocol='traffic_light_protocol',
            threat_types=[Common.ThreatTypes(threat_category='threat_category',
                                             threat_category_confidence='threat_category_confidence')],
            community_notes=[Common.CommunityNotes(note='note', timestamp='2019-01-01T00:00:00')],
            publications=[Common.Publications(title='title', source='source', timestamp='2019-01-01T00:00:00',
                                              link='link')],
            organization_name='Some Organization',
            organization_type='Organization type',
            feed_related_indicators=None,
            tags=['tag1', 'tag2'],
            malware_family=['malware_family1', 'malware_family2'],
            relationships=None,
            blocked=False,
            description='description test',
            stix_id='stix_id',
            whois_records=[Common.WhoisRecord('test_key', 'test_value', 'test_date')],
        )

        results = CommandResults(
            outputs_key_field=None,
            outputs_prefix=None,
            outputs=None,
            indicators=[ip]
        )

        assert results.to_context() == {
            'Type': 1,
            'ContentsFormat': 'json',
            'Contents': None,
            'HumanReadable': None,
            'EntryContext': {
                'IP(val.Address && val.Address == obj.Address)': [
                    {'Address': '8.8.8.8',
                     'ASN': 'some asn',
                     'Region': 'region',
                     'Port': 'port',
                     'STIXID': 'stix_id',
                     'Registrar': {
                         'Abuse': {
                             'Name': 'Mr Registrar',
                             'Address': 'Registrar Address',
                             'Country': 'Registrar Country',
                             'Network': 'Registrar Network',
                             'Email': 'registrar@test.com'
                         }
                     },
                     'Campaign': 'campaign',
                     'Description': 'description test',
                     'TrafficLightProtocol': 'traffic_light_protocol',
                     'CommunityNotes': [{'note': 'note', 'timestamp': '2019-01-01T00:00:00'}],
                     'Publications': [
                         {
                             'source': 'source',
                             'title': 'title',
                             'link': 'link',
                             'timestamp': '2019-01-01T00:00:00'
                         }
                     ],
                     'ThreatTypes': [
                         {'threatcategory': 'threat_category',
                          'threatcategoryconfidence': 'threat_category_confidence'}
                     ],
                     'WhoisRecords': [{'key': 'test_key', 'value': 'test_value', 'date': 'test_date'}],
                     'Hostname': 'test.com',
                     'Geo': {
                         'Location': 'geo_latitude:geo_longitude',
                         'Country': 'geo_country',
                         'Description': 'geo_description'
                     },
                     'Organization': {
                         'Name': 'Some Organization',
                         'Type': 'Organization type'
                     },
                     'DetectionEngines': 10,
                     'PositiveDetections': 5,
                     'Tags': ['tag1', 'tag2'],
                     'MalwareFamily': ['malware_family1', 'malware_family2']
                     }
                ],
                'DBotScore(val.Indicator && val.Indicator == obj.Indicator && '
                'val.Vendor == obj.Vendor && val.Type == obj.Type)': [
                    {'Indicator': '8.8.8.8',
                     'Type': 'ip',
                     'Vendor': 'Test',
                     'Score': 1
                     }
                ]
            },
            'IndicatorTimeline': [],
            'IgnoreAutoExtract': False,
            'Note': False,
            'Relationships': [],
        }

    def test_create_domain(self):
        """
            Given:
                - A single Domain indicator entry
            When
               - Creating a Common.Domain object
           Then
               - The context created matches the data entry
       """
        from CommonServerPython import CommandResults, Common, DBotScoreType

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
            first_seen_by_source='2024-10-06T09:50:50.555Z',
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
            billing='billing',
            whois_records=[Common.WhoisRecord('test_key', 'test_value', 'test_date')],
            description='test_description',
            stix_id='test_stix_id',
            blocked=True,
            certificates=[Common.Certificates('test_issuedto', 'test_issuedby', 'test_validfrom', 'test_validto')],
            dns_records=[Common.DNSRecord('test_type', 'test_ttl', 'test_data')]
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
                        'Name': 'somedomain.com',
                        'DNS': 'dns.somedomain',
                        'DetectionEngines': 10,
                        'PositiveDetections': 5,
                        'Registrar': {'Name': 'Mr Registrar', 'AbuseEmail': 'registrar@test.com', 'AbusePhone': None},
                        'Registrant': {'Name': 'Mr Registrant', 'Email': None, 'Phone': None, 'Country': None},
                        'Admin': {'Name': None, 'Email': 'admin@test.com', 'Phone': '18000000', 'Country': None},
                        'FirstSeenBySource': '2024-10-06T09:50:50.555Z',
                        'Organization': 'Some Organization',
                        'Subdomains': ['sub-domain1.somedomain.com', 'sub-domain2.somedomain.com',
                                       'sub-domain3.somedomain.com'], 'DomainStatus': 'ACTIVE',
                        'CreationDate': '2019-01-01T00:00:00',
                        'UpdatedDate': '2019-01-02T00:00:00',
                        'NameServers': ['PNS31.CLOUDNS.NET', 'PNS32.CLOUDNS.NET'],
                        'Tags': ['tag1', 'tag2'],
                        'FeedRelatedIndicators': [{'value': '8.8.8.8', 'type': 'IP', 'description': 'test'}],
                        'WhoisRecords': [{'key': 'test_key', 'value': 'test_value', 'date': 'test_date'}],
                        'MalwareFamily': ['malware_family1', 'malware_family2'], 'DomainIDNName': 'domain_idn_name',
                        'Port': 'port',
                        'Internal': 'False',
                        'Category': 'category',
                        'Campaign': 'campaign',
                        'TrafficLightProtocol': 'traffic_light_protocol',
                        'ThreatTypes': [{'threatcategory': 'threat_category',
                                         'threatcategoryconfidence': 'threat_category_confidence'}],
                        'CommunityNotes': [{'note': 'note', 'timestamp': '2019-01-01T00:00:00'}],
                        'Publications': [{'source': 'source', 'title': 'title', 'link': 'link',
                                          'timestamp': '2019-01-01T00:00:00'}],
                        'Geo': {'Location': 'geo_location', 'Country': 'geo_country', 'Description': 'geo_description'},
                        'Tech': {'Country': 'tech_country', 'Name': 'tech_name', 'Organization': 'tech_organization',
                                 'Email': 'tech_email'},
                        'Billing': 'billing',
                        'WHOIS': {
                            'Registrar': {'Name': 'Mr Registrar', 'AbuseEmail': 'registrar@test.com',
                                          'AbusePhone': None},
                            'Registrant': {'Name': 'Mr Registrant', 'Email': None, 'Phone': None, 'Country': None},
                            'Admin': {'Name': None, 'Email': 'admin@test.com', 'Phone': '18000000', 'Country': None},
                            'DomainStatus': 'ACTIVE',
                            'CreationDate': '2019-01-01T00:00:00',
                            'UpdatedDate': '2019-01-02T00:00:00',
                            'NameServers': ['PNS31.CLOUDNS.NET', 'PNS32.CLOUDNS.NET']
                        },
                        'DNSRecords': [{'type': 'test_type', 'ttl': 'test_ttl', 'data': 'test_data'}],
                        'STIXID': 'test_stix_id',
                        'Description': 'test_description',
                        'Blocked': True,
                        'Certificates': [{'issuedto': 'test_issuedto', 'issuedby': 'test_issuedby',
                                          'validfrom': 'test_validfrom', 'validto': 'test_validto'}]
                    }
                ],
                'DBotScore(val.Indicator && val.Indicator == obj.Indicator &&'
                ' val.Vendor == obj.Vendor && val.Type == obj.Type)': [
                    {'Indicator': 'somedomain.com', 'Type': 'domain', 'Vendor': 'Test', 'Score': 1}
                ]
            },
            'IndicatorTimeline': [],
            'IgnoreAutoExtract': False,
            'Note': False,
            'Relationships': [],
        }

    def test_create_url(self):
        """
            Given:
                - A single URL indicator entry
            When
               - Creating a Common.URL object
           Then
               - The context created matches the data entry
       """
        from CommonServerPython import CommandResults, Common, DBotScoreType

        dbot_score = Common.DBotScore(
            indicator='https://somedomain.com',
            integration_name='Test',
            indicator_type=DBotScoreType.URL,
            score=Common.DBotScore.GOOD
        )

        url = Common.URL(
            url='https://somedomain.com',
            dbot_score=dbot_score,
            positive_detections=5,
            detection_engines=10,
            category='test_category',
            feed_related_indicators=None,
            tags=['tag1', 'tag2'],
            malware_family=['malware_family1', 'malware_family2'],
            port='port',
            internal=None,
            campaign='test_campaign',
            traffic_light_protocol='test_traffic_light_protocol',
            threat_types=[Common.ThreatTypes(threat_category='threat_category',
                                             threat_category_confidence='threat_category_confidence')],
            asn='test_asn',
            as_owner='test_as_owner',
            geo_country='test_geo_country',
            organization='test_organization',
            community_notes=[Common.CommunityNotes(note='note', timestamp='2019-01-01T00:00:00')],
            publications=[Common.Publications(title='title', source='source', timestamp='2019-01-01T00:00:00',
                                              link='link')],
            relationships=None,
            blocked=True,
            certificates=None,
            description='description test',
            stix_id='stix_id',
            organization_first_seen='2024-11-04T14:48:23.456Z',
        )

        results = CommandResults(
            outputs_key_field=None,
            outputs_prefix=None,
            outputs=None,
            indicators=[url]
        )

        assert results.to_context() == {
            'Type': 1,
            'ContentsFormat': 'json',
            'Contents': None,
            'HumanReadable': None,
            'EntryContext': {
                'URL(val.Data && val.Data == obj.Data)': [
                    {
                        'Data': 'https://somedomain.com',
                        'Blocked': True,
                        'Description': 'description test',
                        'STIXID': 'stix_id',
                        'DetectionEngines': 10,
                        'PositiveDetections': 5,
                        'Category': 'test_category',
                        'Tags': ['tag1', 'tag2'],
                        'MalwareFamily': ['malware_family1', 'malware_family2'],
                        'Port': 'port',
                        'Campaign': 'test_campaign',
                        'TrafficLightProtocol': 'test_traffic_light_protocol',
                        'ThreatTypes': [
                            {
                                'threatcategory': 'threat_category',
                                'threatcategoryconfidence': 'threat_category_confidence'
                            }
                        ],
                        'ASN': 'test_asn',
                        'ASOwner': 'test_as_owner',
                        'Geo': {'Country': 'test_geo_country'},
                        'Organization': 'test_organization',
                        'OrganizationFirstSeen': '2024-11-04T14:48:23.456Z',
                        'CommunityNotes': [{'note': 'note', 'timestamp': '2019-01-01T00:00:00'}],
                        'Publications': [
                            {'source': 'source',
                             'title': 'title',
                             'link': 'link',
                             'timestamp': '2019-01-01T00:00:00'
                             }
                        ]
                    }
                ],
                'DBotScore(val.Indicator && val.Indicator == obj.Indicator &&'
                ' val.Vendor == obj.Vendor && val.Type == obj.Type)': [
                    {
                        'Indicator': 'https://somedomain.com',
                        'Type': 'url',
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

    def test_create_file(self):
        """
            Given:
                - A single File indicator entry
            When
               - Creating a Common.File object
           Then
               - The context created matches the data entry
       """
        from CommonServerPython import CommandResults, Common, DBotScoreType

        indicator_id = '63347f5d946164a23faca26b78a91e1c'

        dbot_score = Common.DBotScore(
            indicator=indicator_id,
            integration_name='Test',
            indicator_type=DBotScoreType.FILE,
            score=Common.DBotScore.BAD,
            malicious_description='malicious!'
        )

        file = Common.File(
            md5=indicator_id,
            sha1='test_sha1',
            sha256='test_sha256',
            sha512='test_sha512',
            ssdeep='test_ssdeep',
            imphash='test_imphash',
            name='test_name',
            entry_id='test_entry_id',
            size=1000,
            dbot_score=dbot_score,
            extension='test_extension',
            file_type='test_file_type',
            hostname='test_hostname',
            path=None,
            company=None,
            product_name=None,
            digital_signature__publisher=None,
            signature=None,
            actor='test_actor',
            tags=['tag1', 'tag2'],
            feed_related_indicators=None,
            malware_family=['malware_family1', 'malware_family2'],
            quarantined=None,
            campaign='test_campaign',
            associated_file_names=None,
            traffic_light_protocol='traffic_light_protocol',
            organization='test_organization',
            community_notes=[Common.CommunityNotes(note='note', timestamp='2019-01-01T00:00:00')],
            publications=[Common.Publications(title='title', source='source', timestamp='2019-01-01T00:00:00',
                                              link='link')],
            threat_types=[Common.ThreatTypes(threat_category='threat_category',
                                             threat_category_confidence='threat_category_confidence')],
            behaviors=None,
            relationships=None,
            creation_date='test_creation_date',
            description='test_description',
            hashes=None,
            stix_id='test_stix_id',
            organization_prevalence=0,
        )

        results = CommandResults(
            outputs_key_field=None,
            outputs_prefix=None,
            outputs=None,
            indicators=[file]
        )

        assert results.to_context() == {
            'Type': 1,
            'ContentsFormat': 'json',
            'Contents': None,
            'HumanReadable': None,
            'EntryContext': {
                'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 &&'
                ' val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 &&'
                ' val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep &&'
                ' val.SSDeep == obj.SSDeep)': [
                    {'Hashes': [{'type': 'MD5', 'value': '63347f5d946164a23faca26b78a91e1c'},
                                {'type': 'SHA1', 'value': 'test_sha1'}, {'type': 'SHA256', 'value': 'test_sha256'},
                                {'type': 'SHA512', 'value': 'test_sha512'}, {'type': 'SSDeep', 'value': 'test_ssdeep'},
                                {'type': 'Imphash', 'value': 'test_imphash'}],
                     'Name': 'test_name',
                     'EntryID': 'test_entry_id',
                     'Size': 1000,
                     'MD5': '63347f5d946164a23faca26b78a91e1c',
                     'SHA1': 'test_sha1',
                     'SHA256': 'test_sha256',
                     'SHA512': 'test_sha512',
                     'SSDeep': 'test_ssdeep',
                     'Extension': 'test_extension',
                     'Type': 'test_file_type',
                     'Hostname': 'test_hostname',
                     'Actor': 'test_actor',
                     'Tags': ['tag1', 'tag2'],
                     'MalwareFamily': ['malware_family1', 'malware_family2'],
                     'Campaign': 'test_campaign',
                     'TrafficLightProtocol': 'traffic_light_protocol',
                     'CommunityNotes': [{'note': 'note', 'timestamp': '2019-01-01T00:00:00'}], 'Publications': [
                        {'source': 'source', 'title': 'title', 'link': 'link', 'timestamp': '2019-01-01T00:00:00'}],
                     'ThreatTypes': [{'threatcategory': 'threat_category',
                                      'threatcategoryconfidence': 'threat_category_confidence'}],
                     'Imphash': 'test_imphash',
                     'Organization': 'test_organization',
                     'OrganizationPrevalence': 0,
                     'Malicious': {'Vendor': 'Test', 'Description': 'malicious!'}
                     }
                ],
                'DBotScore(val.Indicator && val.Indicator == obj.Indicator &&'
                ' val.Vendor == obj.Vendor && val.Type == obj.Type)': [
                    {'Indicator': '63347f5d946164a23faca26b78a91e1c',
                     'Type': 'file',
                     'Vendor': 'Test',
                     'Score': 3}
                ]
            },
            'IndicatorTimeline': [],
            'IgnoreAutoExtract': False,
            'Note': False,
            'Relationships': []
        }

    def test_create_cve(self):
        """
            Given:
                - A single CVE indicator entry
            When
               - Creating a Common.CVE object
           Then
               - The context created matches the data entry
       """
        from CommonServerPython import CommandResults, Common

        cve = Common.CVE(
            id='CVE-2015-1653',
            cvss='10.0',
            published='2022-04-28T13:16:54+00:00',
            modified='2022-04-31T13:16:54+00:00',
            description='test_description',
            relationships=None,
            stix_id='test_stix_id',
            cvss_version='test_cvss_version',
            cvss_score=10,
            cvss_vector='test_cvss_vector',
            cvss_table='test_cvss_table',
            community_notes=[Common.CommunityNotes(note='note', timestamp='2019-01-01T00:00:00')],
            tags=['tag1', 'tag2'],
            traffic_light_protocol='traffic_light_protocol'
        )

        results = CommandResults(
            outputs_key_field=None,
            outputs_prefix=None,
            outputs=None,
            indicators=[cve]
        )

        assert results.to_context() == {
            'Type': 1,
            'ContentsFormat': 'json',
            'Contents': None,
            'HumanReadable': None,
            'EntryContext': {
                'CVE(val.ID && val.ID == obj.ID)': [
                    {
                        'ID': 'CVE-2015-1653',
                        'CVSS': {
                            'Score': '10.0',
                            'Version': 'test_cvss_version',
                            'Vector': 'test_cvss_vector',
                            'Table': 'test_cvss_table'
                        },
                        'Published': '2022-04-28T13:16:54+00:00',
                        'Modified': '2022-04-31T13:16:54+00:00',
                        'Description': 'test_description',
                        'STIXID': 'test_stix_id',
                        'CommunityNotes': [{'note': 'note', 'timestamp': '2019-01-01T00:00:00'}],
                        'Tags': ['tag1', 'tag2'],
                        'TrafficLightProtocol': 'traffic_light_protocol'
                    }
                ],
                'DBotScore(val.Indicator && val.Indicator == obj.Indicator &&'
                ' val.Vendor == obj.Vendor && val.Type == obj.Type)': [
                    {'Indicator': 'CVE-2015-1653',
                     'Type': 'cve',
                     'Vendor': None,
                     'Score': 0
                     }
                ]
            },
            'IndicatorTimeline': [],
            'IgnoreAutoExtract': False,
            'Note': False,
            'Relationships': []
        }

    def test_create_account(self):
        """
            Given:
                - A single Account indicator entry
            When
               - Creating a Common.Account object
           Then
               - The context created matches the data entry
       """
        from CommonServerPython import CommandResults, Common

        dbot_score = Common.DBotScore(
            indicator='test_account_id',
            integration_name='Test',
            indicator_type=DBotScoreType.ACCOUNT,
            score=Common.DBotScore.GOOD
        )

        account = Common.Account(
            id='test_account_id',
            type='test_account_type',
            username='test_username',
            display_name='test_display_name',
            groups=None,
            domain=None,
            email_address='user@test.com',
            telephone_number=None,
            office='test_office',
            job_title='test_job_title',
            department='test_department',
            country='test_country',
            state='test_state',
            city='test_city',
            street='test_street',
            is_enabled=None,
            dbot_score=dbot_score,
            relationships=None,
            blocked=True,
            community_notes=[Common.CommunityNotes(note='note', timestamp='2019-01-01T00:00:00')],
            creation_date='test_creation_date',
            description='test_description',
            stix_id='test_stix_id',
            tags=['tag1', 'tag2'],
            traffic_light_protocol='traffic_light_protocol',
            user_id='test_user_id',
            manager_email='test_manager_email@test.com',
            manager_display_name='test_manager_display_name',
            risk_level='test_risk_level',
            **{'some_undefinedKey': 'value'}
        )

        results = CommandResults(
            outputs_key_field=None,
            outputs_prefix=None,
            outputs=None,
            indicators=[account]
        )

        assert results.to_context() == {
            'Type': 1,
            'ContentsFormat': 'json',
            'Contents': None,
            'HumanReadable': None,
            'EntryContext': {
                'Account(val.id && val.id == obj.id)': [
                    {'ID': 'test_account_id',
                     'Type': 'test_account_type',
                     'Blocked': True,
                     'CreationDate': 'test_creation_date',
                     'City': 'test_city',
                     'CommunityNotes': [{'note': 'note', 'timestamp': '2019-01-01T00:00:00'}],
                     'Country': 'test_country',
                     'Department': 'test_department',
                     'Description': 'test_description',
                     'DisplayName': 'test_display_name',
                     'Email': {
                         'Address': 'user@test.com'
                     },
                     'JobTitle': 'test_job_title',
                     'Office': 'test_office',
                     'State': 'test_state',
                     'StixId': 'test_stix_id',
                     'Street': 'test_street',
                     'Tags': ['tag1', 'tag2'],
                     'TrafficLightProtocol': 'traffic_light_protocol',
                     'UserId': 'test_user_id',
                     'Username': 'test_username',
                     'Manager': {
                         'Email': 'test_manager_email@test.com',
                         'DisplayName': 'test_manager_display_name'
                     },
                     'RiskLevel': 'test_risk_level',
                     'some_undefinedKey': 'value'
                     }
                ],
                'DBotScore(val.Indicator && val.Indicator == obj.Indicator &&'
                ' val.Vendor == obj.Vendor && val.Type == obj.Type)': [
                    {
                        'Indicator': 'test_account_id',
                        'Type': 'account',
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

    def test_create_external_reference(self):
        """
            Given:
                - A single ExternalReference object
            When
               - Running 'to_context' function
           Then
               - Verify that the context is as expected
       """
        from CommonServerPython import Common

        external_reference = Common.ExternalReference(
            source_name='test_source_name',
            source_id='test_source_id'
        )

        assert external_reference.to_context() == {
            'sourcename': 'test_source_name',
            'sourceid': 'test_source_id'
        }

    def test_create_attack_pattern(self):
        """
            Given:
                - A single AttackPattern indicator entry
            When
               - Creating a Common.AttackPattern object
           Then
               - The context created matches the data entry
       """
        from CommonServerPython import CommandResults, Common

        dbot_score = Common.DBotScore(
            indicator='test_stix_id',
            integration_name='Test',
            indicator_type=DBotScoreType.ATTACKPATTERN,
            score=Common.DBotScore.GOOD
        )

        attack_pattern = Common.AttackPattern(
            stix_id='test_stix_id',
            kill_chain_phases='test_kill_chain_phases',
            first_seen_by_source=None,
            description='test_description',
            operating_system_refs=None,
            publications='test_publications',
            mitre_id='test_mitre_id',
            tags=['tag1', 'tag2'],
            traffic_light_protocol='test_traffic_light_protocol',
            dbot_score=dbot_score,
            value='test_stix_id',
            community_notes=[Common.CommunityNotes(note='note', timestamp='2019-01-01T00:00:00')],
            external_references=None
        )

        results = CommandResults(
            outputs_key_field=None,
            outputs_prefix=None,
            outputs=None,
            indicators=[attack_pattern]
        )

        assert results.to_context() == {
            'Type': 1,
            'ContentsFormat': 'json',
            'Contents': None,
            'HumanReadable': None,
            'EntryContext': {
                'AttackPattern(val.value && val.value == obj.value)': [
                    {
                        'STIXID': 'test_stix_id',
                        'KillChainPhases': 'test_kill_chain_phases',
                        'FirstSeenBySource': None,
                        'OperatingSystemRefs': None,
                        'Publications': 'test_publications',
                        'MITREID': 'test_mitre_id',
                        'Value': 'test_stix_id',
                        'Tags': ['tag1', 'tag2'],
                        'Description': 'test_description',
                        'TrafficLightProtocol': 'test_traffic_light_protocol'
                    }
                ],
                'DBotScore(val.Indicator && val.Indicator == obj.Indicator &&'
                ' val.Vendor == obj.Vendor && val.Type == obj.Type)': [
                    {
                        'Indicator': 'test_stix_id',
                        'Type': 'attackpattern',
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

    def test_create_certificates(self):
        """
            Given:
                - A Certificates object
            When
               - Running 'to_context' function
           Then
               - Verify that the context is as expected
       """
        from CommonServerPython import Common

        certificates = Common.Certificates(
            issued_to='test_issued_to',
            issued_by='test_issued_by',
            valid_from='test_valid_from',
            valid_to='test_valid_to'
        )

        assert certificates.to_context() == {
            'issuedto': 'test_issued_to',
            'issuedby': 'test_issued_by',
            'validfrom': 'test_valid_from',
            'validto': 'test_valid_to'
        }

    def test_create_hash(self):
        """
            Given:
                - A single Hash object
            When
               - Running 'to_context' function
           Then
               - Verify that the context is as expected
       """
        from CommonServerPython import Common

        hash_object = Common.Hash(
            hash_type='test_hash_type',
            hash_value='test_hash_value'
        )

        assert hash_object.to_context() == {
            'type': 'test_hash_type',
            'value': 'test_hash_value',
        }

    def test_create_whois_record(self):
        """
            Given:
                - A single WhoisRecord object
            When
               - Running 'to_context' function
           Then
               - Verify that the context is as expected
       """
        from CommonServerPython import Common

        whois_record = Common.WhoisRecord(
            whois_record_type='test_whois_record_type',
            whois_record_value='test_whois_record_value',
            whois_record_date='test_whois_record_date',

        )

        assert whois_record.to_context() == {
            'key': 'test_whois_record_type',
            'value': 'test_whois_record_value',
            'date': 'test_whois_record_date'
        }

    def test_create_dns_record(self):
        """
            Given:
                - A single DNSRecord object
            When
               - Running 'to_context' function
           Then
               - Verify that the context is as expected
       """
        from CommonServerPython import Common

        dns_record = Common.DNSRecord(
            dns_record_type='test_dns_record_type',
            dns_ttl='test_dns_ttl',
            dns_record_data='test_dns_record_data',

        )

        assert dns_record.to_context() == {
            'type': 'test_dns_record_type',
            'ttl': 'test_dns_ttl',
            'data': 'test_dns_record_data'
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
            dbot_score=dbot_score,
            description='test',
            internal=True,
            stix_id='stix_id_test',
            tags=['tag1', 'tag2'],
            traffic_light_protocol='traffic_light_protocol_test'
        )
        assert email_context.to_context()[email_context.CONTEXT_PATH] == \
            {"Email": {'Address': 'user@example.com'},
             'Domain': 'example.com',
             'Description': 'test',
             'Internal': True,
             'STIXID': 'stix_id_test',
             'Tags': ['tag1', 'tag2'],
             'TrafficLightProtocol': 'traffic_light_protocol_test'}

    @pytest.mark.parametrize('item', [
        'CommunityNotes', 'Publications', 'ThreatTypes'
    ])
    def test_common_indicator_create_context_table(self, item):
        """
        Tests the functionality of the 'create_context_table' function.
            Given:
                Case a: A list containing CommunityNotes items.
                Case b: A list containing Publications items.
                Case c: A list containing ThreatTypes items.

            When:
                Running the 'create_context_table' function.

            Then:
                Case a: Verify that the output is a list of CommunityNotes context items as expected.
                Case b: Verify that the output is a list of Publications context items as expected.
                Case c: Verify that the output is a list of ThreatTypes context items as expected.
        """
        if item == 'CommunityNotes':
            community_notes1 = Common.CommunityNotes(note='note1', timestamp='time1')
            community_notes2 = Common.CommunityNotes(note='note2', timestamp='time2')
            items = [community_notes1, community_notes2]
            expected_output = [{'note': 'note1', 'timestamp': 'time1'}, {'note': 'note2', 'timestamp': 'time2'}]

        elif item == 'Publications':
            publications1 = Common.Publications(source='source1', title='title1', link='link1', timestamp='time1')
            publications2 = Common.Publications(source='source2', title='title2', link='link2', timestamp='time2')
            items = [publications1, publications2]
            expected_output = [{'source': 'source1', 'title': 'title1', 'link': 'link1', 'timestamp': 'time1'},
                               {'source': 'source2', 'title': 'title2', 'link': 'link2', 'timestamp': 'time2'}]

        elif item == 'ThreatTypes':
            threat_types1 = Common.ThreatTypes(threat_category='test1', threat_category_confidence='10')
            threat_types2 = Common.ThreatTypes(threat_category='test2', threat_category_confidence='20')
            items = [threat_types1, threat_types2]
            expected_output = [{'threatcategory': 'test1', 'threatcategoryconfidence': '10'},
                               {'threatcategory': 'test2', 'threatcategoryconfidence': '20'}]

        table = Common.Indicator.create_context_table(items)
        assert table == expected_output


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
                return {'searchAfter': None, 'iocs': [], "total": 0}
        iocs = [{'value': 'mock{}'.format(search_after_value)}]
        return {'searchAfter': search_after_value, 'iocs': iocs, 'total': 4}

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
        for n in range(7):
            search_indicators_obj_search_after.search_indicators_by_version()
        assert search_indicators_obj_search_after._search_after_param is None
        assert search_indicators_obj_search_after._page == 7

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
        results = []
        for res in search_indicators:
            results.append(res)
        assert len(results) == 4

    def test_iterator__research_flow(self, mocker):
        from CommonServerPython import IndicatorsSearcher
        mocker.patch.object(demisto, 'searchIndicators', side_effect=self.mock_search_indicators_search_after)
        # fetch first 3
        search_indicators = IndicatorsSearcher(limit=3)
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

    def test_search_indicators_with_sort(self, mocker):
        """
        Given:
          - Searching indicators with a custom sort parameter.
          - Mocking the searchIndicators function.
        When:
          - Calling the searchIndicators function with the custom sort parameter.
        Then:
          - Ensure that the sort parameter is set correctly.
          - Ensure that the searchIndicators function is called with the expected arguments.
        """
        from CommonServerPython import IndicatorsSearcher
        get_demisto_version._version = None  # clear cache between runs of the test
        mocker.patch.object(demisto, 'demistoVersion', return_value={'version': '6.6.0'})

        mocker.patch.object(demisto, 'searchIndicators')
        sort_param = [{"field": "created", "asc": False}]
        search_indicators_obj_search_after = IndicatorsSearcher(sort=sort_param)
        search_indicators_obj_search_after.search_indicators_by_version()
        expected_args = {'size': 100, 'sort': [{'asc': False, 'field': 'created'}]}
        assert search_indicators_obj_search_after._sort == sort_param
        demisto.searchIndicators.assert_called_once_with(**expected_args)


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

    def test_get_demisto_version_2(self, mocker):
        mocker.patch.object(
            demisto,
            'demistoVersion',
            return_value={
                'version': '6.10.0',
                'buildNumber': '50000'
            }
        )
        assert get_demisto_version() == {
            'version': '6.10.0',
            'buildNumber': '50000'
        }
        assert is_demisto_version_ge('6.5.0')
        assert is_demisto_version_ge('6.1.0')
        assert is_demisto_version_ge('6.5')
        assert not is_demisto_version_ge('7.0.0')

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


class TestDeterminePlatform:
    @classmethod
    @pytest.fixture(scope='function', autouse=True)
    def clear_cache(cls):
        get_demisto_version._version = None

    @pytest.mark.parametrize('demistoVersion, method', [
        ({'platform': 'xsoar', 'version': '6.5.0'}, is_xsoar),
        ({'platform': 'xsoar', 'version': '8.2.0'}, is_xsoar),
        ({'platform': 'xsoar_hosted', 'version': '6.5.0'}, is_xsoar),
        ({'platform': 'x2', 'version': '8.2.0'}, is_xsiam_or_xsoar_saas),
        ({'platform': 'xsoar', 'version': '8.2.0'}, is_xsiam_or_xsoar_saas),
        ({'platform': 'xsoar', 'version': '6.5.0'}, is_xsoar_on_prem),
        ({'platform': 'xsoar_hosted', 'version': '6.5.0'}, is_xsoar_hosted),
        ({'platform': 'xsoar', 'version': '8.2.0'}, is_xsoar_saas),
        ({'platform': 'x2', 'version': '8.2.0'}, is_xsiam),
    ])
    def test_determine_platform(self, mocker, demistoVersion, method):
        mocker.patch.object(demisto, 'demistoVersion', return_value=demistoVersion)
        assert method()


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


class TestFetchWithLookBack:
    LAST_RUN = {}
    INCIDENTS = [
        {
            'incident_id': 1,
            'created': '2022-04-01T08:00:00'
        },
        {
            'incident_id': 2,
            'created': '2022-04-01T10:00:00'
        },
        {
            'incident_id': 3,
            'created': '2022-04-01T10:31:00'
        },
        {
            'incident_id': 4,
            'created': '2022-04-01T10:41:00'
        },
        {
            'incident_id': 5,
            'created': '2022-04-01T10:51:00'
        }
    ]

    NEW_INCIDENTS = [
        {
            'incident_id': 6,
            'created': '2022-04-01T10:11:00'
        },
        {
            'incident_id': 7,
            'created': '2022-04-01T10:35:00'
        },
        {
            'incident_id': 8,
            'created': '2022-04-01T10:37:00'
        }
    ]

    INCIDENTS_TIME_AWARE = [
        {
            'incident_id': incident.get('incident_id'),
            'created': incident.get('created') + 'Z'
        } for incident in INCIDENTS
    ]

    NEW_INCIDENTS_TIME_AWARE = [
        {
            'incident_id': incident.get('incident_id'),
            'created': incident.get('created') + 'Z'
        } for incident in NEW_INCIDENTS
    ]

    def example_fetch_incidents(self, time_aware=False):
        """
        An example fetch for testing
        """

        from CommonServerPython import get_fetch_run_time_range, filter_incidents_by_duplicates_and_limit, \
            update_last_run_object, arg_to_number
        date_format = '%Y-%m-%dT%H:%M:%S' + ('Z' if time_aware else '')
        incidents = []

        params = demisto.params()
        fetch_limit_param = params.get('limit')
        look_back = arg_to_number(params.get('look_back', 0))
        first_fetch = params.get('first_fetch')
        time_zone = params.get('time_zone', 0)

        last_run = demisto.getLastRun()
        fetch_limit = last_run.get('limit') or fetch_limit_param

        start_fetch_time, end_fetch_time = get_fetch_run_time_range(last_run=last_run, first_fetch=first_fetch,
                                                                    look_back=look_back, timezone=time_zone,
                                                                    date_format=date_format)

        query = self.build_query(start_fetch_time, end_fetch_time, fetch_limit)
        incidents_res = self.get_incidents_request(query, date_format)

        incidents = filter_incidents_by_duplicates_and_limit(incidents_res=incidents_res, last_run=last_run,
                                                             fetch_limit=fetch_limit_param, id_field='incident_id')

        last_run = update_last_run_object(last_run=last_run, incidents=incidents, fetch_limit=fetch_limit_param,
                                          start_fetch_time=start_fetch_time,
                                          end_fetch_time=end_fetch_time, look_back=look_back,
                                          created_time_field='created', id_field='incident_id', date_format=date_format)

        demisto.setLastRun(last_run)
        return incidents

    @staticmethod
    def build_query(start_time, end_time, limit, return_incidents_by_limit=True):
        query = {'from': start_time, 'to': end_time}
        if return_incidents_by_limit:
            query['limit'] = limit
        return query

    def get_incidents_request(self, query, date_format):
        time_aware = 'Z' in date_format
        source_incidents = self.INCIDENTS_TIME_AWARE if time_aware else self.INCIDENTS
        from_time = datetime.strptime(query['from'], date_format)
        incidents = [inc for inc in source_incidents if
                     datetime.strptime(inc['created'], date_format) > from_time]
        if query.get('limit') is not None:
            return incidents[:query['limit']]
        return incidents

    def set_last_run(self, new_last_run):
        self.LAST_RUN = new_last_run

    @pytest.mark.parametrize('params, result_phase1, result_phase2, expected_last_run', [
        ({'limit': 2, 'first_fetch': '40 minutes'}, [INCIDENTS[2], INCIDENTS[3]], [INCIDENTS[4]],
         {'limit': 2, 'time': INCIDENTS[3]['created'], 'found_incident_ids': {3: 1667482800, 4: 1667482800}}),
        ({'limit': 2, 'first_fetch': '40 minutes', 'look_back': None}, [INCIDENTS[2], INCIDENTS[3]], [INCIDENTS[4]],
         {'limit': 2, 'time': INCIDENTS[3]['created'], 'found_incident_ids': {3: 1667482800, 4: 1667482800}}),
        ({'limit': 3, 'first_fetch': '40 minutes'}, [INCIDENTS[2], INCIDENTS[3], INCIDENTS[4]], [],
         {'limit': 3, 'time': INCIDENTS[4]['created'], 'found_incident_ids': {3: 1667482800, 4: 1667482800, 5: 1667482800}}),
        ({'limit': 2, 'first_fetch': '2 hours'}, [INCIDENTS[1], INCIDENTS[2]], [INCIDENTS[3], INCIDENTS[4]],
         {'limit': 2, 'time': INCIDENTS[2]['created'], 'found_incident_ids': {2: 1667482800, 3: 1667482800}}),
        ({'limit': 3, 'first_fetch': '2 hours'}, [INCIDENTS[1], INCIDENTS[2], INCIDENTS[3]], [INCIDENTS[4]],
         {'limit': 3, 'time': INCIDENTS[3]['created'], 'found_incident_ids': {2: 1667482800, 3: 1667482800, 4: 1667482800}}),
        ({'limit': 2, 'first_fetch': '40 minutes'}, [INCIDENTS_TIME_AWARE[2], INCIDENTS_TIME_AWARE[3]],
         [INCIDENTS_TIME_AWARE[4]], {'limit': 2, 'time': INCIDENTS_TIME_AWARE[3]['created'],
                                     'found_incident_ids': {3: 1667482800, 4: 1667482800}}),
        ({'limit': 3, 'first_fetch': '40 minutes'}, [INCIDENTS_TIME_AWARE[2], INCIDENTS_TIME_AWARE[3], INCIDENTS_TIME_AWARE[4]],
         [],
         {'limit': 3, 'time': INCIDENTS_TIME_AWARE[4]['created'],
          'found_incident_ids': {3: 1667482800, 4: 1667482800, 5: 1667482800}}),
        ({'limit': 2, 'first_fetch': '2 hours'}, [INCIDENTS_TIME_AWARE[1], INCIDENTS_TIME_AWARE[2]], [INCIDENTS_TIME_AWARE[3],
                                                                                                      INCIDENTS_TIME_AWARE[4]],
         {'limit': 2, 'time': INCIDENTS_TIME_AWARE[2]['created'], 'found_incident_ids': {2: 1667482800, 3: 1667482800}}),
        ({'limit': 3, 'first_fetch': '2 hours'}, [INCIDENTS_TIME_AWARE[1], INCIDENTS_TIME_AWARE[2], INCIDENTS_TIME_AWARE[3]],
         [INCIDENTS_TIME_AWARE[4]],
         {'limit': 3, 'time': INCIDENTS_TIME_AWARE[3]['created'],
          'found_incident_ids': {2: 1667482800, 3: 1667482800, 4: 1667482800}}),
    ])
    @freeze_time("2022-11-03 13:40:00 UTC")
    def test_regular_fetch(self, mocker, params, result_phase1, result_phase2, expected_last_run):
        """
        Given:
        - Connfiguration fetch parameters (incidents limit and first fetch time)

        When:
        - Running the example fetch incidents

        Then:
        - Ensure the return incidents and LastRun object as expected
        """
        if sys.version_info.major == 2:
            # skip for python 2 - date
            assert True
            return
        time_aware = 'Z' in expected_last_run['time']

        self.LAST_RUN = {}

        mocker.patch.object(dateparser, 'parse', side_effect=self.mock_dateparser)
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'getLastRun', return_value=self.LAST_RUN)
        mocker.patch.object(demisto, 'setLastRun', side_effect=self.set_last_run)

        # Run first fetch
        incidents_phase1 = self.example_fetch_incidents(time_aware)

        assert incidents_phase1 == result_phase1
        assert self.LAST_RUN == expected_last_run

        # Run second fetch
        mocker.patch.object(demisto, 'getLastRun', return_value=self.LAST_RUN)
        incidents_phase2 = self.example_fetch_incidents(time_aware)
        assert incidents_phase2 == result_phase2

    def mock_dateparser(self, date_string, settings):
        time_aware = isinstance(date_string, str) and 'Z' in date_string
        date_format = '%Y-%m-%dT%H:%M:%S' + ('Z' if time_aware else '')
        date_arr = date_string.split(' ')
        if len(date_arr) > 1 and date_arr[0].isdigit():
            return datetime(2022, 4, 1, 11, 0, 0) - timedelta(minutes=int(date_arr[0])) if date_arr[1] == 'minutes' \
                else datetime(2022, 4, 1, 11, 0, 0) - timedelta(hours=int(date_arr[0]))
        return datetime(2022, 4, 1, 11, 0, 0) - (
            datetime(2022, 4, 1, 11, 0, 0) - datetime.strptime(date_string, date_format))

    @pytest.mark.parametrize(
        'params, result_phase1, result_phase2, result_phase3, expected_last_run_phase1, expected_last_run_phase2, new_incidents, index',
        [
            (
                {'limit': 2, 'first_fetch': '50 minutes', 'look_back': 15}, [INCIDENTS[2], INCIDENTS[3]],
                [INCIDENTS[4]], [],
                {'found_incident_ids': {3: '', 4: ''}, 'limit': 4},
                {'found_incident_ids': {3: '', 4: '', 5: ''}, 'limit': 5},
                [NEW_INCIDENTS[0]], 2
            ),
            (
                {'limit': 2, 'first_fetch': '20 minutes', 'look_back': 30}, [INCIDENTS[2], INCIDENTS[3]],
                [NEW_INCIDENTS[1], NEW_INCIDENTS[2]], [INCIDENTS[4]],
                {'found_incident_ids': {3: '', 4: ''}, 'limit': 4},
                {'found_incident_ids': {3: '', 4: '', 7: '', 8: ''}, 'limit': 6},
                [NEW_INCIDENTS[1], NEW_INCIDENTS[2]], 3
            ),
            (
                {'limit': 3, 'first_fetch': '181 minutes', 'look_back': 15},
                [INCIDENTS[0], INCIDENTS[1], INCIDENTS[2]], [INCIDENTS[3], INCIDENTS[4]], [],
                {'found_incident_ids': {1: '', 2: '', 3: ''}, 'limit': 6},
                {'found_incident_ids': {1: '', 2: '', 3: '', 4: '', 5: ''}, 'limit': 8},
                [NEW_INCIDENTS[0]], 2
            ),
            (
                {'limit': 3, 'first_fetch': '181 minutes', 'look_back': 30 * 60},
                [INCIDENTS[0], INCIDENTS[1], INCIDENTS[2]], [NEW_INCIDENTS[0], INCIDENTS[3], INCIDENTS[4]], [],
                {'found_incident_ids': {1: '', 2: '', 3: ''}, 'limit': 6},
                {'found_incident_ids': {1: '', 2: '', 3: '', 4: '', 5: '', 6: ''}, 'limit': 9},
                [NEW_INCIDENTS[0]], 2
            ),

            (
                {'limit': 3, 'first_fetch': '20 minutes', 'look_back': 30},
                [INCIDENTS[2], INCIDENTS[3], INCIDENTS[4]], [NEW_INCIDENTS[1], NEW_INCIDENTS[2]], [],
                {'found_incident_ids': {3: '', 4: '', 5: ''}, 'limit': 6},
                {'found_incident_ids': {3: '', 4: '', 5: '', 7: '', 8: ''}, 'limit': 8},
                [NEW_INCIDENTS[1], NEW_INCIDENTS[2]], 3
            ),

            (
                {'limit': 2, 'first_fetch': '50 minutes', 'look_back': 15}, [INCIDENTS_TIME_AWARE[2], INCIDENTS_TIME_AWARE[3]],
                [INCIDENTS_TIME_AWARE[4]], [],
                {'found_incident_ids': {3: '', 4: ''}, 'limit': 4},
                {'found_incident_ids': {3: '', 4: '', 5: ''}, 'limit': 5},
                [NEW_INCIDENTS_TIME_AWARE[0]], 2
            ),
            (
                {'limit': 2, 'first_fetch': '20 minutes', 'look_back': 30}, [INCIDENTS_TIME_AWARE[2], INCIDENTS_TIME_AWARE[3]],
                [NEW_INCIDENTS_TIME_AWARE[1], NEW_INCIDENTS_TIME_AWARE[2]], [INCIDENTS_TIME_AWARE[4]],
                {'found_incident_ids': {3: '', 4: ''}, 'limit': 4},
                {'found_incident_ids': {3: '', 4: '', 7: '', 8: ''}, 'limit': 6},
                [NEW_INCIDENTS_TIME_AWARE[1], NEW_INCIDENTS_TIME_AWARE[2]], 3
            ),
            (
                {'limit': 3, 'first_fetch': '181 minutes', 'look_back': 15},
                [INCIDENTS_TIME_AWARE[0], INCIDENTS_TIME_AWARE[1], INCIDENTS_TIME_AWARE[2]], [INCIDENTS_TIME_AWARE[3],
                                                                                              INCIDENTS_TIME_AWARE[4]], [],
                {'found_incident_ids': {1: '', 2: '', 3: ''}, 'limit': 6},
                {'found_incident_ids': {1: '', 2: '', 3: '', 4: '', 5: ''}, 'limit': 8},
                [NEW_INCIDENTS_TIME_AWARE[0]], 2
            ),
            (
                {'limit': 3, 'first_fetch': '20 minutes', 'look_back': 30},
                [INCIDENTS_TIME_AWARE[2], INCIDENTS_TIME_AWARE[3], INCIDENTS_TIME_AWARE[4]],
                [NEW_INCIDENTS_TIME_AWARE[1], NEW_INCIDENTS_TIME_AWARE[2]], [],
                {'found_incident_ids': {3: '', 4: '', 5: ''}, 'limit': 6},
                {'found_incident_ids': {3: '', 4: '', 5: '', 7: '', 8: ''}, 'limit': 8},
                [NEW_INCIDENTS_TIME_AWARE[1], NEW_INCIDENTS_TIME_AWARE[2]], 3
            ),
        ])
    def test_fetch_with_look_back(self, mocker, params, result_phase1, result_phase2, result_phase3,
                                  expected_last_run_phase1, expected_last_run_phase2, new_incidents, index):
        """
        Given:
        - Connfiguration fetch parameters (incidents limit, first fetch time and look back)

        When:
        - Running the example fetch incidents and creating new incidents between fetch calles

        Then:
        - Ensure the return incidents and LastRun object as expected
        """
        if sys.version_info.major == 2:
            # skip for python 2 - date
            assert True
            return
        time_aware = 'Z' in result_phase1[0]['created']
        self.LAST_RUN = {}
        incidents = self.INCIDENTS_TIME_AWARE[:] if time_aware else self.INCIDENTS[:]

        mocker.patch.object(CommonServerPython, 'get_current_time', return_value=datetime(2022, 4, 1, 11, 0, 0))
        mocker.patch.object(dateparser, 'parse', side_effect=self.mock_dateparser)
        mocker.patch.object(demisto, 'params', return_value=params)
        mocker.patch.object(demisto, 'getLastRun', return_value=self.LAST_RUN)
        mocker.patch.object(demisto, 'setLastRun', side_effect=self.set_last_run)

        # Run first fetch
        incidents_phase1 = self.example_fetch_incidents(time_aware)

        assert incidents_phase1 == result_phase1
        assert self.LAST_RUN['limit'] == expected_last_run_phase1['limit']
        assert self.LAST_RUN['found_incident_ids'].keys() == expected_last_run_phase1['found_incident_ids'].keys()
        for inc in incidents_phase1:
            assert inc['incident_id'] in self.LAST_RUN['found_incident_ids']

        source_incidents = incidents[:index] + new_incidents + incidents[index:]
        if time_aware:
            self.INCIDENTS_TIME_AWARE = source_incidents
        else:
            self.INCIDENTS = source_incidents
        # Run second fetch
        mocker.patch.object(demisto, 'getLastRun', return_value=self.LAST_RUN)
        incidents_phase2 = self.example_fetch_incidents(time_aware)

        assert incidents_phase2 == result_phase2
        assert self.LAST_RUN['limit'] == expected_last_run_phase2['limit']
        assert self.LAST_RUN['found_incident_ids'].keys() == expected_last_run_phase2['found_incident_ids'].keys()

        assert incidents_phase2[-1]['created'] == self.LAST_RUN['time']

        for inc in incidents_phase2:
            assert inc['incident_id'] in self.LAST_RUN['found_incident_ids']

        # Run third fetch
        mocker.patch.object(demisto, 'getLastRun', return_value=self.LAST_RUN)
        incidents_phase3 = self.example_fetch_incidents(time_aware)

        assert incidents_phase3 == result_phase3

        # Remove new incidents from self.INCIDENTS
        if time_aware:
            self.INCIDENTS_TIME_AWARE = incidents
        else:
            self.INCIDENTS = incidents

    @pytest.mark.parametrize(
        'args1, expected_results1, args2, expected_results2, args3, expected_results3',
        [
            (
                {
                    'incidents': [
                        {'createAt': '2022-04-01T10:11:00', 'id': '1'},
                        {'createAt': '2022-04-01T10:12:00', 'id': '2'},
                        {'createAt': '2022-04-01T10:13:00', 'id': '3'}
                    ],
                    'fetch_limit': 3,
                    'start_fetch_time': '2022-04-01T10:11:00',
                    'end_fetch_time': '2022-04-05T10:11:00',
                    'look_back': 1,
                    'created_time_field': 'createAt',
                    'id_field': 'id',
                    'date_format': '%Y-%m-%dT%H:%M:%S',
                    'increase_last_run_time': True
                },
                {
                    'time': '2022-04-01T10:13:00',
                    'limit': 6,
                    'found_incident_ids': {'1': '', '2': '', '3': ''}
                },
                {
                    'incidents': [
                        {'createAt': '2022-04-02T10:11:00', 'id': '4'},
                        {'createAt': '2022-04-02T10:12:00', 'id': '5'},
                        {'createAt': '2022-04-02T10:13:00', 'id': '6'}
                    ],
                    'fetch_limit': 3,
                    'start_fetch_time': '2022-04-01T10:11:00',
                    'end_fetch_time': '2022-04-06T10:11:00',
                    'look_back': 1,
                    'created_time_field': 'createAt',
                    'id_field': 'id',
                    'date_format': '%Y-%m-%dT%H:%M:%S',
                    'increase_last_run_time': True
                },
                {
                    'time': '2022-04-02T10:13:00',
                    'limit': 9,
                    'found_incident_ids': {'1': '', '2': '', '3': '',
                                           '4': '', '5': '', '6': ''}
                },
                {
                    'incidents': [
                        {'createAt': '2022-04-03T10:11:00', 'id': '7'},
                        {'createAt': '2022-04-03T10:12:00', 'id': '8'},
                        {'createAt': '2022-04-03T10:13:00', 'id': '9'}
                    ],
                    'fetch_limit': 3,
                    'start_fetch_time': '2022-04-01T10:11:00',
                    'end_fetch_time': '2022-04-07T10:11:00',
                    'look_back': 1,
                    'created_time_field': 'createAt',
                    'id_field': 'id',
                    'date_format': '%Y-%m-%dT%H:%M:%S',
                    'increase_last_run_time': True
                },
                {
                    'time': '2022-04-03T10:13:00',
                    'limit': 9,
                    'found_incident_ids': {'1': '', '2': '', '3': '',
                                           '4': '', '5': '', '6': '',
                                           '7': '', '8': '', '9': ''}
                }
            ),
            (
                {
                    'incidents': [
                        {'createAt': '2022-04-01T10:11:00', 'id': '1'},
                        {'createAt': '2022-04-01T10:12:00', 'id': '2'},
                        {'createAt': '2022-04-01T10:13:00', 'id': '3'}
                    ],
                    'fetch_limit': 3,
                    'start_fetch_time': '2022-04-01T10:11:00',
                    'end_fetch_time': '2022-04-05T10:11:00',
                    'look_back': 1,
                    'created_time_field': 'createAt',
                    'id_field': 'id',
                    'date_format': '%Y-%m-%dT%H:%M:%S',
                    'increase_last_run_time': True
                },
                {
                    'time': '2022-04-01T10:13:00',
                    'limit': 6,
                    'found_incident_ids': {'1': '', '2': '', '3': ''}
                },
                {
                    'incidents': [
                        {'createAt': '2022-04-02T10:11:00', 'id': '4'},
                        {'createAt': '2022-04-02T10:12:00', 'id': '5'},
                    ],
                    'fetch_limit': 3,
                    'start_fetch_time': '2022-04-01T10:11:00',
                    'end_fetch_time': '2022-04-06T10:11:00',
                    'look_back': 1,
                    'created_time_field': 'createAt',
                    'id_field': 'id',
                    'date_format': '%Y-%m-%dT%H:%M:%S',
                    'increase_last_run_time': True
                },
                {
                    'time': '2022-04-02T10:12:00',
                    'limit': 8,
                    'found_incident_ids': {'4': '', '5': ''}
                },
                {
                    'incidents': [
                        {'createAt': '2022-04-03T10:11:00', 'id': '7'},
                        {'createAt': '2022-04-03T10:12:00', 'id': '8'},
                        {'createAt': '2022-04-03T10:13:00', 'id': '9'}
                    ],
                    'fetch_limit': 3,
                    'start_fetch_time': '2022-04-02T10:12:00',
                    'end_fetch_time': '2022-04-07T10:11:00',
                    'look_back': 1,
                    'created_time_field': 'createAt',
                    'id_field': 'id',
                    'date_format': '%Y-%m-%dT%H:%M:%S',
                    'increase_last_run_time': True
                },
                {
                    'time': '2022-04-03T10:13:00',
                    'limit': 8,
                    'found_incident_ids': {'4': '', '5': '',
                                           '7': '', '8': '', '9': ''}
                }
            ),
            (
                {
                    'incidents': [
                        {'createAt': '2022-04-01T10:11:00', 'id': '1'},
                        {'createAt': '2022-04-01T10:12:00', 'id': '2'},
                        {'createAt': '2022-04-01T10:13:00', 'id': '3'}
                    ],
                    'fetch_limit': 3,
                    'start_fetch_time': '2022-04-01T10:11:00',
                    'end_fetch_time': '2022-04-05T10:11:00',
                    'look_back': 1,
                    'created_time_field': 'createAt',
                    'id_field': 'id',
                    'date_format': '%Y-%m-%dT%H:%M:%S',
                    'increase_last_run_time': True
                },
                {
                    'time': '2022-04-01T10:13:00',
                    'limit': 6,
                    'found_incident_ids': {'1': '', '2': '', '3': ''}
                },
                {
                    'incidents': [],
                    'fetch_limit': 3,
                    'start_fetch_time': '2022-04-01T10:11:00',
                    'end_fetch_time': '2022-04-06T10:11:00',
                    'look_back': 1,
                    'created_time_field': 'createAt',
                    'id_field': 'id',
                    'date_format': '%Y-%m-%dT%H:%M:%S',
                    'increase_last_run_time': True
                },
                {
                    'time': '2022-04-06T10:11:00',
                    'limit': 3,
                    'found_incident_ids': {'1': '', '2': '', '3': ''}
                },
                {
                    'incidents': [],
                    'fetch_limit': 3,
                    'start_fetch_time': '2022-04-02T10:12:00',
                    'end_fetch_time': '2022-04-07T10:13:00',
                    'look_back': 1,
                    'created_time_field': 'createAt',
                    'id_field': 'id',
                    'date_format': '%Y-%m-%dT%H:%M:%S',
                    'increase_last_run_time': True
                },
                {
                    'time': '2022-04-07T10:13:00',
                    'limit': 3,
                    'found_incident_ids': {'1': '', '2': '', '3': ''}
                }
            )
        ]
    )
    def test_update_last_run_object(self, args1, expected_results1, args2, expected_results2, args3, expected_results3):

        from CommonServerPython import update_last_run_object

        args1.update({'last_run': {}})
        results = update_last_run_object(**args1)

        assert results.get('time') == expected_results1.get('time')
        assert results.get('limit') == expected_results1.get('limit')
        for id_ in results.get('found_incident_ids').keys():
            assert id_ in expected_results1.get('found_incident_ids')

        for id_ in results.get('found_incident_ids'):
            results['found_incident_ids'][id_] = results['found_incident_ids'][id_] - 200
        args2.update({'last_run': results})
        results = update_last_run_object(**args2)

        assert results.get('time') == expected_results2.get('time')
        assert results.get('limit') == expected_results2.get('limit')
        for id_ in results.get('found_incident_ids').keys():
            assert id_ in expected_results2.get('found_incident_ids')

        for id_ in results.get('found_incident_ids'):
            results['found_incident_ids'][id_] = results['found_incident_ids'][id_] - 200
        args3.update({'last_run': results})
        results = update_last_run_object(**args3)

        assert results.get('time') == expected_results3.get('time')
        assert results.get('limit') == expected_results3.get('limit')
        for id_ in results.get('found_incident_ids').keys():
            assert id_ in expected_results3.get('found_incident_ids')

    def test_lookback_with_offset_update_last_run(self):
        """
        Given:
            A last run

        When:
            Calling create_updated_last_run_object with a new offset to change

        Then:
            - The last run is updated with the new offset, and the start time remains as it was.
            - When the offset needs to be reset, the last time is the latest incident time and the offset resets
        """
        from CommonServerPython import create_updated_last_run_object
        last_time = "2022-04-07T10:13:00"
        last_run = {"time": last_time, "offset": 3}
        new_offset = 4
        new_last_run, _ = create_updated_last_run_object(last_run,
                                                         self.INCIDENTS,
                                                         fetch_limit=3,
                                                         look_back=1,
                                                         start_fetch_time=last_time,
                                                         end_fetch_time=datetime.now().isoformat(),
                                                         created_time_field="created",
                                                         new_offset=new_offset,
                                                         )
        # make sure that the start time is unchanged because of the offset, and the offset is updated
        assert new_last_run["offset"] == 4
        assert new_last_run["time"] == last_time

        last_run = {"time": last_time, "offset": new_offset}
        new_offset = 0
        new_last_run, _ = create_updated_last_run_object(last_run,
                                                         self.INCIDENTS,
                                                         fetch_limit=3,
                                                         look_back=1,
                                                         start_fetch_time=last_time,
                                                         end_fetch_time=datetime.now().isoformat(),
                                                         created_time_field="created",
                                                         new_offset=new_offset,
                                                         )
        assert new_last_run["offset"] == 0
        assert new_last_run["time"] == "2022-04-01T10:51:00"

    def test_calculate_new_offset(self):
        """
        Test that the new offset for the next run calculated correctly based on the old offset, number of incidents and total number of incidents.
        The first argument is the old offset, the second is number of incidents and the third is the total number of incidents returned.
        Given:
            old offset, number of incidents, total number of incidents (could be None)

        When:
            Calculating a new offset to the next run

        Then:
            Make sure that the new offset is correct
        """
        from CommonServerPython import calculate_new_offset
        assert calculate_new_offset(0, 2, 4) == 2
        assert calculate_new_offset(0, 2, 2) == 0
        assert calculate_new_offset(0, 2, 3) == 2
        assert calculate_new_offset(1, 2, 4) == 3
        assert calculate_new_offset(1, 2, 3) == 0
        assert calculate_new_offset(1, 2, None) == 3


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


PACK_VERSION_INFO = [
    (
        {'context': {'IntegrationBrand': 'PaloAltoNetworks_PrismaCloudCompute'}, 'integration': True},
        ''
    ),
    (
        {'context': {'ScriptName': 'test-script'}, 'integration': False},
        ''
    ),
    (
        {},
        'test-pack'
    ),
    (
        {'context': {'IntegrationBrand': 'PagerDuty v2'}, 'integration': True},
        ''
    )
]


def get_pack_version_mock_internal_http_request(method, uri, body):
    if method == 'POST':
        if uri == '/contentpacks/marketplace/search':
            if 'integrationsQuery' in body:  # whether its an integration that needs to be searched
                integration_brand = demisto.callingContext.get('context', {}).get('IntegrationBrand')
                if integration_brand == 'PaloAltoNetworks_PrismaCloudCompute':
                    return {
                        'body': '{"packs":[{"currentVersion":"1.0.0","contentItems":'
                                '{"integration":[{"name":"Palo Alto Networks - Prisma Cloud Compute"}]}}]}'
                    }
                elif integration_brand == 'PagerDuty v2':
                    return {
                        'body': '{"packs":[{"currentVersion":"1.0.0","contentItems":'
                                '{"integration":[{"name":"PagerDuty v2"}]}}]}'
                    }
            elif 'automationQuery' in body:  # whether its a script/automation that needs to be searched
                return {
                    'body': '{"packs":[{"currentVersion":"1.0.0",'
                            '"contentItems":{"automation":[{"name":"test-script"}]}}]}'
                }
            else:  # whether its a pack that needs to be searched
                return {
                    'body': '{"packs":[{"currentVersion":"1.0.0","name":"test-pack"}]}'
                }
        if uri == '/settings/integration/search':
            # only used in an integration where the brand/name/id is not equal to the display name
            return {
                'body': '{"configurations":[{"id":"PaloAltoNetworks_PrismaCloudCompute",'
                        '"display":"Palo Alto Networks - Prisma Cloud Compute"}]}'
            }
    return {}


@pytest.mark.parametrize(
    'calling_context_mock, pack_name', PACK_VERSION_INFO
)
def test_get_pack_version(mocker, calling_context_mock, pack_name):
    """
    Given -
        Case1: an integration that its display name is not the same as the integration brand/name/id.
        Case2: a script/automation.
        Case3: a pack name.
        Case4: an integration that its display name is the same as the integration brand/name/id.

    When -
        executing the get_pack_version function.

    Then -
        Case1: the pack version of which the integration is a part of is returned.
        Case2: the pack version of which the script is a part of is returned.
        Case3: the pack version of the requested pack is returned.
        Case4: the pack version of which the integration is a part of is returned.
    """
    from CommonServerPython import get_pack_version
    mocker.patch('demistomock.callingContext', calling_context_mock)
    mocker.patch.object(demisto, 'internalHttpRequest', side_effect=get_pack_version_mock_internal_http_request)
    assert get_pack_version(pack_name=pack_name) == '1.0.0'


TEST_CREATE_INDICATOR_RESULT_WITH_DBOTSCOR_UNKNOWN = [
    (
        {'indicator': 'f4dad67d0f0a8e53d87fc9506e81b76e043294da77ae50ce4e8f0482127e7c12',
         'indicator_type': DBotScoreType.FILE, 'reliability': DBotScoreReliability.A},
        {'instance': Common.File, 'indicator_type': 'SHA256', 'reliability': 'A - Completely reliable'}
    ),
    (
        {'indicator': 'd26cec10398f2b10202d23c966022dce', 'indicator_type': DBotScoreType.FILE,
         'reliability': DBotScoreReliability.B},
        {'instance': Common.File, 'indicator_type': 'MD5', 'reliability': 'B - Usually reliable'}
    ),
    (
        {'indicator': 'd26cec10398f2b10202d23c966022dce', 'indicator_type': DBotScoreType.FILE,
         'reliability': DBotScoreReliability.B},
        {'instance': Common.File, 'indicator_type': 'MD5', 'reliability': 'B - Usually reliable',
         'integration_name': 'test'}
    ),
    (
        {'indicator': 'f4dad67d0f0a8e53d8*****937fc9506e81b76e043294da77ae50ce4e8f0482127e7c12',
         'indicator_type': DBotScoreType.FILE, 'reliability': DBotScoreReliability.A},
        {
            'error_message': 'This indicator -> f4dad67d0f0a8e53d8*****937fc9506e81b76e043294da77ae50ce4e8f0482127e7c12 is incorrect'}
    ),
    (
        {'indicator': '8.8.8.8', 'indicator_type': DBotScoreType.IP},
        {'instance': Common.IP, 'indicator_type': 'IP', 'reliability': None}
    ),
    (
        {'indicator': 'www.google.com', 'indicator_type': DBotScoreType.URL, 'reliability': DBotScoreReliability.A},
        {'instance': Common.URL, 'indicator_type': 'URL', 'reliability': 'A - Completely reliable'}
    ),
    (
        {'indicator': 'google.com', 'indicator_type': DBotScoreType.DOMAIN},
        {'instance': Common.Domain, 'indicator_type': 'DOMAIN', 'reliability': None}
    ),
    (
        {'indicator': 'test@test.com', 'indicator_type': DBotScoreType.ACCOUNT},
        {'instance': Common.Account, 'indicator_type': 'ACCOUNT', 'reliability': None}
    ),
    (
        {'indicator': 'test@test.com', 'indicator_type': DBotScoreType.CRYPTOCURRENCY, 'address_type': 'bitcoin'},
        {'instance': Common.Cryptocurrency, 'indicator_type': 'BITCOIN', 'reliability': None}
    ),
    (
        {'indicator': 'test@test.com', 'indicator_type': DBotScoreType.CERTIFICATE},
        {'instance': Common.Certificate, 'indicator_type': 'CERTIFICATE', 'reliability': None}
    ),
    (
        {'indicator': 'test@test.com', 'indicator_type': 'test', 'context_prefix': 'test'},
        {'instance': Common.CustomIndicator, 'indicator_type': 'TEST', 'reliability': None}
    ),
    (
        {'indicator': 'test@test.com', 'indicator_type': 'test'},
        {'error_message': 'Indicator type is invalid'}
    ),
    (
        {'indicator': 'test@test.com', 'indicator_type': DBotScoreType.CRYPTOCURRENCY},
        {'error_message': 'Missing address_type parameter'}
    ),
    (
        {'indicator': 'test@test.com', 'indicator_type': DBotScoreType.CVE},
        {'error_message': 'DBotScoreType.CVE is unsupported'}
    )
]


@pytest.mark.parametrize('args, expected', TEST_CREATE_INDICATOR_RESULT_WITH_DBOTSCOR_UNKNOWN)
def test_create_indicator_result_with_dbotscore_unknown(mocker, args, expected):
    from CommonServerPython import create_indicator_result_with_dbotscore_unknown

    if expected.get('integration_name'):
        mocker.patch('CommonServerPython.Common.DBotScore',
                     return_value=Common.DBotScore(indicator=args['indicator'],
                                                   indicator_type=args['indicator_type'],
                                                   score=0,
                                                   integration_name=expected['integration_name'],
                                                   reliability=args['reliability'],
                                                   message='No results found.'))
    try:
        results = create_indicator_result_with_dbotscore_unknown(**args)
    except ValueError as e:
        assert str(e) == expected['error_message']
        return

    assert expected['indicator_type'] in results.readable_output
    assert isinstance(results.indicator, expected['instance'])
    assert results.indicator.dbot_score.score == 0
    assert results.indicator.dbot_score.reliability == expected['reliability']
    assert results.indicator.dbot_score.message == 'No results found.'

    if expected.get('integration_name'):
        assert expected['integration_name'] in results.readable_output
    else:
        assert 'Results:' in results.readable_output


@pytest.mark.parametrize('content_format,outputs,expected_type', ((None, {}, 'json'),
                                                                  (None, 'foo', 'text'),
                                                                  (None, 1, 'text'),
                                                                  ('html', '', 'html'),
                                                                  ('html', {}, 'html')))
def test_content_type(content_format, outputs, expected_type):
    from CommonServerPython import CommandResults
    command_results = CommandResults(
        outputs=outputs,
        readable_output='human_readable',
        outputs_prefix='prefix',
        content_format=content_format,
    )
    assert command_results.to_context()['ContentsFormat'] == expected_type


class TestSendEventsToXSIAMTest:
    with open('test_data/events.json') as f:
        test_data = json.load(f)
    events_test_log_data = EVENTS_LOG_ERROR
    assets_test_log_data = ASSETS_LOG_ERROR
    orig_xsiam_file_size = 2 ** 20  # 1Mib

    @staticmethod
    def get_license_custom_field_mock(arg):
        if 'token' in arg:
            return "TOKEN"
        elif 'url' in arg:
            return "url"

    @pytest.mark.parametrize('data_use_case, data_type', [
        ('json_events', 'events'),
        ('text_list_events', 'events'),
        ('text_events', 'events'),
        ('cef_events', 'events'),
        ('json_zero_events', 'events'),
        ('big_event', 'events'),
        ('json_assets', 'assets'),
    ])
    def test_send_data_to_xsiam_positive(self, mocker, data_use_case, data_type):
        """
        Test for the fetch events and fetch assets function
        Given:
            Case a: a list containing dicts representing events.
            Case b: a list containing strings representing events.
            Case c: a string representing events (separated by a new line).
            Case d: a string representing events (separated by a new line).
            Case e: an empty list of events.
            Case f: a "big" event. a big event is bigger than XSIAM EVENT SIZE declared.
            Case g: a list containing dicts representing assets.
            ( currently the Ideal event size is 1 Mib)

        When:
            Case a: Calling the send_assets_to_xsiam function with no explicit data format specified.
            Case b: Calling the send_assets_to_xsiam function with no explicit data format specified.
            Case c: Calling the send_assets_to_xsiam function with no explicit data format specified.
            Case d: Calling the send_assets_to_xsiam function with a cef data format specification.
            Case e: Calling the send_assets_to_xsiam function with no explicit data format specified.
            Case f: Calling the send_assets_to_xsiam function with no explicit data format specified.
            Case g: Calling the send_assets_to_xsiam function with no explicit data format specified.

        Then ensure that:
            Case a:
                - The events data was compressed correctly
                - The data format was automatically identified as json.
                - The number of events reported to the module health equals to number of events sent to XSIAM - 2
            Case b:
                - The events data was compressed correctly
                - The data format was automatically identified as text.
                - The number of events reported to the module health equals to number of events sent to XSIAM - 2
            Case c:
                - The events data was compressed correctly
                - The data format was automatically identified as text.
                - The number of events reported to the module health equals to number of events sent to XSIAM - 2
            Case d:
                - The events data was compressed correctly
                - The data format remained as cef.
                - The number of events reported to the module health equals to number of events sent to XSIAM - 2
            Case e:
                - No request to XSIAM API was made.
                - The number of events reported to the module health - 0.
            Case f:
                - The events data was compressed correctly. Expecting to see that last chunk sent.
                - The data format remained as json.
                - The number of events reported to the module health - 2. For the last chunk.
            Case g:
                - The assets data was compressed correctly
                - The data format was automatically identified as json.
                - The number of assets reported to the module health equals to number of assets sent to XSIAM - 2
        """
        if not IS_PY3:
            return

        from CommonServerPython import BaseClient
        from requests import Response
        mocker.patch.object(demisto, 'getLicenseCustomField', side_effect=self.get_license_custom_field_mock)
        mocker.patch.object(demisto, 'updateModuleHealth')
        mocker.patch('time.time', return_value=123)

        api_response = Response()
        api_response.status_code = 200
        api_response._content = json.dumps({'error': 'false'}).encode('utf-8')

        _http_request_mock = mocker.patch.object(BaseClient, '_http_request', return_value=api_response)

        items = self.test_data[data_use_case][data_type]
        number_of_items = self.test_data[data_use_case]['number_of_events']  # pushed in each chunk.
        chunk_size = self.test_data[data_use_case].get('XSIAM_FILE_SIZE', self.orig_xsiam_file_size)
        data_format = self.test_data[data_use_case].get('format')
        send_data_to_xsiam(data=items, vendor='some vendor', product='some product', data_format=data_format,
                           chunk_size=chunk_size, data_type=data_type)

        if number_of_items:
            expected_format = self.test_data[data_use_case]['expected_format']
            expected_data = self.test_data[data_use_case]['expected_data']
            arguments_called = _http_request_mock.call_args[1]
            decompressed_data = gzip.decompress(arguments_called['data']).decode("utf-8")

            assert arguments_called['headers']['format'] == expected_format
            assert decompressed_data == expected_data
            assert arguments_called['headers']['collector-type'] == data_type
        else:
            assert _http_request_mock.call_count == 0
        if data_type == "events":
            demisto.updateModuleHealth.assert_called_with({'eventsPulled': number_of_items})
        elif data_type == "assets":
            demisto.updateModuleHealth.assert_called_with({'assetsPulled': number_of_items})
            assert arguments_called['headers']['snapshot-id'] == '123000'
            assert arguments_called['headers']['total-items-count'] == '2'

    @pytest.mark.parametrize('data_type, snapshot_id, items_count, expected', [
        ('assets', None, None, {'snapshot_id': '123000', 'items_count': '2'}),
        ('assets', '12345', 25, {'snapshot_id': '12345', 'items_count': '25'})
    ])
    def test_send_data_to_xsiam_custom_snapshot_id_and_items_count(self, mocker, data_type, snapshot_id, items_count, expected):
        """
        Test the send_data_to_xsiam with and without custom snapshot_id and items_count
        Given:
            Case a: no custom snapshot_id and items_count.
            Case b: custom snapshot_id and items_count.

        When:
            Case a: Calling the send_assets_to_xsiam function without custom snapshot_id and items_count.
            Case b: Calling the send_assets_to_xsiam function with custom snapshot_id and items_count.

        Then ensure that:
            Case a: The headers was set with the default data.
            Case b: The headers was set with the custom data
        """
        if not IS_PY3:
            return

        from CommonServerPython import BaseClient
        from requests import Response
        mocker.patch.object(demisto, 'getLicenseCustomField', side_effect=self.get_license_custom_field_mock)
        mocker.patch.object(demisto, 'updateModuleHealth')
        mocker.patch('time.time', return_value=123)

        api_response = Response()
        api_response.status_code = 200
        api_response._content = json.dumps({'error': 'false'}).encode('utf-8')

        _http_request_mock = mocker.patch.object(BaseClient, '_http_request', return_value=api_response)

        items = self.test_data['json_assets'][data_type]
        send_data_to_xsiam(data=items, vendor='some vendor', product='some product', data_type=data_type, snapshot_id=snapshot_id,
                           items_count=items_count)

        arguments_called = _http_request_mock.call_args[1]
        assert arguments_called['headers']['collector-type'] == data_type
        assert arguments_called['headers']['snapshot-id'] == expected['snapshot_id']
        assert arguments_called['headers']['total-items-count'] == expected['items_count']

    @pytest.mark.parametrize('error_msg, data_type', [(None, "events"), ({'error': 'error'}, "events"), ('', "events"),
                                                      ({'error': 'error'}, "assets")])
    def test_send_data_to_xsiam_error_handling(self, mocker, requests_mock, error_msg, data_type):
        """
        Given:
            case a: response type containing None
            case b: response type containing json
            case c: response type containing empty string

        When:
            calling the send_data_to_xsiam function

        Then:
            case a:
                - DemistoException is raised with the empty response message
                - Error log is created with the empty response message and status code of 403
                - Make sure only single api request was sent and that retry mechanism was not triggered
            case b:
                - DemistoException is raised with the Unauthorized[401] message
                - Error log is created with Unauthorized[401] message and status code of 401
                - Make sure only single api request was sent and that retry mechanism was not triggered
            case c:
                - DemistoException is raised with the empty response message
                - Error log is created with the empty response message and status code of 403
                - Make sure only single api request was sent and that retry mechanism was not triggered

        """
        if not IS_PY3:
            return

        mocker.patch.object(demisto, "params", return_value={"url": "www.test_url.com"})
        mocker.patch.object(demisto, "callingContext", {"context": {"IntegrationInstance": "test_integration_instance",
                                                                    "IntegrationBrand": "test_brand"}})
        mocker.patch('time.time', return_value=123)
        if isinstance(error_msg, dict):
            status_code = 401
            request_mocker = requests_mock.post(
                'https://api-url/logs/v1/xsiam', json=error_msg, status_code=status_code, reason='Unauthorized[401]'
            )
            expected_error_msg = 'Unauthorized[401]'
        else:
            status_code = 403
            request_mocker = requests_mock.post('https://api-url/logs/v1/xsiam', text=None, status_code=status_code)
            expected_error_msg = 'Received empty response from the server'

        mocker.patch.object(demisto, 'getLicenseCustomField', side_effect=self.get_license_custom_field_mock)
        mocker.patch.object(demisto, 'updateModuleHealth')
        error_log_mocker = mocker.patch.object(demisto, 'error')

        events = self.test_data['json_events']['events']
        expected_request_and_response_info = self.events_test_log_data if data_type == "events" else self.assets_test_log_data
        expected_error_header = 'Error sending new {data_type} into XSIAM.\n'.format(data_type=data_type)

        with pytest.raises(
            DemistoException,
            match=re.escape(expected_error_header + expected_error_msg),
        ):
            send_data_to_xsiam(data=events, vendor='some vendor', product='some product', data_type=data_type)

        # make sure the request was sent only once and retry mechanism was not triggered
        assert request_mocker.call_count == 1

        error_log_mocker.assert_called_with(
            expected_request_and_response_info.format(status_code=str(status_code), error_received=expected_error_msg))

    @pytest.mark.parametrize(
        'mocked_responses, expected_request_call_count, expected_error_log_count, should_succeed', [
            (
                [
                    (429, None), (429, None), (429, None)
                ],
                3,
                1,
                False
            ),
            (
                [
                    (401, None)
                ],
                1,
                1,
                False
            ),
            (
                [
                    (429, None), (429, None), (200, json.dumps({'error': 'false'}).encode('utf-8'))
                ],
                3,
                0,
                True
            ),
            (
                [
                    (429, None), (200, json.dumps({'error': 'false'}).encode('utf-8'))
                ],
                2,
                0,
                True
            ),
            (
                [
                    (200, json.dumps({'error': 'false'}).encode('utf-8'))
                ],
                1,
                0,
                True
            )
        ]
    )
    def test_retries_send_data_to_xsiam_rate_limit(
        self, mocker, mocked_responses, expected_request_call_count, expected_error_log_count, should_succeed
    ):
        """
        Given:
            case a: 3 responses indicating about api limit from xsiam (429)
            case b: 2 responses indicating about unauthorized access from xsiam (401)
            case c: 2 responses indicating about api limit from xsiam (429) and the third indicating about success
            case d: 1 response indicating about api limit from xsiam (429) and the second indicating about success
            case e: 1 response indicating about success from xsiam with no rate limit errors

        When:
            calling the send_data_to_xsiam function

        Then:
            case a:
                - DemistoException is raised
                - Error log is called 1 time
                - Make sure 3 api requests were sent by the retry mechanism
            case b:
                - DemistoException is raised
                - Error log is called 1 time
                - Make sure only 1 api request were sent by the retry mechanism
            case c:
                - Error log is not called at all
                - Make sure only 3 api requests were sent by the retry mechanism
            case d:
                - EError log is not called at all
                - Make sure only 2 api requests were sent by the retry mechanism
            case e:
                - Error log is not called at all
                - Make sure only 1 api request were sent by the retry mechanism

        """
        if not IS_PY3:
            return

        import requests
        mocked_responses_side_effect = []
        for status_code, text in mocked_responses:
            api_response = requests.Response()
            api_response.status_code = status_code
            api_response._content = text
            mocked_responses_side_effect.append(api_response)

        request_mock = mocker.patch.object(requests.Session, 'request', side_effect=mocked_responses_side_effect)

        mocker.patch.object(demisto, 'getLicenseCustomField', side_effect=self.get_license_custom_field_mock)
        mocker.patch.object(demisto, 'updateModuleHealth')
        error_mock = mocker.patch.object(demisto, 'error')

        events = self.test_data['json_events']['events']
        if should_succeed:
            send_data_to_xsiam(data=events, vendor='some vendor', product='some product')
        else:
            with pytest.raises(DemistoException):
                send_data_to_xsiam(data=events, vendor='some vendor', product='some product')

        assert error_mock.call_count == expected_error_log_count
        assert request_mock.call_count == expected_request_call_count


class TestIsMetricsSupportedByServer:
    @classmethod
    @pytest.fixture(scope='function', autouse=True)
    def clear_cache(cls):
        get_demisto_version._version = None

    def test_metrics_supported(self, mocker):
        """
        Given: An XSOAR server running version 6.8.0
        When: Testing that a server supports ExecutionMetrics
        Then: Assert that is_supported reports True
        """
        from CommonServerPython import ExecutionMetrics
        mocker.patch.object(
            demisto,
            'demistoVersion',
            return_value={
                'version': '6.8.0',
                'buildNumber': '50000'
            }
        )
        mock_metrics = ExecutionMetrics()

        # XSOAR version is 7.0.0 and should be supported. Assert that it is.
        assert mock_metrics.is_supported() is True

    def test_metrics_are_not_supported(self, mocker):
        """
        Given: An XSOAR server running version 1.0.0
        When: Testing that a server does not support ExecutionMetrics
        Then: Assert that is_supported reports False
        """
        from CommonServerPython import ExecutionMetrics

        # XSOAR version is not supported.
        mocker.patch.object(
            demisto,
            'demistoVersion',
            return_value={
                'version': '1.0.0',
                'buildNumber': '50000'
            }
        )
        mock_metrics = ExecutionMetrics()
        # XSOAR version is 1.0.0 and should not be supported. Assert that it isn't.
        assert mock_metrics.is_supported() is False


def test_collect_execution_metrics():
    """
    Given:
        An ExecutionMetrics object -
            Case 1 - Reports a successful metric
            Case 2 - Reports a quota error metric
            Case 3 - Reports multiple quota error metrics
    When:
        Case 1 - Testing that a success metric has been reported
        Case 2 - Testing that a quota metric has been reported
        Case 3 - Testing that multiple quota errors have been reported
    Then:
        Case 1 - Assert that there is one successful metric and that the entry is an ExecutionMetrics entry
        Case 2 - Assert that there is a quota error added to the metric report and is contained in the ExecutionMetrics entry
        Case 3 - Assert that there are 26 total quota errors that are contained in the ExecutionMetrics entry
    """
    from CommonServerPython import ExecutionMetrics

    mock_metrics = ExecutionMetrics()

    # Report Successful Metrics
    mock_metrics.success += 1

    # Collect Metrics
    collected_metrics = mock_metrics.metrics

    expected_command_results = {'APIExecutionMetrics': [{'APICallsCount': 1, 'Type': 'Successful'}],
                                'Contents': 'Metrics reported successfully.',
                                'ContentsFormat': 'text',
                                'EntryContext': {},
                                'HumanReadable': None,
                                'IgnoreAutoExtract': False,
                                'IndicatorTimeline': [],
                                'Note': False,
                                'Relationships': [],
                                'Type': 19}

    # Assert collected metrics are correct
    assert collected_metrics.to_context() == expected_command_results

    # Report Quota Error
    mock_metrics.quota_error += 1

    # Update Test Bank
    expected_command_results['APIExecutionMetrics'].append({'APICallsCount': 1, 'Type': 'QuotaError'})

    # Assert collected metrics are correct
    assert collected_metrics.to_context() == expected_command_results

    # Report multiple metrics
    mock_metrics.quota_error += 25

    # Update Test Bank
    expected_command_results['APIExecutionMetrics'][1]['APICallsCount'] = 26

    # Assert collected metrics are correct
    assert collected_metrics.to_context() == expected_command_results


def test_is_scheduled_command_retry(mocker):
    """
    Given:
        Test Case 1 - A command's metadata indicates it is scheduled.
        Test Case 2 - A command's metadata indicates it is not scheduled.
    When:
        Test Case 1 - Checking if a command is scheduled or not.
        Test Case 2 - Checking if a command is scheduled or not.
    Then:
        Test Case 1 - Assert the function returns True
        Test Case 2 - Assert the function returns False
    """
    from CommonServerPython import is_scheduled_command_retry

    mock_scheduled_command = {
        'polling': True,
        'pollingCommand': 'SomeCommand',
        'pollingArgs': {'some': 'args'},
        'timesRan': 0,
        'startDate': '5.4.2022',
        'endingDate': '1.2.2022'
    }

    mocker.patch.dict(demisto.callingContext, {'context': {'ParentEntry': mock_scheduled_command}})
    mocker.patch.object(CommonServerPython, 'get_integration_name', return_value='')

    # The run should be considered a scheduled command
    assert is_scheduled_command_retry() is True

    # Change run to not be a scheduled command
    mock_scheduled_command['polling'] = False

    # The run should not be considered a scheduled command
    assert is_scheduled_command_retry() is False


def test_append_metrics(mocker):
    """

    Given: CommandResults list and Execution_metrics object to be added to the list.
    When: Metrics need to be added after reputation commands ran.
    Then: Metrics added as the last object of the list.

    """
    mocker.patch.object(ExecutionMetrics, 'is_supported', return_value=True)
    metrics = ExecutionMetrics()
    results = []
    metrics.success += 1

    results = CommonServerPython.append_metrics(metrics, results)
    assert len(results) == 1


def test_convert_dict_values_bytes_to_str():
    """
    Given:
        Dictionary contains bytes objects

    When:
        Creating outputs for commands

    Then:
        assert all bytes objects have been converted to strings
    """

    input_dict = {'some_key': b'some_value',
                  'some_key1': [b'some_value'],
                  'some_key2': {'some_key': [b'some_value'],
                                'some_key1': b'some_value'}
                  }
    expected_output_dict = {'some_key': 'some_value',
                            'some_key1': ['some_value'],
                            'some_key2': {'some_key': ['some_value'],
                                          'some_key1': 'some_value'}
                            }
    actual_output = convert_dict_values_bytes_to_str(input_dict)
    assert actual_output == expected_output_dict


@pytest.mark.parametrize(
    'filename',
    ['/test', '\\test', ',test', ':test', 't/est.pdf', '../../test.xslx', '~test.png']
)
def test_is_valid_filename_faild(filename):
    """
    Given:
        Filename.
    When:
        Checking if the filename is invalid
    Then:
        Test - Assert the function returns Exception
    """
    assert is_filename_valid(filename=filename) is False


@pytest.mark.parametrize(
    'filename',
    ['test', 'test.txt', 'test.xslx', 'Test', 'טסט', 'test-test.pdf', 'test test.md']
)
def test_is_valid_filename(filename):
    """
    Given:
        Filename.
    When:
        Checking if the filename is invalid
    Then:
        Test - Assert the function does not raise an Exception
    """
    assert is_filename_valid(filename)


TEST_REPLACE_SPACES_IN_CREDENTIAL = [
    (
        'TEST test TEST', 'TEST test TEST'
    ),
    (
        '-----BEGIN SSH CERTIFICATE----- MIIF7z gdwZcx IENpdH -----END SSH CERTIFICATE-----',
        '-----BEGIN SSH CERTIFICATE-----\nMIIF7z\ngdwZcx\nIENpdH\n-----END SSH CERTIFICATE-----'
    ),
    (
        '-----BEGIN RSA PRIVATE KEY----- MIIF7z gdwZcx IENpdH -----END RSA PRIVATE KEY-----',
        '-----BEGIN RSA PRIVATE KEY-----\nMIIF7z\ngdwZcx\nIENpdH\n-----END RSA PRIVATE KEY-----'
    ),
    (
        '-----BEGIN RSA PRIVATE KEY----- MIIF7z gdwZcx IENpdH',
        '-----BEGIN RSA PRIVATE KEY----- MIIF7z gdwZcx IENpdH'
    ),
    (
        None, None
    ),
    (
        '', ''
    )
]


@pytest.mark.parametrize('credential, expected', TEST_REPLACE_SPACES_IN_CREDENTIAL)
def test_replace_spaces_in_credential(credential, expected):
    """
    Given:
        Credential with spaces.
    When:
        Running replace_spaces_in_credential function.
    Then:
        Test - Assert the function not returning as expected.
    """
    from CommonServerPython import replace_spaces_in_credential

    result = replace_spaces_in_credential(credential)
    assert result == expected


TEST_RESPONSE_TO_CONTEXT_DATA = [
    (
        {"id": "111"}, {"ID": "111"}, {}
    ),
    (
        {"test": [1]}, {"Test": [1]}, {}
    ),
    (
        {"test1": [{'test2': "val"}]}, {"Test1": [{'Test2': "val"}]}, {}
    ),
    (
        {"test1": {'test2': "val"}}, {"Test1": {'Test2': "val"}}, {}
    ),
    (
        [{"test1": {'test2': "val"}}], [{"Test1": {'Test2': "val"}}], {}
    ),
    (
        "test", "test", {}
    ),
    (
        {"test_func": "test"}, {"TestFunc": "test"}, {}
    ),
    (
        {"testid": "test"}, {"TestID": "test"}, {"testid": "TestID"}
    ),
    (
        {"testid": "test", "id": "test_id", "test": "test_val"}, {"TestID": "test", "ID": "test_id", "Test": "test_val"},
        {"testid": "TestID"}
    )
]


@pytest.mark.parametrize('response, expected_results, user_predefiend_keys', TEST_RESPONSE_TO_CONTEXT_DATA)
def test_response_to_context(response, expected_results, user_predefiend_keys):
    """
    Given:
        A response and user_predefiend_keys dict.
        Case 1: a response dict with a key "id".
        Case 2: a response dict with a list as a value.
        Case 3: a response dict with a list of dicts as a value.
        Case 4: a response dict with a dict as a value.
        Case 5: a response list.
        Case 6: a response string.
        Case 7: a response dict with a key with underscore.
        Case 8: a response dict and a user_predefiend_keys dict,
                where the key of the response dict is in the user_predefiend_keys dict.
        Case 9: a response dict with 3 keys and a user_predefiend_keys dict,
                where one key of the response dict is in the user_predefiend_keys dict.
                where one key of the response dict is in the predefined_keys dict.
                where one key of the response is not in any predefined dict.
    When:
        Running response_to_context function.
    Then:
        Test - Assert the function created the dict formatted succesfuly.
        Case 1: Should transfom key to "ID".
        Case 2: Should attempt to transform only the dict key.
        Case 3: Should attempt to transform only the dict inside the list.
        Case 4: Should attempt to transform both the given dict key and the keys of the nested dict.
        Case 5: Should modify the dict inside the list.
        Case 6: Should return the input as is.
        Case 7: Should remove the underscore and capitalize the first letters of both words.
        Case 8: Should change the key according to the user_predefiend_keys dict.
        Case 9: Should change the first key according to the user_predefiend_keys dict,
                the second key according to predefined_keys, and the third regularly.
    """
    assert response_to_context(response, user_predefiend_keys) == expected_results


class TestIsIntegrationCommandExecution:
    def test_with_script_exec(self, mocker):
        mocker.patch.object(demisto, 'callingContext', {'context': {'ExecutedCommands': [{'moduleBrand': 'Scripts'}]}})
        assert is_integration_command_execution() == False

    def test_with_integration_exec(self, mocker):
        mocker.patch.object(demisto, 'callingContext', {'context': {'ExecutedCommands': [{'moduleBrand': 'some-integration'}]}})
        assert is_integration_command_execution() == True

    data_test_problematic_cases = [
        None, 1, [], {}, {'context': {}}, {'context': {'ExecutedCommands': None}},
        {'context': {'ExecutedCommands': []}}, {'context': {'ExecutedCommands': [None]}},
        {'context': {'ExecutedCommands': [{}]}}
    ]

    @pytest.mark.parametrize('calling_context_mock', data_test_problematic_cases)
    def test_problematic_cases(self, mocker, calling_context_mock):
        mocker.patch.object(demisto, 'callingContext', calling_context_mock)
        assert is_integration_command_execution() == True


@pytest.mark.parametrize("timestamp_str, seconds_threshold, expected", [
    ("2019-01-01T00:00:00Z", 60, True),
    ("2022-01-01T00:00:00GMT+1", 60, True),
    ("2022-01-01T00:00:00Z", 60, False),
    ("invalid", 60, ValueError)
])
def test_has_passed_time_threshold__different_timestamps(timestamp_str, seconds_threshold, expected, mocker):
    """
    Given:
        A timestamp string and a seconds threshold.
    When:
        Running has_passed_time_threshold function.
    Then:
        Test - Assert the function returns the expected result.
        Case 1: The timestamp is in the past.
        Case 2: Though the timestamp appears identical, it is in a different timezone, so the time passed the threshold.
        Case 3: The timestamp did not pass the threshold.
        Case 4: The timestamp is invalid.
    """
    from CommonServerPython import has_passed_time_threshold
    mocker.patch('CommonServerPython.datetime', autospec=True)
    mocker.patch.object(CommonServerPython.datetime, 'now', return_value=datetime(2022, 1, 1, 0, 0, 0, tzinfo=pytz.utc))
    if expected == ValueError:
        with pytest.raises(expected) as e:
            has_passed_time_threshold(timestamp_str, seconds_threshold)
        assert str(e.value) == "Failed to parse timestamp: invalid"
    else:
        assert has_passed_time_threshold(timestamp_str, seconds_threshold) == expected


@pytest.mark.parametrize("indicator,expected_result", [
    ("e61fcc6a06420106fa6642ef833b9c38", "md5"),
    ("3fec1b14cea32bbcd97fad4507b06888", "md5"),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
    ("bb8098f4627441f6a29c31757c45339c74b2712b92783173df9ab58d47ae3bfa", "sha256"),
    ("193:iAklVz3fzvBk5oFblLPBN1iXf2bCRErwyN4aEbwyiNwyiQwNeDAi4XMG:iAklVzfzvBTFblLpN1iXOYpyuapyiWym", "ssdeep"),
    ("3:Wg8oEIjOH9+KS3qvRBTdRi690oVqzBUGyT0/n:Vx0HgKnTdE6eoVafY8", "ssdeep"),
    ("1ff8be1766d9e16b0b651f89001e8e7375c9e71f", "sha1"),
    ("6c5360d41bd2b14b1565f5b18e5c203cf512e493", "sha1"),
    (
        "eaf7542ade2c338d8d2cc76fcbf883e62c31336e60cb236f86ed66c8154ea9fb836fd88367880911529bdafed0e76cd34272123a4d656db61b120b95eaa3e069",
        "sha512"),
    (
        "a7c19471fb4f2b752024246c28a37127ea7475148c04ace743392334d0ecc4762baf30b892d6a24b335e1065b254166f905fc46cc3ba5dba89e757bb7023a211",
        "sha512"),
    ("@", None)
])
def test_detect_file_indicator_type(indicator, expected_result):
    """
    Given:
        An indicator string.
    When:
        Running detect_file_indicator_type function.
    Then:
        Test - Assert the function returns the expected result.
        Case 1: md5 indicator type.
        Case 2: sha256 indicator type.
        Case 3: ssdeep indicator type.
        Case 4: sha1 indicator type.
        Case 5: sha512 indicator type.
        Case 6: invalid type.
    """
    from CommonServerPython import detect_file_indicator_type
    assert detect_file_indicator_type(indicator) == expected_result


def test_create_clickable_url():
    """
    Given:
        One URL and one text.
    When:
        Running create_clickable_url function.
    Then:
        Assert the function returns the expected result.
            A URL with different text than the link.
    """
    from CommonServerPython import create_clickable_url
    assert create_clickable_url('https://example.com', 'click here') == '[click here](https://example.com)'


def test_create_clickable_url_one_url_without_text():
    """
    Given:
        One URL.
    When:
        Running create_clickable_url function.
    Then:
        Assert the function returns the expected result.
            A clickable URL with the same text as the link.
    """
    from CommonServerPython import create_clickable_url
    assert create_clickable_url('https://example.com', None) == '[https://example.com](https://example.com)'


def test_create_clickable_url_list_of_urls_with_list_of_text():
    """
    Given:
        A list of URLs and a list of texts.
    When:
        Running create_clickable_url function.
    Then:
        Assert the function returns the expected result.
            A list of URLs with different texts than the links.
    """
    from CommonServerPython import create_clickable_url
    expected = ['[click here1](https://example1.com)', '[click here2](https://example2.com)']
    assert create_clickable_url(['https://example1.com', 'https://example2.com'], ['click here1', 'click here2']) == expected


def test_create_clickable_url_list_of_urls_without_text():
    """
    Given:
        A list of URLs without text.
    When:
        Running create_clickable_url function.
    Then:
        Assert the function returns the expected result.
            A list URLs without texts as the links.
    """
    from CommonServerPython import create_clickable_url
    expected = ['[https://example1.com](https://example1.com)', '[https://example2.com](https://example2.com)']
    assert create_clickable_url(['https://example1.com', 'https://example2.com'], None) == expected


def test_create_clickable_test_wrong_text_value():
    """
    Given:
        A list of links and texts (not in teh same length).
    When:
        Running create_clickable_url function.
    Then:
        Assert the function returns the expected error.
    """
    from CommonServerPython import create_clickable_url
    with pytest.raises(AssertionError) as e:
        assert create_clickable_url(['https://example1.com', 'https://example2.com'], ['click here1'])

    assert e.type == AssertionError
    assert 'The URL list and the text list must be the same length.' in e.value.args


@pytest.mark.parametrize("request_log, expected_output", [
    (
        "send: b'GET /api/v1/users HTTP/1.1\\r\\nHost: example.com\\r\\nmy_authorization: Bearer token123\\r\\n'",
        "send: b'GET /api/v1/users HTTP/1.1\\r\\nHost: example.com\\r\\nmy_authorization: Bearer <XX_REPLACED>\\r\\n'"
    ),
    (
        "send: b'GET /api/v1/users HTTP/1.1\\r\\nHost: example.com\\r\\nSet_Cookie: session_id=123\\r\\n'",
        "send: b'GET /api/v1/users HTTP/1.1\\r\\nHost: example.com\\r\\nSet_Cookie: <XX_REPLACED>\\r\\n'"
    ),
    (
        "send: b'GET /api/v1/users HTTP/1.1\\r\\nHost: example.com\\r\\nAuthorization: token123\\r\\n'",
        "send: b'GET /api/v1/users HTTP/1.1\\r\\nHost: example.com\\r\\nAuthorization: <XX_REPLACED>\\r\\n'"
    ),
    (
        "GET /api/v1/users HTTP/1.1\\r\\nHost: example.com\\r\\nAuthorization: Bearer token123\\r\\n",
        "GET /api/v1/users HTTP/1.1\\r\\nHost: example.com\\r\\nAuthorization: Bearer <XX_REPLACED>\\r\\n"
    ),
    (
        "GET /api/v1/users HTTP/1.1\\r\\nHost: example.com\\r\\nAuthorization: JWT token123\\r\\n",
        "GET /api/v1/users HTTP/1.1\\r\\nHost: example.com\\r\\nAuthorization: JWT <XX_REPLACED>\\r\\n"
    ),
    (
        "send: b'GET /api/v1/users HTTP/1.1\\r\\nHost: example.com\\r\\n'",
        str("send: b'GET /api/v1/users HTTP/1.1\\r\\nHost: example.com\\r\\n'")
    ),
    (
        "send: b'GET /api/v1/users HTTP/1.1\\r\\nHost: example.com\\r\\apiKey: 1234\\r\\n'",
        "send: b'GET /api/v1/users HTTP/1.1\\r\\nHost: example.com\\r\\apiKey: <XX_REPLACED>\\r\\n'"
    ),
    (
        "send: b'GET /api/v1/users HTTP/1.1\\r\\nHost: example.com\\r\\credentials: {'good':'day'}\\r\\n'",
        "send: b'GET /api/v1/users HTTP/1.1\\r\\nHost: example.com\\r\\credentials: <XX_REPLACED>\\r\\n'"
    ),
    (
        "send: b'GET /api/v1/users HTTP/1.1\\r\\nHost: example.com\\r\\client_name: client\\r\\n'",
        "send: b'GET /api/v1/users HTTP/1.1\\r\\nHost: example.com\\r\\client_name: <XX_REPLACED>\\r\\n'"
    ),],
    ids=["Bearer", "Cookie", "Authorization", "Bearer", "JWT", "No change", "Key", "credential", "client"],)
def test_censor_request_logs(request_log, expected_output):
    """
    Given:
        A request log.
        case 1: A request log with a sensitive data under the 'Authorization' header, but the 'Authorization' is not capitalized and within a string.
        case 2: A request log with a sensitive data under the 'Cookie' header, but with a 'Set_Cookie' prefix.
        case 3: A request log with a sensitive data under the 'Authorization' header, but with no 'Bearer' prefix.
        case 4: A request log with a sensitive data under the 'Authorization' header, but with no 'send b' prefix at the beginning.
        case 5: A request log with no sensitive data.
    When:
        Running censor_request_logs function.
    Then:
        Assert the function returns the exactly same log with the sensitive data masked. 
    """
    assert censor_request_logs(request_log) == expected_output


@pytest.mark.parametrize("request_log", [
    ('send: hello\n'),
    ('header: Authorization\n')
])
def test_logger_write__censor_request_logs_has_been_called(mocker, request_log):
    """
    Given:
        A request log that starts with 'send' or 'header' that may contains sensitive data.
    When:
        Running logger.write function when using debug-mode.
    Then:
        Assert the censor_request_logs function has been called.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'credentials': {'password': 'my_password'},
    })
    mocker.patch.object(demisto, 'info')
    mocker.patch('CommonServerPython.is_debug_mode', return_value=True)
    mock_censor = mocker.patch('CommonServerPython.censor_request_logs')
    mocker.patch('CommonServerPython.IntegrationLogger.build_curl')
    ilog = IntegrationLogger()
    ilog.set_buffering(False)
    ilog.write(request_log)
    assert mock_censor.call_count == 1


def test_replace_send_preffix(mocker):
    """
    Given:
        - A string that contains 'send: b"' in it.
    When:
        - The write function is called to add this string to the logs.
    Then:
        - Verify that the text 'send: b"' has been replaced with "send: b'" to standardize the log format for easier log handling.
    """
    mocker.patch.object(demisto, 'params', return_value={
        'credentials': {'password': 'my_password'},
    })
    mocker.patch.object(demisto, 'info')
    mocker.patch('CommonServerPython.is_debug_mode', return_value=True)
    mock_censor = mocker.patch('CommonServerPython.censor_request_logs')
    mocker.patch('CommonServerPython.IntegrationLogger.build_curl')
    ilog = IntegrationLogger()
    ilog.set_buffering(False)
    ilog.write('send: b"hello\n')
    assert mock_censor.call_args[0][0] == "send: b\'hello"


@freeze_time(datetime(2024, 4, 10, 10, 0, 10))
def test_sleep_exceeds_ttl(mocker):
    """
   Given: a sleep duration exceeding the remaining TTL.

    When: The `sleep` method is called with that duration.

   Then:
    - A warning should be outputed indicating that the requested sleep exceeds the TTL.
  """
    mocker.patch.object(demisto, 'callingContext', {"context": {"runDuration": 5}})
    setattr(CommonServerPython, 'SAFE_SLEEP_START_TIME', datetime(2024, 4, 10, 10, 0, 0))  # Set stub in your_script

    with pytest.raises(ValueError) as excinfo:
        safe_sleep(duration_seconds=350)
    assert str(excinfo.value) == "Requested a sleep of 350 seconds, but time left until docker timeout is 300 seconds."


def test_sleep_not_supported(mocker):
    """
       Given: a sleep duration in not supported server version.

        When: The `sleep` method is called with that duration.

       Then:
        - A warning should be outputed indicating that the requested sleep exceeds the TTL.
        - Sleep the requested time.
      """
    mocker.patch.object(demisto, 'callingContext', {"context": {}})
    logger_mocker = mocker.patch.object(demisto, 'info')

    sleep_mocker = mocker.patch('time.sleep')

    safe_sleep(duration_seconds=50)

    # Verify sleep duration based on mocked time difference
    assert sleep_mocker.call_count == 1
    assert logger_mocker.call_args[0][0] == "Safe sleep is not supported in this server version, sleeping for the requested time."


def test_sleep_mocked_time(mocker):
    """
    Given:  a method using sleep.

   When:  The `sleep` method is called with a specific duration.

   Then:
    - The sleep duration should be based on the difference between the mocked time calls.
    - No exception should be raised if the sleep duration is within the remaining TTL based on mocked time.
    """

    mocker.patch.object(demisto, 'callingContext', {"context": {"runDuration": 5}})
    setattr(CommonServerPython, 'SAFE_SLEEP_START_TIME', datetime(2024, 4, 10, 10, 0, 0))  # Set stub in your_script
    sleep_mocker = mocker.patch('time.sleep')

    with freeze_time(datetime(2024, 4, 10, 10, 0, 10)):
        safe_sleep(duration_seconds=5)  # Sleep for 5 seconds

    # Advance mocked time by the sleep duration
    with freeze_time(datetime(2024, 4, 10, 10, 0, 25)):
        safe_sleep(duration_seconds=50)

    # Verify sleep duration based on mocked time difference
    assert sleep_mocker.call_count == 2


def test_get_server_config(mocker):
    mock_response = {
        'body': '{"sysConf":{"incident.closereasons":"CustomReason1, CustomReason 2, Foo","versn":40},"defaultMap":{}}\n',
        'headers': {
            'Content-Length': ['104'],
            'X-Xss-Protection': ['1; mode=block'],
            'X-Content-Type-Options': ['nosniff'],
            'Strict-Transport-Security': ['max-age=10886400000000000; includeSubDomains'],
            'Vary': ['Accept-Encoding'],
            'Server-Timing': ['7'],
            'Date': ['Wed, 03 Jul 2010 09:11:35 GMT'],
            'X-Frame-Options': ['DENY'],
            'Content-Type': ['application/json']
        },
        'status': '200 OK',
        'statusCode': 200
    }

    mocker.patch.object(demisto, 'internalHttpRequest', return_value=mock_response)
    server_config = get_server_config()
    assert server_config == {'incident.closereasons': 'CustomReason1, CustomReason 2, Foo', 'versn': 40}


@pytest.mark.skipif(not IS_PY3, reason='test not supported in py2')
def test_get_server_config_fail(mocker):
    mock_response = {
        'body': 'NOT A VALID JSON',
        'headers': {
            'Content-Length': ['104'],
            'X-Xss-Protection': ['1; mode=block'],
            'X-Content-Type-Options': ['nosniff'],
            'Strict-Transport-Security': ['max-age=10886400000000000; includeSubDomains'],
            'Vary': ['Accept-Encoding'],
            'Server-Timing': ['7'],
            'Date': ['Wed, 03 Jul 2010 09:11:35 GMT'],
            'X-Frame-Options': ['DENY'],
            'Content-Type': ['application/json']
        },
        'status': '200 OK',
        'statusCode': 200
    }

    mocker.patch.object(demisto, 'internalHttpRequest', return_value=mock_response)
    mocked_error = mocker.patch.object(demisto, 'error')
    assert get_server_config() == {}
    assert mocked_error.call_args[0][0] == 'Error decoding JSON: Expecting value: line 1 column 1 (char 0)'


@pytest.mark.parametrize('instance_name, expected_result',
                         [('instance_name1', 'engine_id'),
                          ('instance_name2', '')
                          ], ids=[
                              "Test-instanec-with-xsoar-engine-configures",
                              "Test-instanec-without-xsoar-engine-configures"
                         ])
def test_is_integration_instance_running_on_engine(mocker, instance_name, expected_result):
    """ Tests the 'is_integration_instance_running_on_engine' function's logic. 

        Given:  
                1. A name of an instance that has an engine configured (and relevant mocked responses).
                2. A name of an instance that doesn't have an engine configured (and relevant mocked responses).

        When:  
            - Running the 'is_integration_instance_running_on_engine' funcution. 

        Then:
            - Verify that: 
                1. The result is the engine's id. 
                2. The result is an empty string.
    """
    mock_response = {
        'body': """{"instances": [
            {"id": "1111", "name": "instance_name1", "engine": "engine_id"},
            {"id": "2222", "name": "instance_name2", "engine": ""}
        ]}""",
    }
    mocker.patch.object(demisto, 'internalHttpRequest', return_value=mock_response)
    mocker.patch.object(demisto, 'integrationInstance', return_value=instance_name)
    res = is_integration_instance_running_on_engine()
    assert res == expected_result


def test_get_engine_base_url(mocker):
    """ Tests the 'get_engine_base_url' function's logic. 

        Given:  
            - Mocked response of the internalHttpRequest call for the '/engines' endpoint, including 2 engines.
            - An id of an engine. 

        When:  
            - Running the 'is_integration_instance_running_on_engine' funcution. 

        Then:
            - Verify that base url of the given engine id was returened.

    """
    mock_response = {
        'body': """{"engines": [
            {"id": "1111", "baseUrl": "11.111.111.33:443"},
            {"id": "2222", "baseUrl": "11.111.111.44:443"}
        ]}""",
    }
    mocker.patch.object(demisto, 'internalHttpRequest', return_value=mock_response)
    res = get_engine_base_url('1111')
    assert res == '11.111.111.33:443'


@pytest.mark.parametrize('input_text, pattern, expected_output, call_count', [
    pytest.param('invalid_grant: java.security.SignatureException: Invalid signature for token: 1234',
                 r'(token:\s*)(\S+)', '1234', 1, id='Match token value'),
    pytest.param('invalid_grant: java.security.SignatureException: Invalid signature for token: 1234', r'(invalid_grant: java.security.SignatureException: Invalid signature for token: 1234)',
                 'invalid_grant: java.security.SignatureException: Invalid signature for token: 1234', 1, id='Match entire string')
])
def test_find_and_remove_sensitive_text__found_onc(input_text, pattern, expected_output, call_count, mocker):
    """
    Given:
    - Input text that includes sensitive information.

    When:
    - Invoking the `find_and_remove_sensitive_text` method with a regex pattern to search for sensitive information.

    Then:
    - Verify that the function responsible for removing sensitive information from the logs is called with the sensitive data as an argument.
    - Verify that the function is called the correct number of times.

    """
    input_text = 'invalid_grant: java.security.SignatureException: Invalid signature for token: 1234'
    mock_remove_from_logs = mocker.patch('CommonServerPython.add_sensitive_log_strs', return_value=None)
    find_and_remove_sensitive_text(input_text, pattern)

    assert mock_remove_from_logs.call_count == call_count
    assert mock_remove_from_logs.call_args[0][0] == expected_output


@pytest.mark.parametrize('pattern, expected_output, call_count', [
    pytest.param(r'n', ['n', 'n', 'n', 'n', 'n', 'n', 'n'], 7, id='Match character "n"'),
    pytest.param(r'(?i)invalid', ['invalid', 'Invalid'], 2, id='Match word "invalid" case insensitive')
])
def test_find_and_remove_sensitive_text__found_multiple(pattern, expected_output, call_count, mocker):
    """
    Given:
    - Input text that includes sensitive information.

    When:
    - Invoking the `find_and_remove_sensitive_text` method with a regex pattern to search for a sensitive information.

    Then:
        verify that the function responsible for removing sensitive information from the logs is called with the sensitive data as an argument.
        verify that the function is called the correct number of times.
    """
    input_text = 'invalid_grant: java.security.SignatureException: Invalid signature for token: 1234'
    mock_remove_from_logs = mocker.patch('CommonServerPython.add_sensitive_log_strs', return_value=None)
    find_and_remove_sensitive_text(input_text, pattern)
    assert mock_remove_from_logs.call_count == call_count
    for x in range(call_count):
        assert mock_remove_from_logs.call_args_list[x][0][0] == expected_output[x]


def test_find_and_remove_sensitive_text__not_found(mocker):
    """
    Given:
    - Input text that does not contain any sensitive information (e.g., no word following "token:").

    When:
    - Invoking the `find_and_remove_sensitive_text` method with a regex pattern to search for a sensitive information (the word following "token:").

    Then:
    - Ensure that the function does not remove anything from the logs.
    """

    input_text = 'invalid_grant: java.security.SignatureException: Invalid signature for text: 1234'
    mock_remove_from_logs = mocker.patch('CommonServerPython.add_sensitive_log_strs', return_value=None)
    find_and_remove_sensitive_text(input_text, r'(token:\s*)(\S+)')

    mock_remove_from_logs.assert_not_called()
