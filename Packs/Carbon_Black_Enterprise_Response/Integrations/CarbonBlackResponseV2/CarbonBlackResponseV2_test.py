"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io
import pytest


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


QUERY_STRING_CASES = [
    (
        {'hostname': 'ec2amaz-l4c2okc', 'query': 'chrome.exe'},  # case both query and params
        'chrome.exe'  # expected
    ),
    (
        {'hostname': 'ec2amaz-l4c2okc'},  # case only params
        'hostname:ec2amaz-l4c2okc'  # expected
    ),
    (
        {'query': 'chrome.exe'},  # case only query
        'chrome.exe'  # expected
    )
]


@pytest.mark.parametrize('params,expected_results', QUERY_STRING_CASES)
def test_create_query_string(params, expected_results):
    """
    Given:
        - A search task's parameters

    When:
        - running commands using filter arguments

    Then:
        - validating the query string containing the params

    """
    from CarbonBlackResponseV2 import _create_query_string

    query_string = _create_query_string(params)

    assert query_string == expected_results


def test_fail_create_query_string():
    """
    Given:
        - En empty dictionary of params

    When:
        - running commands using filter arguments

    Then:
        - validating the function fails

    """
    from CarbonBlackResponseV2 import _create_query_string
    with pytest.raises(Exception) as e:
        _create_query_string({})
    assert str(e.value) == 'Search without any filter is not permitted.'


PARSE_FIELD_CASES = [
    ('x.x.x.x,06d3d4a5ba28|', ',', 1, '|', '06d3d4a5ba28'),
    ('06d3d4a5ba28|', ',', 0, '|', '06d3d4a5ba28'),
    ('06d3d4a5ba28^&*', ',', 0, '&^*', '06d3d4a5ba28'),
]


@pytest.mark.parametrize('field, sep, index_after_split, chars_to_remove, expected', PARSE_FIELD_CASES)
def test_parse_field(field, sep, index_after_split, chars_to_remove, expected):
    """
        Given:
            - A field with x.x.x.x,y| format

        When:
            - running Endpoints command

        Then:
            - validate only the ip returns
        """
    from CarbonBlackResponseV2 import _parse_field
    res = _parse_field(field, sep, index_after_split, chars_to_remove)
    assert res == expected


@pytest.mark.parametrize('isolation_activated, is_isolated, expected',
                         [(0, 1, 'Pending unisolation'), (0, 0, 'No'), (1, 0, 'Pending isolation'), (1, 1, 'Yes')])
def test_get_isolation_status_field(isolation_activated, is_isolated, expected):
    """
    Given:
        - A sensor isolation configuration

    When:
        - getting/ setting isolation status for a sensor

    Then:
        - validate status according to API.
    """
    from CarbonBlackResponseV2 import _get_isolation_status_field
    status = _get_isolation_status_field(isolation_activated, is_isolated)
    assert status == expected


''' ProcessEventDetail Tests'''

FILEMOD_CASES = [
    (
        "1|2013-09-16 07:11:58.000000|test_path.dll|||false",
        {'operation type': 'Created the file', 'event time': '2013-09-16 07:11:58.000000',
         'file path': 'test_path.dll', 'md5 of the file after last write': '', 'file type': '',
         'flagged as potential tamper attempt': 'false'}
    )
]
FILEMOD_BAD_CASES = [
    (
        "1|2013-09-16 07:11:58.000000|test_path.dll||false",
        "Data from API is in unexpected format."
    )
]


@pytest.mark.parametrize('data_str, expected', FILEMOD_CASES)
def test_filemod(data_str, expected):
    from CarbonBlackResponseV2 import filemod_complete

    res = filemod_complete(data_str).format()
    assert res == expected


@pytest.mark.parametrize('data_str, expected', FILEMOD_BAD_CASES)
def test_fail_filemod(data_str, expected):
    from CarbonBlackResponseV2 import filemod_complete
    with pytest.raises(Exception) as e:
        filemod_complete(data_str)
    assert str(e.value) == expected


MODLOAD_CASES = [
    (
        '2013-09-19 22:07:07.000000|f404e59db6a0f122ab26bf4f3e2fd0fa|test_path.dll',
        {'event time': '2013-09-19 22:07:07.000000', 'MD5 of the loaded module': 'f404e59db6a0f122ab26bf4f3e2fd0fa',
         'Full path of the loaded module': 'test_path.dll'}
    )
]


@pytest.mark.parametrize('data_str, expected', MODLOAD_CASES)
def test_modload(data_str, expected):
    from CarbonBlackResponseV2 import modload_complete

    res = modload_complete(data_str).format()
    assert res == expected


REGMOD_CASES = [
    (
        "2|2013-09-19 22:07:07.000000|test_path",
        {'operation type': 'First wrote to the file', 'event time': '2013-09-19 22:07:07.000000',
         'the registry key path': 'test_path'}
    )
]


@pytest.mark.parametrize('data_str, expected', REGMOD_CASES)
def test_regmod(data_str, expected):
    from CarbonBlackResponseV2 import regmod_complete

    res = regmod_complete(data_str).format()
    assert res == expected


CROSSPROC_CASES = [
    (
        "ProcessOpen|2014-01-23 09:19:08.331|00000177-0000-0258-01cf-c209d9f1c431|204f3f58212b3e422c90bd9691a2df28|"
        "test_path.exe|1|2097151|false",
        {'type of cross-process access': 'ProcessOpen', 'event time': '2014-01-23 09:19:08.331',
         'unique_id of the targeted process': '00000177-0000-0258-01cf-c209d9f1c431',
         'md5 of the targeted process': '204f3f58212b3e422c90bd9691a2df28',
         'path of the targeted process': 'test_path.exe', 'sub-type for ProcessOpen': 'handle open to process',
         'requested access priviledges': '2097151', 'flagged as potential tamper attempt': 'false'}
    )
]


@pytest.mark.parametrize('data_str, expected', CROSSPROC_CASES)
def test_crossproc(data_str, expected):
    from CarbonBlackResponseV2 import crossproc_complete

    res = crossproc_complete(data_str).format()
    assert res == expected


''' COMMANDS TESTS '''
CLIENT = {"base_url": "example.com",
          "apitoken": "apikey",
          "use_ssl": False,
          "use_proxy": False}


PROCESS_SEARCH_CASES = [
    (
        {'query': 'chrome.exe', 'facet': False}, 2
    ),
]


@pytest.mark.parametrize('args, expected', PROCESS_SEARCH_CASES)
def test_processes_search_command(mocker, args, expected):
    from CarbonBlackResponseV2 import Client, processes_search_command
    client = Client(**CLIENT)
    mock_res = util_load_json('test_data/commands_test_data.json')
    mocker.patch.object(Client, '_http_request', return_value=mock_res.get('processes_search_command'))
    res = processes_search_command(client, **args)
    assert len(res.outputs.get('Results', [])) == expected
