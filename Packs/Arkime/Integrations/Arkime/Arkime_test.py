import json
import io
from typing import Callable

import pytest
from requests.auth import HTTPDigestAuth
from requests.models import Response

from Arkime import Client, PAGE_SIZE_ERROR_MSG, LENGTH_ERROR_MSG
from CommonServerPython import *


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def util_load_csv(path):
    with open(path, 'r') as f:
        lines = f.read()
    the_response = Response()
    the_response._content = str.encode(lines)
    return the_response


def util_load_txt_to_json(path):
    with open(path) as f:
        lines = f.read()
    the_response = Response()
    the_response._content = str.encode(lines)
    return the_response


# ----------------------------------------- COMMAND FUNCTIONS TESTS ---------------------------
HEADERS = {'Content-Type': 'application/json'}


@pytest.fixture
def arkime_client():
    auth = HTTPDigestAuth('username', 'password')

    return Client(server_url='https://www.example.com', verify=True, proxy=False, headers=HEADERS, auth=auth)


def test_connection_csv_get_command(mocker, arkime_client):
    """
    Given:
        - An app client object
        - Relevant arguments
    When:
        - arkime-connection-csv-get command is executed
    Then:
        - The http request is called with the right arguments
        - Ensure the output's type is INFO_FILE
    """
    from Arkime import connection_csv_get_command

    http_request = mocker.patch.object(arkime_client, '_http_request',
                                       return_value=util_load_csv('test_data/connection_csv_get.csv'))

    args = {'start_time': '1648817940',
            'stop_time': '1649595540',
            }
    import Arkime
    mocker.patch.object(Arkime, 'fileResult', return_value={'Type': EntryType.ENTRY_INFO_FILE})
    res = connection_csv_get_command(arkime_client, **args)

    params = {'date': 1,
              'startTime': '1648817940',
              'stopTime': '1649595540',
              }

    http_request.assert_called_with('POST', 'api/connections/csv', params=params, headers=HEADERS, resp_type='response')

    assert res['Type'] == EntryType.ENTRY_INFO_FILE


def test_connection_list_command_with_default_start(mocker, arkime_client):
    """
    Given:
        - An app client object
        - Relevant arguments
    When:
        - arkime-connection-list command is executed
    Then:
        - The http request is called with the right arguments
        - Ensure the readable outputs is a list of connections in the correct format
    """
    from Arkime import connection_list_command

    http_request = mocker.patch.object(arkime_client, '_http_request',
                                       return_value=util_load_json('test_data/connection_list.json'))
    args = {'baseline_date': '720',
            'start_time': '1648817940',
            'stop_time': '1649595540',
            }

    res = connection_list_command(arkime_client, **args)

    params = {'baselineDate': '720',
              'date': 1,
              'startTime': '1648817940',
              'stopTime': '1649595540',
              }

    http_request.assert_called_with('POST', 'api/connections', params=params, headers=HEADERS)

    assert res.readable_output == '### Connection Results:\n' \
                                  '|Source IP|Count|Sessions|Node|\n' \
                                  '|---|---|---|---|\n' \
                                  '| 1.1.1.1 | 1 | 2 | localhost |\n'


def test_pcap_file_list_command(mocker, arkime_client):
    """
    Given:
        - An app client object
        - Relevant arguments
    When:
        - arkime-pcap-file-list command is executed
    Then:
        - The http request is called with the right arguments
        - Ensure the readable outputs is a list of pcap files in the correct format
    """
    from Arkime import pcap_file_list_command

    http_request = mocker.patch.object(arkime_client, '_http_request',
                                       return_value=util_load_json('test_data/pcap_file_list.json'))

    res = pcap_file_list_command(arkime_client, limit=1)

    params = {'length': 1,
              'start': 0,
              }

    http_request.assert_called_with('GET', 'api/files', params=params, headers=HEADERS)

    assert res.readable_output == ('Showing 1 results, limit=1\n'
                                   '### Files List Result:\n'
                                   '|Node|Name|Number|First|File Size|Packet Size|\n'
                                   '|---|---|---|---|---|---|\n'
                                   '| localhost | /opt/arkime/raw/localhost-220523-00000280.pcap | 280 | '
                                   '1970-01-20 03:15:31 | 2147483898 | 2147483898 |\n')


def test_session_list_command(mocker, arkime_client):
    """
    Given:
        - An app client object
        - Relevant arguments
    When:
        - arkime-session-list command is executed
    Then:
        - The http request is called with the right arguments
        - Ensure the readable output is a list of sessions in the correct format
    """
    from Arkime import session_list_command

    http_request = mocker.patch.object(arkime_client, '_http_request',
                                       return_value=util_load_json('test_data/session_list.json'))

    res = session_list_command(arkime_client, start_time='1650190238', stop_time='1650363038')

    params = {'date': 1,
              'length': 100,
              'start': 0,
              'startTime': '1650190238',
              'stopTime': '1650363038'}

    http_request.assert_called_with('POST', 'api/sessions', params=params, headers=HEADERS)

    assert res.readable_output == ('Showing 1 results, limit=100\n'
                                   '### Session List Result:\n'
                                   '|ID|IP Protocol|Start Time|Stop Time|Source IP|Source Port|Destination IP|'
                                   'Destination Port|Node|\n'
                                   '|---|---|---|---|---|---|---|---|---|\n'
                                   '| 3@220417-Yg7OpiE4Pi1PFaRqu8lztuA6 | 6 | 2022-04-14 07:26:39 | 2022-04-17 10:15:31'
                                   ' | 192.168.1.130 | 22 | 192.168.1.88 | 41096 | localhost |\n')


def test_session_csv_get_command(mocker, arkime_client):
    """
    Given:
        - An app client object
        - Relevant arguments
    When:
        - arkime-session-csv-get command is executed
    Then:
        - The http request is called with the right arguments
        - Ensure the output's type is INFO_FILE
    """
    from Arkime import sessions_csv_get_command

    http_request = mocker.patch.object(arkime_client, '_http_request',
                                       return_value=util_load_csv('test_data/sessions_list.csv'))

    args = {'start_time': '1650190238',
            'stop_time': '1650363038',
            }

    import Arkime
    mocker.patch.object(Arkime, 'fileResult', return_value={'Type': EntryType.ENTRY_INFO_FILE})
    res = sessions_csv_get_command(arkime_client, **args)

    params = {'date': 1,
              'length': 100,
              'start': 0,
              'startTime': '1650190238',
              'stopTime': '1650363038',
              }

    http_request.assert_called_with('POST', 'api/sessions/csv', params=params, headers=HEADERS, resp_type='response')

    assert res['Type'] == EntryType.ENTRY_INFO_FILE


def test_session_pcap_get_command(mocker, arkime_client):
    """
    Given:
        - An app client object
        - Relevant arguments
    When:
        - arkime-session-pcap-get command is executed
    Then:
        - The http request is called with the right arguments
        - Ensure the output's type is INFO_FILE
    """
    from Arkime import sessions_pcap_get_command

    http_request = mocker.patch.object(arkime_client, '_http_request',
                                       return_value=util_load_txt_to_json('test_data/raw_session_data.pcap'))

    args = {'start_time': '1648817940',
            'stop_time': '1649595540',
            'ids': '220516-QHSdz21pJ_xCtJGoL8mbmyNv',
            }

    import Arkime
    mocker.patch.object(Arkime, 'fileResult', return_value={'Type': EntryType.ENTRY_INFO_FILE})
    res = sessions_pcap_get_command(arkime_client, **args)

    params = {
        'startTime': '1648817940',
        'stopTime': '1649595540',
        'ids': '220516-QHSdz21pJ_xCtJGoL8mbmyNv',
    }

    http_request.assert_called_with('GET', 'api/sessions/pcap', params=params, headers=HEADERS, resp_type='response')

    assert res['Type'] == EntryType.ENTRY_INFO_FILE


def test_spigraph_get_command(mocker, arkime_client):
    """
    Given:
        - An app client object
        - Relevant arguments
    When:
        - arkime-spigraph-get command is executed
    Then:
        - The http request is called with the right arguments
        - Ensure the output's type is INFO_FILE
    """
    from Arkime import spigraph_get_command

    http_request = mocker.patch.object(arkime_client, '_http_request',
                                       return_value=util_load_json('test_data/spi_graph.json'))
    args = {'start_time': '1648817940',
            'stop_time': '1649595540',
            'field': '220516-QHSdz21pJ_xCtJGoL8mbmyNv',
            }

    import Arkime
    mocker.patch.object(Arkime, 'fileResult', return_value={'Type': EntryType.ENTRY_INFO_FILE})
    res = spigraph_get_command(arkime_client, **args)

    params = {
        'startTime': '1648817940',
        'stopTime': '1649595540',
        'ids': '220516-QHSdz21pJ_xCtJGoL8mbmyNv',
        'date': 1,
    }

    http_request.assert_called_with('POST', 'api/spigraph', params=params, headers=HEADERS)

    assert res['Type'] == EntryType.ENTRY_INFO_FILE


def test_spiview_get_command(mocker, arkime_client):
    """
    Given:
        - An app client object
        - Relevant arguments
    When:
        - arkime-spiview-get command is executed
    Then:
        - The http request is called with the right arguments
        - Ensure the output's type is INFO_FILE
    """
    from Arkime import spiview_get_command

    http_request = mocker.patch.object(arkime_client, '_http_request',
                                       return_value=util_load_json('test_data/spi_view.json'))

    args = {'start_time': '1650868312',
            'spi': 'destination.ip:100',
            'date': 2,
            }

    import Arkime
    mocker.patch.object(Arkime, 'fileResult', return_value={'Type': EntryType.ENTRY_INFO_FILE})
    res = spiview_get_command(arkime_client, **args)

    params = {
        'startTime': '1650868312',
        'spi': 'destination.ip:100',
        'date': 2,
        'bounding': ['last'],
        'strictly': False,
    }

    http_request.assert_called_with('POST', 'api/spiview', params=params, headers=HEADERS)

    assert res['Type'] == EntryType.ENTRY_INFO_FILE


def test_field_list_command(mocker, arkime_client):
    """
    Given:
        - An app client object
        - Relevant arguments
    When:
        - arkime-field-list command is executed
    Then:
        - The http request is called with the right arguments
        - Ensure the readable outputs a list of fields in the correct format
    """
    from Arkime import fields_list_command

    http_request = mocker.patch.object(arkime_client, '_http_request',
                                       return_value=util_load_json('test_data/field_list.json'))

    res = fields_list_command(arkime_client)

    params = {'array': False}

    http_request.assert_called_with('GET', 'api/fields', params=params, headers=HEADERS)

    assert res.readable_output == ('### Fields Results:\n'
                                   '|Friendly Name|Type|Group|Help|DB Field|\n'
                                   '|---|---|---|---|---|\n'
                                   '|  |  |  |  |  |\n'
                                   '')


def test_unique_field_list_command(mocker, arkime_client):
    """
    Given:
        - An app client object
        - Relevant arguments
    When:
        - arkime-unique-field-list command is executed
    Then:
        - The http request is called with the right arguments
        - Ensure the readable output is a list of unique field values in the correct format
    """
    from Arkime import unique_field_list_command

    http_request = mocker.patch.object(arkime_client, '_http_request',
                                       return_value=util_load_txt_to_json('test_data/unique_field_list.txt'))

    args = {'counts': '1',
            'expression_field_names': 'dns.ASN',
            }

    res = unique_field_list_command(arkime_client, args)

    params = {'bounding': ['last'],
              'counts': 0,
              'date': 1,
              'exp': {'counts': '1', 'expression_field_names': 'dns.ASN'},
              'strictly': False}

    http_request.assert_called_with('POST', 'api/unique', params=params, headers=HEADERS, resp_type='response')

    assert res.readable_output == ('Showing 4 results, limit=50\n'
                                   '### Unique Field Results:\n'
                                   '|Field|Count|\n'
                                   '|---|---|\n'
                                   '| AS15169 GOOGLE |  758 |\n'
                                   '| AS396982 GOOGLE-CLOUD-PLATFORM |  293 |\n'
                                   '| AS16509 AMAZON-02 |  133 |\n'
                                   '| AS8075 MICROSOFT-CORP-MSN-AS-BLOCK |  130 |\n'
                                   '')


def test_multi_unique_field_list_command(mocker, arkime_client):
    """
    Given:
        - An app client object
        - Relevant arguments
    When:
        - arkime-multi-unique-field-list command is executed
    Then:
        - The http request is called with the right arguments
        - Ensure the readable output is an intersection of unique field values in the correct format
    """
    from Arkime import multi_unique_field_list_command

    http_request = mocker.patch.object(arkime_client, '_http_request',
                                       return_value=util_load_txt_to_json('test_data/unique_field_list.txt'))

    args = {'counts': '1',
            'expression_field_names': 'dns.ASN',
            }

    res = multi_unique_field_list_command(arkime_client, args)

    params = {'bounding': ['last'],
              'counts': 0,
              'date': 1,
              'exp': {'counts': '1', 'expression_field_names': 'dns.ASN'},
              'strictly': False}

    http_request.assert_called_with('POST', 'api/multiunique', params=params, headers=HEADERS, resp_type='response')

    assert res.readable_output == ('Showing 4 results, limit=50\n'
                                   '### Unique Field Results:\n'
                                   '|Field|Count|\n'
                                   '|---|---|\n'
                                   '| AS15169 GOOGLE |  758 |\n'
                                   '| AS396982 GOOGLE-CLOUD-PLATFORM |  293 |\n'
                                   '| AS16509 AMAZON-02 |  133 |\n'
                                   '| AS8075 MICROSOFT-CORP-MSN-AS-BLOCK |  130 |\n'
                                   '')


def test_session_tag_add_command(mocker, arkime_client):
    """
    Given:
        - An app client object
        - Relevant arguments
    When:
        - arkime-session-tag-add command is executed
    Then:
        - The http request is called with the right arguments
        - Ensure the readable output is correct,
         'success' - Whether the add tags operation was successful,
         'text' - The success/error message to (optionally) display to the user
    """
    from Arkime import session_tag_add_command

    http_request = mocker.patch.object(arkime_client, '_http_request',
                                       return_value=util_load_json('test_data/session_tag_add.json'))

    args = {'segments': ['no'],
            'ids': '220516-QHSdz21pJ_xCtJGoL8mbmyNv',
            'tags': 'deletethistag',
            }

    res = session_tag_add_command(arkime_client, args)

    params = {'segments': ['no'],
              'bounding': ['last'],
              'date': 1,
              'strictly': False,
              'tags': {'ids': '220516-QHSdz21pJ_xCtJGoL8mbmyNv',
                       'segments': ['no'],
                       'tags': 'deletethistag'}
              }

    http_request.assert_called_with('POST', 'api/sessions/addtags', json_data=params, headers=HEADERS)

    assert res.readable_output == ('### Session Tag Results:\n'
                                   '|Success|Text|\n'
                                   '|---|---|\n'
                                   '| false | Missing token |\n')


def test_session_tag_remove_command(mocker, arkime_client):
    """
    Given:
        - An app client object
        - Relevant arguments
    When:
        - arkime-session-tag-remove command is executed
    Then:
        - The http request is called with the right arguments
        - Ensure the readable output is correct,
         'success' - Whether the add tags operation was successful,
         'text' - The success/error message to (optionally) display to the user
    """
    from Arkime import session_tag_remove_command

    http_request = mocker.patch.object(arkime_client, '_http_request',
                                       return_value=util_load_json('test_data/session_tag_remove.json'))

    args = {'segments': ['no'],
            'ids': '220516-QHSdz21pJ_xCtJGoL8mbmyNv',
            'tags': 'deletethistag',
            }

    res = session_tag_remove_command(arkime_client, args)

    params = {'segments': ['no'],
              'bounding': ['last'],
              'date': 1,
              'strictly': False,
              'tags': {'ids': '220516-QHSdz21pJ_xCtJGoL8mbmyNv',
                       'segments': ['no'],
                       'tags': 'deletethistag'}
              }

    http_request.assert_called_with('POST', 'api/sessions/removetags', json_data=params, headers=HEADERS)

    assert res.readable_output == ('### Session Tag Results:\n'
                                   '|Success|Text|\n'
                                   '|---|---|\n'
                                   '| true | Tags removed successfully |\n')


# ----------------------------------------- HELPER FUNCTIONS TESTS  ---------------------------

page_size_in_range = (50, 50)
page_size_validness_valid_input = [page_size_in_range]


@pytest.mark.parametrize('page_size, page_size_expected', page_size_validness_valid_input)
def test_page_size_validness_for_valid_input(page_size: int, page_size_expected: int):
    from Arkime import page_size_validness
    assert page_size_validness(page_size) == page_size_expected


page_size_above_range = (150, PAGE_SIZE_ERROR_MSG)
page_size_below_range = (-1, PAGE_SIZE_ERROR_MSG)

page_size_validness_invalid_input = [page_size_above_range, page_size_below_range]


@pytest.mark.parametrize('page_size, exception_msg_expected', page_size_validness_invalid_input)
def test_page_size_validness_for_invalid_input(page_size: int, exception_msg_expected: str):
    from Arkime import page_size_validness
    with pytest.raises(DemistoException) as e:
        page_size_validness(page_size)
    assert e.value.message == exception_msg_expected


response_without_Histo = (dict(items=[
    {
        "name": "localhost",
        "count": 3527811,
        "map": {},
    }
], map={}, recordsTotal=6420810, recordsFiltered=3527811), {"items": [{
    "name": "localhost",
    "count": 3527811,
    "map": {},
}], "map": {}, "recordsTotal": 6420810, "recordsFiltered": 3527811})
response_with_Histo = (dict(items=[
    {
        "name": "localhost",
        "count": 3527811,
        "graph": {
            "xmin": 1648817940000,
            "xmax": 1649595540000,
            "interval": 3600,
            "sessionsHisto": [
                [
                    1648911600000,
                    11967
                ],
                [
                    1648915200000,
                    26527
                ],
            ],
            "sessionsTotal": 3527811,
            "source.packetsHisto": [
                [
                    1648911600000,
                    237763
                ],
                [
                    1648915200000,
                    498464
                ],
            ],
            "destination.packetsHisto": [
                [
                    1648911600000,
                    282884
                ],
                [
                    1648915200000,
                    567752
                ],
            ],
            "network.packetsTotal": 150692542,
            "source.bytesHisto": [
                [
                    1648911600000,
                    42048340
                ],
                [
                    1648915200000,
                    77687566
                ],
            ],
            "destination.bytesHisto": [
                [
                    1648911600000,
                    116097823
                ],
                [
                    1648915200000,
                    238375971
                ],
            ],
            "network.bytesTotal": 45699563388,
            "client.bytesHisto": [
                [
                    1648911600000,
                    4365402
                ],
                [
                    1648915200000,
                    12113797
                ],
            ],
            "server.bytesHisto": [
                [
                    1648911600000,
                    79323099
                ],
                [
                    1648915200000,
                    163262642
                ],
            ],
            "totDataBytesTotal": 26114638647
        },
        "map": {},
        "sessionsHisto": 3527811,
        "source.packetsHisto": 72514612,
        "destination.packetsHisto": 78177930,
        "source.bytesHisto": 12403293350,
        "destination.bytesHisto": 33296270038,
        "client.bytesHisto": 2660012416,
        "server.bytesHisto": 23454626231,
        "network.packetsHisto": 150692542,
        "totDataBytesHisto": 26114638647,
        "network.bytesHisto": 45699563388
    }], graph={
    "xmin": 1648817940000,
    "xmax": 1649595540000,
    "interval": 3600,
    "sessionsHisto": [
        [
            1648911600000,
            11967
        ],
        [
            1648915200000,
            26527
        ],
    ],
    "sessionsTotal": 3527811,
    "source.packetsHisto": [
        [
            1648911600000,
            237763
        ],
        [
            1648915200000,
            498464
        ],
    ],
    "destination.packetsHisto": [
        [
            1648911600000,
            282884
        ],
        [
            1648915200000,
            567752
        ],
    ],
    "network.packetsTotal": 150692542,
    "source.bytesHisto": [
        [
            1648911600000,
            42048340
        ],
        [
            1648915200000,
            77687566
        ],
    ],
    "destination.bytesHisto": [
        [
            1648911600000,
            116097823
        ],
        [
            1648915200000,
            238375971
        ],
    ],
    "network.bytesTotal": 45699563388,
    "client.bytesHisto": [
        [
            1648911600000,
            4365402
        ],
        [
            1648915200000,
            12113797
        ],
    ],
    "server.bytesHisto": [
        [
            1648911600000,
            79323099
        ],
        [
            1648915200000,
            163262642
        ],
    ],
    "totDataBytesTotal": 26114638647
}, map={}, recordsTotal=6420810, recordsFiltered=3527811), {"items": [{
    "name": "localhost",
    "count": 3527811,
    "graph": {
        "xmin": 1648817940000,
        "xmax": 1649595540000,
        "interval": 3600,
        "sessionsTotal": 3527811,
        "network.packetsTotal": 150692542,
        "network.bytesTotal": 45699563388,
        "totDataBytesTotal": 26114638647
    },
    "map": {},
}], "graph": {
    "xmin": 1648817940000,
    "xmax": 1649595540000,
    "interval": 3600,
    "sessionsTotal": 3527811,
    "network.packetsTotal": 150692542,
    "network.bytesTotal": 45699563388,
    "totDataBytesTotal": 26114638647}, "map": {}, "recordsTotal": 6420810, "recordsFiltered": 3527811})
remove_all_keys_endswith_histo_input = [response_without_Histo, response_with_Histo]


@pytest.mark.parametrize('response, updated_response', remove_all_keys_endswith_histo_input)
def test_remove_all_keys_endswith_histo(response: dict, updated_response: dict):
    from Arkime import remove_all_keys_endswith_histo
    assert remove_all_keys_endswith_histo(response) == updated_response


length_in_range = (50, 1000, 50)
length_validness_valid_input = [length_in_range]


@pytest.mark.parametrize('length, max_length, expected_length', length_validness_valid_input)
def test_length_validness_for_valid_input(length: int, max_length: int, expected_length: int):
    from Arkime import length_validness
    assert length_validness(length, max_length) == expected_length


length_above_max = (150, 100, LENGTH_ERROR_MSG.format(max_length=100))
negative_length = (-1, 0, LENGTH_ERROR_MSG.format(max_length=0))

length_validness_invalid_input = [length_above_max, negative_length]


@pytest.mark.parametrize('length, max_length, exception_msg_expected', length_validness_invalid_input)
def test_length_validness_for_invalid_input(length: int, max_length: int, exception_msg_expected: str):
    from Arkime import length_validness
    with pytest.raises(DemistoException) as e:
        length_validness(length, max_length)
    assert e.value.message == exception_msg_expected


# page_number_input, page_size_input -> start, length, page_number, page_size
page_number_and_page_size = (2, 30, 60, 30, 2, 30)

calculate_offset_and_limit_input = [page_number_and_page_size]


@pytest.mark.parametrize('page_number_input, page_size_input, start, length, page_number, page_size',
                         calculate_offset_and_limit_input)
def test_calculate_offset_and_limit(page_number_input: int, page_size_input: int, start: int, length: int,
                                    page_number: int, page_size: int):
    from Arkime import calculate_offset_and_limit
    assert calculate_offset_and_limit(page_number_input, page_size_input) == (start, length, page_number, page_size)


def request_method_helper(length: int, start: int) -> dict:
    return {'first_field': 'a',
            'second_field': ['a'],
            'third_field': {'a': {1: None}},
            }


only_one_response = (request_method_helper, 500, 0,
                     {'first_field': 'a',
                      'second_field': ['a'],
                      'third_field': {'a': {1: None}}
                      })
more_than_one_response = (request_method_helper, 1500, 0,
                          {'first_field': 'aaa',
                           'second_field': ['a', 'a', 'a'],
                           'third_field': {'a': {1: None}}
                           }
                          )
responses_by_batches_input = [only_one_response, more_than_one_response]


@pytest.mark.parametrize('request_method, length, start, expected_final_dict', responses_by_batches_input)
def test_responses_by_batches(request_method: Callable, length: int, start: int, expected_final_dict: dict) -> Dict:
    from Arkime import responses_by_batches
    assert responses_by_batches(request_method, length, start) == expected_final_dict
