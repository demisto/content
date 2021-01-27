import datetime
import io
import json
import pytest
import demistomock as demisto
from CrowdStrikeMalquery import Client
from freezegun import freeze_time

from CommonServerPython import DemistoException

get_hunt_request_outputs = {'Request_ID': '096f6aa5-f245-4b09-790f-133bc89d4d26', 'Status': 'done', 'File': [
    {'sha256': 'd207ccf1eabcc9453288896d963f1a1c558c427abfe9305d7328e3a6fb06f6ee',
     'sha1': '85be23059c9abb3370586dc49dbd8f1ced05df8e', 'md5': '0b189ab69d40e782fe827c63e1cc6f06', 'filesize': 151552,
     'first_seen': '2020/06/09', 'filetype': 'PE32', 'label': 'unknown', 'samples': []},
    {'sha256': '41a1d7b98d0ce3259270c9a8f26fe8899cca402cba69ef8e5c70449faea8b714',
     'sha1': '2ca2622317bc840bf890d1e337d2c547be2cfebf', 'md5': '688bdedf1f9dd44d6db51a7f8499939c', 'filesize': 245760,
     'family': 'Stonedrill', 'first_seen': '2019/03/12', 'filetype': 'PE32', 'label': 'malware', 'samples': []},
    {'sha256': '0f191518ab7f24643218bd3384ae4bd1f52ec80419730d87196605a2a69938d7',
     'sha1': '6ae00484a878201e6150108ca1b234dd1f68930d', 'md5': '345ade2a73ee83e4f75447a26c4e78c9', 'filesize': 317440,
     'family': 'Stonedrill', 'first_seen': '2018/01/24', 'filetype': 'PE32', 'label': 'malware', 'samples': []},
    {'sha256': '3fb85b787fa005e591cd2cd7e1e83c79d103b1c26f5da31fdf788764ae0b8bb0',
     'sha1': 'df07d50296914de0ca3116d4ca6d3845d55c7540', 'md5': '2b82ce15a632e3ce1485bfc87e586ee5', 'filesize': 128512,
     'family': 'Cadlotcorg', 'first_seen': '2017/07/20', 'filetype': 'PE32', 'label': 'malware', 'samples': []},
    {'sha256': 'bf79622491dc5d572b4cfb7feced055120138df94ffd2b48ca629bb0a77514cc',
     'sha1': 'b9fc1ac4a7ccee467402f190391974a181391da3', 'md5': '697c515a46484be4f9597cb4f39b2959', 'filesize': 130560,
     'family': 'Cadlotcorg', 'first_seen': '2016/12/09', 'filetype': 'PE32', 'label': 'malware', 'samples': []}]}
get_hunt_request_hr = '| 317440 | PE32 | 2018/01/24 | malware | 345ade2a73ee83e4f75447a26c4e78c9 | ' \
                      '6ae00484a878201e6150108ca1b234dd1f68930d | ' \
                      '0f191518ab7f24643218bd3384ae4bd1f52ec80419730d87196605a2a69938d7 |'

get_exact_search_request_outputs = {
    'File': [{'filesize': 484872,
              'filetype': 'PE32',
              'samples': [],
              'sha256': '201e81ecf31926dc9160741c5666a5b1d9a9795e637a4c7955417a6af7e5b2a4'},
             {'filesize': 2112000,
              'filetype': 'PE32',
              'samples': [],
              'sha256': '9a3c5febd9b4659e948ffd6a71802f409feca44c9c7f0aa0c152aa93c950a947'},
             {'filesize': 1080320,
              'filetype': 'PE32',
              'samples': [],
              'sha256': '07c95170772e76b7e8d87f5b3535fb3a65a57a468cf9b0a42664fcd3813d21cd'},
             {'filesize': 229376,
              'filetype': 'PE32',
              'samples': [],
              'sha256': 'b293c151970a37eee4ed696d85cc845c00ae07e039795fdcd13f3ae3f093431c'},
             {'filesize': 303360,
              'filetype': 'PE32',
              'samples': [],
              'sha256': 'd7364785cef732b41894f3d4523d28a396944dc1de8fbbc6a0df5a0b6aeb887e'},
             {'filesize': 573440,
              'filetype': 'PE32',
              'samples': [],
              'sha256': 'de055123772aff2ef0d0a2c6faa1759f007e970f56310db2c93ae99577cb53bb'},
             {'filesize': 2142208,
              'filetype': 'PE32',
              'samples': [],
              'sha256': '72862c0ca1a862e63d0e6b351abb95f23d94b52eb0fc38b358b92a4923c5d66a'},
             {'filesize': 163840,
              'filetype': 'PE32',
              'samples': [],
              'sha256': '24805fdb4f387db3c76e4a8422857f2154a5d6793762fbe27efa5a7f7d3b0cf3'},
             {'filesize': 2007552,
              'filetype': 'PE32',
              'samples': [],
              'sha256': '2871b4b8eda4a717d5e5a57551063a30b30aef94a5ac5a7fd35b8d41a6e0be07'},
             {'filesize': 216472,
              'filetype': 'PE32',
              'samples': [],
              'sha256': 'c6c20403715090ce0ccecb9de2c71e78673bd87abf8f4cbcda5e97a72bddfbf9'}],
    'Request_ID': 'fc4db762-288c-40cc-5f4f-4f19b65649a',
    'Status': 'done'}
get_exact_search_request_hr = '| 1080320 | PE32 | ' \
                              '07c95170772e76b7e8d87f5b3535fb3a65a57a468cf9b0a42664fcd3813d21cd |'

get_request_status_inprogress_raw = {
    "meta": {"query_time": 0.1, "powered_by": "malquery-api", "trace_id": "def-456", "reqid": "abc-123",
             "status": "inprogress"}, "resources": []}
get_request_status_inprogress_outputs = {'Request_ID': 'abc-123', 'Status': 'inprogress'}
get_request_status_inprogress_hr = 'abc-123'

client = Client(
    base_url="base_url",
    verify=False,
    client_id="client_id",
    client_secret="client_secret",
    proxy=False)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@freeze_time("2020-06-29 18:04:21")
def test_get_passed_mins():
    """
    Tests get_passed_mins helper function.
    Using @freeze_time decorator in order to make the datetime.now() method to permanent value.
    """
    from CrowdStrikeMalquery import get_passed_mins
    start_time = datetime.datetime.now()
    end_time_str = start_time.replace(hour=16).timestamp()
    expected_time_delta = 120
    result = get_passed_mins(start_time, end_time_str)
    assert expected_time_delta == result


@pytest.mark.parametrize(
    "integration_context, expected_token",
    [({'access_token': 'access_token', 'valid_until': 1593443061.0}, "access_token"),
     ({'access_token': 'access_token', 'valid_until': 1573443061.0}, "new_access_token"),
     ({}, 'new_access_token')])
@freeze_time("2020-06-29 18:04:21.446809")
def test_get_access_token(mocker, integration_context, expected_token):
    """
        Configures mocker instance and patches the client's _http_request to generate access token.
        Also patches demisto's `getIntegrationContext`

        Use-cases:
        1. There is a valid access token in the integration context.
        2. The access token saved in the integration context is no longer valid.
        3. There is no access token in the integration context.
    """
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=integration_context)
    mocker.patch.object(client, '_http_request', return_value={'access_token': expected_token})
    access_token = client.get_access_token()
    assert access_token == expected_token


@pytest.mark.xfail(raises=DemistoException, reason="Must provide a query to search")
def test_exact_search_command_without_patterns():
    """
        Test exact_search_command

        Use-case:
            - No patterns provided - Should raise a DemistoException.
    """
    from CrowdStrikeMalquery import exact_search_command

    exact_search_command(client, {})


def test_exact_search_command_(mocker):
    """
        Configures mocker instance and patches the client's exact_search to generate an appropriate response.

        Use-cases:
            - All data is provided - check context and human readable
    """
    from CrowdStrikeMalquery import exact_search_command
    args = {"hex": "hex", "ascii": "ascii", "limit": "5", "filter_meta": 'sha256, type, size'}
    exact_search_raw_response = util_load_json('test_data/exact_search_raw_response.json')
    mocker.patch.object(client, "exact_search", return_value=exact_search_raw_response)
    result = exact_search_command(client, args)
    assert "ac1403c0-d095-4934-5bd2-4cd45f365a45" in result.readable_output
    assert {'Request_ID': 'ac1403c0-d095-4934-5bd2-4cd45f365a45'} == result.outputs


@pytest.mark.xfail(raises=DemistoException, reason="Must provide a query to search")
def test_fuzzy_search_command_without_patterns():
    """
        Test fuzzy_search_command.

        Use-case:
            - No patterns provided - Should raise a DemistoException.
    """
    from CrowdStrikeMalquery import fuzzy_search_command
    fuzzy_search_command(client, {})


def test_fuzzy_search_command(mocker):
    """
        Configures mocker instance and patches the client's fuzzy_search to generate an appropriate response.

        Use-cases:
            - All data is provided - check context and human readable
    """
    from CrowdStrikeMalquery import fuzzy_search_command
    args = {"hex": "hex", "ascii": "ascii", "limit": "10", "filter_meta": 'sha256, type, size'}
    fuzzy_search_raw_response = util_load_json('test_data/fuzzy_search_raw_response.json')
    mocker.patch.object(client, "fuzzy_search", return_value=fuzzy_search_raw_response)
    result = fuzzy_search_command(client, args)
    expected_context = [
        {'sha256': 'e51f0a8884eb08fc43da0501ebd3776831e2fd4b0a8dd12e69866a8febe41495', 'filesize': 310552,
         'filetype': 'PE32'},
        {'sha256': 'bc74f8fc37b902536b52c1157b74724edc96a586b0e3e38717dd845981443a5b', 'filesize': 1672180,
         'filetype': 'PE32'},
        {'sha256': '72b021085f62e5dc1335f878a2751bce68d95918c84215ec8dfebf491009ea09', 'filesize': 1672188,
         'filetype': 'PE32'},
        {'sha256': '5e2e1735e10684b36d30b3a3362e66cd30fb493afac8e711d92bde8372b9b6d0', 'filesize': 279624,
         'filetype': 'PE32'},
        {'sha256': 'ec0d93607d777c6e3db8e98856e1b58ea8918f45b98ae601bc3f6af91fae9ec0', 'filesize': 287304,
         'filetype': 'PE32'},
        {'sha256': 'c392794b98f5a1180d6f6f4abe94a5f9d9ba09cb5e25de7e6736ded4e6c9e12d', 'filesize': 1661440,
         'filetype': 'PE32'},
        {'sha256': '31c490852525bbe37ad536c153df05e1353e64c9a4bdb08505493c413db28368', 'filesize': 276040,
         'filetype': 'PE32'},
        {'sha256': '0142d5e2b43b5e1ae66c0724959b3ccc7c9022160231c9ef6fa5e571b2edc8dc', 'filesize': 272384,
         'filetype': 'PE32'},
        {'sha256': 'd5023cd464d7578506770338e0fc43bd64887dbf234785b4d8f8547e57efa33d', 'filesize': 19055104,
         'filetype': 'PE32'},
        {'sha256': '9dd98c144cb29cf3ab6dfa26514b8d10ed414e32a66dd4777eae5f03c502197c', 'filesize': 2673152,
         'filetype': 'PE32'}]
    assert '|filesize|filetype|sha256|' in result.readable_output
    assert '| 2673152 | PE32 | ' \
           '9dd98c144cb29cf3ab6dfa26514b8d10ed414e32a66dd4777eae5f03c502197c |' in result.readable_output
    assert expected_context == result.outputs


def test_hunt_command(mocker):
    """
        Configures mocker instance and patches the client's hunt function to generate an appropriate response.

        Use-cases:
            - All data is provided - check context and human readable
    """
    from CrowdStrikeMalquery import hunt_command
    args = {"yara_rule": "yara", "limit": "5", "filter_meta": 'sha256, type, size'}
    hunt_raw_response = util_load_json('test_data/hunt_raw_response.json')
    mocker.patch.object(client, "hunt", return_value=hunt_raw_response)
    result = hunt_command(client, args)
    assert "096f6aa5-f245-4b09-790f-133bc89d4d26" in result.readable_output
    assert {'Request_ID': '096f6aa5-f245-4b09-790f-133bc89d4d26'} == result.outputs


@pytest.mark.parametrize(
    "request_id, raw_response, expected_outputs, expected_hr",
    [
        ('096f6aa5-f245-4b09-790f-133bc89d4d26', util_load_json('test_data/get_hunt_request.json'),
         get_hunt_request_outputs, get_hunt_request_hr),
        ('fc4db762-288c-40cc-5f4f-4f19b65649a', util_load_json('test_data/get_exact_search_request.json'),
         get_exact_search_request_outputs, get_exact_search_request_hr),
        ('abc-123', get_request_status_inprogress_raw, get_request_status_inprogress_outputs,
         get_request_status_inprogress_hr)
    ])
def test_get_request_command(mocker, request_id, raw_response, expected_outputs, expected_hr):
    """
    Test get_request_command function for both hunt request and exact search.
    Configures mocker instance and patches the client's get_request to generate the appropriate
    Checks the output of the command function with the expected outputs and human readable.

    Use-cases:
    1. get hunt request
    2. get exact search request
    3. get a request with status other then `done`
    """
    from CrowdStrikeMalquery import get_request_command
    mocker.patch.object(client, 'get_request', return_value=raw_response)
    result = get_request_command(client, {"request_id": request_id})
    assert expected_outputs == result.outputs
    assert expected_hr in result.readable_output


def test_get_file_metadata_command(mocker):
    """
        Test !file function
        Configures mocker instance and patches the client's get_files_metadata to generate the appropriate response

        Use cases:
                - Returns human readable string as expected
                - Generates indicator from the file specified with the expected dbot score
                - Returns outputs dict as expected
    """
    from CrowdStrikeMalquery import get_file_metadata_command
    hr = '| Arcyess | 484872 | PE32 | 2014/05/09 | malware | 43c596cabeb4c1d335ce53c3c7c4c392 | ' \
         'b32c34ab09e8c20e1ed93a72bcc5424a982d3042 | accc6794951290467e01b7676e8b4ba177076d54f836589ea7d3298cdf6fc995 |'
    outputs = [{'sha256': 'accc6794951290467e01b7676e8b4ba177076d54f836589ea7d3298cdf6fc995',
                'sha1': 'b32c34ab09e8c20e1ed93a72bcc5424a982d3042', 'md5': '43c596cabeb4c1d335ce53c3c7c4c392',
                'filesize': 484872,
                'label': 'malware', 'family': 'Arcyess', 'first_seen': '2014/05/09', 'filetype': 'PE32'}]
    mocker.patch.object(client, 'get_files_metadata',
                        return_value=util_load_json('test_data/get_metadata_raw_response.json'))
    result = get_file_metadata_command(client,
                                       {'file': 'accc6794951290467e01b7676e8b4ba177076d54f836589ea7d3298cdf6fc995'})
    assert 3 == result[0].indicator.dbot_score.score
    assert hr in result[0].readable_output
    assert outputs[0] == result[0].outputs


def test_samples_multidownload_command(mocker):
    """
        Configures mocker instance and patches the client's samples_multidownload to generate an appropriate response.

        Use-cases:
                - All data is provided - check context and human readable
    """
    from CrowdStrikeMalquery import samples_multidownload_command
    mocker.patch.object(client, 'samples_multidownload',
                        return_value=util_load_json('test_data/multidownload_raw_response.json'))
    result = samples_multidownload_command(client, {'samples': 'samples'})
    assert "93b55373-3b69-43cb-6ea1-2870a44e1c1e" in result.readable_output
    assert {'Request_ID': '93b55373-3b69-43cb-6ea1-2870a44e1c1e'} == result.outputs


def test_get_ratelimit_command(mocker):
    """
        Configures mocker instance and patches the client's get_quotas to generate an appropriate response.

        Use-cases:
                - All data is provided - check context and human readable
    """
    from CrowdStrikeMalquery import get_ratelimit_command
    mocker.patch.object(client, 'get_quotas', return_value=util_load_json('test_data/get_ratelimit_raw_respose.json'))
    result = get_ratelimit_command(client, {})
    expected_hr = "|hunt_count|download_count|monitor_count|hunt_limit|download_limit|monitor_limit|refresh_time" \
                  "|days_left|"
    expected_outputs = {'hunt_count': 45, 'download_count': 48, 'monitor_count': 0, 'hunt_limit': 100,
                        'download_limit': 50, 'monitor_limit': 10, 'refresh_time': '2020-07-01T00:00:00Z',
                        'days_left': 0, 'hunt_counts': [{'userid': '', 'counter': 45}],
                        'download_counts': [{'userid': '', 'counter': 48}]}
    assert expected_hr in result.readable_output
    assert expected_outputs == result.outputs
