import json
import re
from datetime import datetime

import pytest

from CommonServerPython import DemistoException
from Absolute import INTEGRATION, ClientV3

EXPECTED_CANONICAL_GET_REQ_NO_PAYLOAD_NO_QUERY = """GET
/v2/reporting/devices

host:api.absolute.com
content-type:application/json
x-abs-date:20170926T172213Z
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"""

EXPECTED_CANONICAL_PUT_REQ_NO_PAYLOAD_WITH_QUERY = """PUT
/v2/devices/e93f2464-2766-4a6b-8f00-66c8fb13e23a/cdf
substringof%28%27760001%27%2C%20esn%29%20eq%20true
host:api.absolute.com
content-type:application/json
x-abs-date:20170926T172213Z
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"""

EXPECTED_CANONICAL_POST_REQ_WITH_PAYLOAD_WITH_QUERY = """POST
/v2/devices/e93f2464-2766-4a6b-8f00-66c8fb13e23a/cdf
substringof%28%27760001%27%2C%20esn%29%20eq%20true%20or%20availablePhysicalMemroyBytes%20lt%201073741824
host:api.absolute.com
content-type:application/json
x-abs-date:20170926T172213Z
4c4cba4fe89f96921d32cf91d4bd4415f524050ffe82c840446e7110a622a025"""

EXPECTED_SIGNING_STRING_PUT = """ABS1-HMAC-SHA-256
20170926T172213Z
20170926/cadc/abs1
c23103585b2b6d617f4a88afa1e76731cf6215ef329fdd0024030ca21a4933b4"""

EXPECTED_SIGNING_STRING_POST = """ABS1-HMAC-SHA-256
20170926T172213Z
20170926/cadc/abs1
ed080b5e0df239b4f747d510a388eefe3b4876730e6f09a9e3d953f36983aec3"""

EXPECTED_SIGNING_STRING_GET = """ABS1-HMAC-SHA-256
20170926T172213Z
20170926/cadc/abs1
1b42a7b1f96d459efdbeceba5ee624d92caeb3ab3ca196268be55bc89c61cd93"""

GET_REQUEST_SIGNATURE = "ab87d64d18610852565a2821625dfef1f19403673afe2f7f511ef185269d2334"
PUT_REQUEST_SIGNATURE = "1d025c22f7fea8d14eb8416e863a12bf17daaa637c59ee98ed19a89509e69132"
POST_REQUEST_SIGNATURE = "2355cede6fe99bf852ec7e4bc7dc450445fac9458814ef81d1a1b0906aac750b"

SIGNING_KEY = b'\xe5_\xf5\x90o+\xa2\xe4\x00\xa4\x89\xd2\x1d\xa32B^\x19\xb7\xbdyy^:1\xd0\xdd\\\x87N\x02M'

GET_REQUEST_AUTH_HEADER = "ABS1-HMAC-SHA-256 Credential=token/20170926/cadc/abs1, " \
                          "SignedHeaders=host;content-type;x-abs-date, " \
                          "Signature=ab87d64d18610852565a2821625dfef1f19403673afe2f7f511ef185269d2334"
PUT_REQUEST_AUTH_HEADER = "ABS1-HMAC-SHA-256 Credential=token/20170926/cadc/abs1, " \
                          "SignedHeaders=host;content-type;x-abs-date, " \
                          "Signature=1d025c22f7fea8d14eb8416e863a12bf17daaa637c59ee98ed19a89509e69132"
POST_REQUEST_AUTH_HEADER = "ABS1-HMAC-SHA-256 Credential=token/20170926/cadc/abs1, " \
                           "SignedHeaders=host;content-type;x-abs-date, " \
                           "Signature=2355cede6fe99bf852ec7e4bc7dc450445fac9458814ef81d1a1b0906aac750b"

FREEZE_REQ_EXPECTED_OUTPUT = [{'ActionRequestUid': 'e416f97e-dc43-4ed0-88c3-b33ea66c660f',
                               'ChangedBy': None,
                               'ChangedUTC': '2021-11-03T07:33:55.966+00:00',
                               'Configuration': {},
                               'Content': None,
                               'CreatedBy': None,
                               'CreatedUTC': '2021-11-03T07:33:56.004+00:00',
                               'DeviceUid': '56be8d1f-2eb8-4e9b-bbd6-1aab032abcde',
                               'Downloaded': False,
                               'EventHistoryId': 'DeviceFreeze-0864',
                               'FreezePolicyUid': None,
                               'ID': '1',
                               'IsCurrent': True,
                               'Name': 'On-demand Freeze request',
                               'NotificationEmails': ['example1@test.com', 'example2@test.com'],
                               'PolicyConfigurationVersion': 0,
                               'PolicyGroupUid': None,
                               'Requester': 'example@test.com',
                               'Statuses': []}]


@pytest.fixture
def absolute_client_v3():
    return ClientV3(proxy=False,
                    verify=False,
                    base_url='https://api.absolute.com',
                    token_id='token',
                    secret_key='secret',
                    headers={}
                    )


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('url', ['https://absolute.com', 'absolute.com'])
def test_invalid_absolute_api_url(url):
    from Absolute import validate_absolute_api_url
    with pytest.raises(DemistoException):
        validate_absolute_api_url(url)


def mock_http(method: str, url_suffix: str, body: dict = {}):
    if url_suffix == '/v3/actions/requests/unenroll':
        return {'requestUid': 'abdcef'}
    elif url_suffix == '/v3/actions/requests/unenroll/abdcef':
        return {'totalDevices': 'totalDevices',
                'pending': 'pending',
                'processing': 'processing',
                'completed': 'completed',
                'canceled': 'canceled',
                'failed': 'failed',
                'requestId': 'abdcef',
                'requestUid': 'abdcef',
                'requestStatus': 'requestStatus',
                'createdDateTimeUtc': 'createdDateTimeUtc',
                'updatedDateTimeUtc': 'updatedDateTimeUtc',
                'requester': 'requester',
                'excludeMissingDevices': 'excludeMissingDevices'}
    else:
        return [{'deviceUid': 'deviceUid',
                 'actionUid': 'actionUid',
                 'requestUid': 'abdcef',
                 'deviceName': 'deviceName',
                 'actionStatus': 'actionStatus',
                 'esn': 'esn',
                 'createdDateTimeUtc': 'createdDateTimeUtc',
                 'updatedDateTimeUtc': 'updatedDateTimeUtc'}]


def test_prepare_request(mocker, absolute_client_v3):
    """
    Given:
        - All relevant arguments for preparing the prepare_request method

    When:
        - prepare_request is executed

    Then:
        - Validate the jwt.encode function gets called with the correct arguments
    """
    import jwt

    jwt_encode = mocker.patch.object(jwt, 'encode', return_value='')
    absolute_client_v3.prepare_request('method', 'url_suffix', 'query_string', {})

    assert jwt_encode.call_args.args == ({}, 'secret')
    absolute_client_v3.prepare_request('method', 'url_suffix', 'query_string', {"test": "test"})

    assert jwt_encode.call_args.args == ({"data": {"test": "test"}}, 'secret')


def test_get_custom_device_field_list_command(mocker, absolute_client_v3):
    from Absolute import get_custom_device_field_list_command
    response = util_load_json('test_data/custom_device_field_list_response.json')
    mocker.patch.object(absolute_client_v3, 'send_request_to_api', return_value=response)
    command_result = get_custom_device_field_list_command(client=absolute_client_v3,
                                                          args={'device_id': '02b9daa4-8e60-4640-8b15-76d41ecf6a94'})
    assert command_result.outputs == {'DeviceUID': '02b9daa4-8e60-4640-8b15-76d41ecf6a94',
                                      'CDFValues': [{'CDFUID': 'njazpLrEQwqeFDqk4yQCfg', 'FieldName': 'Asset Number',
                                                     'FieldKey': 1, 'CategoryCode': 'ESNCOLUMN',
                                                     'FieldValue': 'No Asset Tag', 'Type': 'Text'},
                                                    {'CDFUID': '7PwIrjEXTAqvpb5WdV2w', 'FieldName': 'Assigned Username',
                                                     'FieldKey': 3, 'CategoryCode': 'ESNCOLUMN',
                                                     'FieldValue': '', 'Type': 'Text'}]}


@pytest.mark.parametrize('args, expected_error',
                         [({'device_freeze_type': 'Scheduled'},
                           "When setting device_freeze_type to be Scheduled, you must specify the"
                           " scheduled_freeze_date arg."),  # type is Scheduled and 'scheduled_freeze_date' is missing
                          ({'device_freeze_type': 'OffLine', 'offline_time_seconds': '1'},
                           "the offline_time_seconds arg is not valid. Must be between 1200 seconds "
                           "(20 minutes) and 172800000 seconds (2000 days)."),
                          # type is Offline and 'offline_time_seconds' is not valid
                          ({'passcode_type': 'UserDefined'},
                           "when setting passcode_type to be UserDefined, you must specify the passcode arg."),
                          # passcode_type is UserDefined and 'passcode' is missing
                          ({'passcode_type': 'RandomForEach'},
                           "when setting passcode_type to be RandomForEach or RandomForAll, "
                           "you must specify the passcode_length arg to be between 4 to 8."),
                          # passcode_type is RandomForEach and 'passcode_length' is missing
                          ({'passcode_type': 'RandomForAll', 'passcode_length': '1'},
                           "when setting passcode_type to be RandomForEach or RandomForAll, "
                           "you must specify the passcode_length arg to be between 4 to 8."),
                          # passcode_type is RandomForAll and 'passcode_length' is not valid number
                          ])
def test_prepare_payload_to_freeze_request_with_invalid_args(args, expected_error):
    """
    Given:
        - All relevant arguments for preparing the freeze request

    When:
        - prepare_payload_to_freeze_request is executed

    Then:
        - Validate the exceptions
    """
    from Absolute import prepare_payload_to_freeze_request
    with pytest.raises(DemistoException, match=re.escape(f'{INTEGRATION} error: {expected_error}')):
        prepare_payload_to_freeze_request(args)


@pytest.mark.parametrize('args, expected_payload',
                         [
                             # Scheduled
                             ({'request_name': 'name', 'html_message': 'test', 'message_name': 'name',
                               'device_ids': ["1", "2"], 'scheduled_freeze_date': '2017-09-26T17:22:13Z',
                               'device_freeze_type': 'Scheduled', 'passcode_type': 'UserDefined', 'passcode': '5'},
                              {'deviceUids': ['1', '2'],
                               'freezeDefinition': {'deviceFreezeType': 'Scheduled',
                                                    'scheduledFreezeDateTimeUtc': '2017-09-26T17:22:13Z'},
                               'message': 'test',
                               'messageName': 'name',
                               'requestTitle': 'name',
                               'passcodeDefinition': {'option': 'UserDefined', 'passcode': '5'}}),
                             # Offline
                             ({'request_name': 'name', 'html_message': 'test', 'message_name': 'name',
                               'device_ids': ["1", "2"], 'offline_time_seconds': '1201',
                               'device_freeze_type': 'OffLine', 'passcode_type': 'RandomForEach',
                               'passcode_length': '5'},
                              {'deviceUids': ['1', '2'],
                               'freezeDefinition': {'deviceFreezeType': 'OffLine',
                                                    'offlineTimeSeconds': 1201},
                               'message': 'test',
                               'messageName': 'name',
                               'requestTitle': 'name',
                               'passcodeDefinition': {'option': 'RandomForEach', 'length': 5}})
                         ])
def test_prepare_payload_to_freeze_request_valid_args(args, expected_payload):
    """
    Given:
        - All relevant arguments for preparing the freeze request

    When:
        - prepare_payload_to_freeze_request is executed

    Then:
        - Validate the output
    """
    from Absolute import prepare_payload_to_freeze_request
    assert prepare_payload_to_freeze_request(args) == expected_payload


def test_get_device_freeze_request_command(mocker, absolute_client_v3):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - get_device_freeze_request_command is executed

    Then:
        - The http request is called with the right arguments
    """
    from Absolute import get_device_freeze_request_command
    response = util_load_json('test_data/custom_get_device_freeze_request_response.json')
    mocker.patch.object(absolute_client_v3, 'api_request_absolute', return_value=response)
    command_results = get_device_freeze_request_command(args={'request_uid': '1'}, client=absolute_client_v3)
    assert command_results.outputs[0] == FREEZE_REQ_EXPECTED_OUTPUT[0]


def test_remove_device_freeze_request_command(mocker, absolute_client_v3):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - remove_device_freeze_request_command is executed

    Then:
        - The http request is called with the right arguments
    """
    from Absolute import remove_device_freeze_request_command
    mocker.patch.object(absolute_client_v3, 'api_request_absolute')
    command_results = remove_device_freeze_request_command(args={'device_ids': '1'}, client=absolute_client_v3)
    assert command_results.readable_output == "Successfully removed freeze request for devices ids: 1."


def test_list_device_freeze_message_command(mocker, absolute_client_v3):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - list_device_freeze_message_command is executed

    Then:
        - The http request is called with the right arguments
    """
    from Absolute import list_device_freeze_message_command
    response = util_load_json('test_data/device_freeze_message_list_response.json')
    mocker.patch.object(absolute_client_v3, 'api_request_absolute', return_value=response)
    command_results = list_device_freeze_message_command(args={'message_id': "1"}, client=absolute_client_v3)
    assert command_results.outputs == [{'ID': '1', 'Name': 'On-demand Freeze message',
                                        'CreatedUTC': '2020-11-26T22:29:17.687+00:00',
                                        'ChangedUTC': '2020-12-14T09:14:52.148+00:00',
                                        'Content': '<html><body>This device has been frozen by company.</body></html>',
                                        'CreatedBy': 'example1@test.com',
                                        'ChangedBy': 'example2@test.com'}]


def test_device_unenroll_command(mocker, absolute_client_v3):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - device_unenroll_command command is executed

    Then:
        - The http request is called with the right arguments
    """
    from Absolute import device_unenroll_command
    mocker.patch.object(absolute_client_v3, 'api_request_absolute', side_effect=mock_http)
    outputs = device_unenroll_command(args={'device_ids': "1,2"}, client=absolute_client_v3).outputs
    assert outputs == {'TotalDevices': 'totalDevices',
                       'Pending': 'pending',
                       'Processing': 'processing',
                       'Completed': 'completed',
                       'Canceled': 'canceled',
                       'Failed': 'failed',
                       'RequestId': 'abdcef',
                       'RequestUid': 'abdcef',
                       'RequestStatus': 'requestStatus',
                       'CreatedDateTimeUtc': 'createdDateTimeUtc',
                       'UpdatedDateTimeUtc': 'updatedDateTimeUtc',
                       'Requester': 'requester',
                       'ExcludeMissingDevices': 'excludeMissingDevices',
                       'Devices': [
                                    {'DeviceUid': 'deviceUid',
                                     'ActionUid': 'actionUid',
                                     'RequestUid': 'abdcef',
                                     'DeviceName': 'deviceName',
                                     'ActionStatus': 'actionStatus',
                                     'ESN': 'esn',
                                     'CreatedDateTimeUtc': 'createdDateTimeUtc',
                                     'UpdatedDateTimeUtc': 'updatedDateTimeUtc'
                                     }
                       ]
                       }


def test_list_device_freeze_message_command_no_id(mocker, absolute_client_v3):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - list_device_freeze_message command is executed with no message id

    Then:
        - The http request is called with the right arguments
    """
    from Absolute import list_device_freeze_message_command
    http_request = mocker.patch.object(absolute_client_v3, 'send_request_to_api', return_value={})
    list_device_freeze_message_command(client=absolute_client_v3, args={})
    assert http_request.call_args.args == ('GET', '/v3/actions/freeze/messages', '&pageSize=50')


def test_delete_device_freeze_message_command(mocker, absolute_client_v3):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - delete_device_freeze_message_command command is executed

    Then:
        - The http request is called with the right arguments
    """
    from Absolute import delete_device_freeze_message_command
    message_id = '1'
    http_request = mocker.patch.object(absolute_client_v3, 'send_request_to_api', return_value=[])
    delete_device_freeze_message_command(client=absolute_client_v3, args={'message_id': message_id})

    assert http_request.call_args.args == ('DELETE', f'/v3/actions/freeze/messages/{message_id}', '')


def test_update_device_freeze_message_command(mocker, absolute_client_v3):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - update_device_freeze_message_command command is executed

    Then:
        - The http request is called with the right arguments
    """
    from Absolute import update_device_freeze_message_command
    message_id = '1'
    http_request = mocker.patch.object(absolute_client_v3, 'api_request_absolute', return_value=[])
    args = {'message_id': message_id, 'html_message': 'text', 'message_name': 'name'}
    update_device_freeze_message_command(client=absolute_client_v3, args=args)
    assert http_request.call_args.args == ('PUT', f'/v3/actions/freeze/messages/{message_id}')


def test_create_device_freeze_message_command(mocker, absolute_client_v3):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - create_device_freeze_message_command command is executed

    Then:
        - The http request is called with the right arguments
    """
    from Absolute import create_device_freeze_message_command
    http_request = mocker.patch.object(absolute_client_v3, 'api_request_absolute', return_value={})
    args = {'html_message': 'text', 'message_name': 'name'}
    create_device_freeze_message_command(client=absolute_client_v3, args=args)
    assert http_request.call_args.args == ('POST', '/v3/actions/freeze/messages')


@pytest.mark.parametrize('field_name, list_of_values, query, expected_query',
                         [
                             ("id", [], "query", "query"),
                             ("accountUid", ["1", "2"], "",
                              "substringof('1',accountUid) or substringof('2',accountUid)"),
                             ("accountUid", ["1", "2"], "deviceUID eq '1'",
                              "deviceUID eq '1' or substringof('1',accountUid) or substringof('2',accountUid)"),
                         ])
def test_add_list_to_filter_string(field_name, list_of_values, query, expected_query):
    from Absolute import add_list_to_filter_string
    assert add_list_to_filter_string(field_name, list_of_values, query) == expected_query


@pytest.mark.parametrize('field_name, value, query, expected_query',
                         [
                             ("id", "", "query", "query"),
                             ("accountUid", 1, "", "accountUid eq '1'"),
                             ("accountUid", 1, "deviceUID eq '1'", "deviceUID eq '1' or accountUid eq '1'"),
                         ])
def test_add_value_to_filter_string(field_name, value, query, expected_query):
    from Absolute import add_value_to_filter_string
    assert add_value_to_filter_string(field_name, value, query) == expected_query


@pytest.mark.parametrize('args, change_device_name_to_system, expected_filter',
                         [
                             ({'filter': "accountUid eq '1'"}, False, "$filter=accountUid eq '1'"),
                             ({'filter': "accountUid eq '1'", 'account_uids': '1'}, False, "$filter=accountUid eq '1'"),
                             ({'account_uids': '1,2'}, False,
                              "$filter=substringof('1',accountUid) or substringof('2',accountUid)"),
                             ({'account_uids': '1,2', 'device_names': "name1, name2"}, False,
                              "$filter=substringof('1',accountUid) or substringof('2',accountUid) or "
                              "substringof('name1',deviceName) or substringof('name2',deviceName)"),
                             ({'account_uids': '1,2', 'device_names': "name1, name2"}, True,
                              "$filter=substringof('1',accountUid) or substringof('2',accountUid) or "
                              "substringof('name1',systemName) or substringof('name2',systemName)"),
                             ({'agent_status': 'Active', 'device_names': "name1, name2"}, True,
                              "$filter=substringof('name1',systemName) or substringof('name2',systemName) "
                              "or agentStatus eq 'A'"),
                         ])
def test_create_filter_query_from_args(args, change_device_name_to_system, expected_filter):
    from Absolute import create_filter_query_from_args
    assert create_filter_query_from_args(args, change_device_name_to_system) == expected_filter


@pytest.mark.parametrize('return_fields, query, expected_query',
                         [
                             ("", "", ""),
                             ("", "$filter=accountUid eq '1'", "$filter=accountUid eq '1'"),
                             ("accountUid", "$filter=accountUid eq '1'", "$filter=accountUid eq"
                                                                         " '1'&$select=accountUid"),
                             ("deviceUid", "$filter=accountUid eq '1'", "$filter=accountUid eq '1'&$select=deviceUid"),
                             ("deviceUid,accountUid", "$filter=accountUid eq '1'",
                              "$filter=accountUid eq '1'&$select=deviceUid,accountUid"),
                             ("deviceUid,accountUid", "", "$select=deviceUid,accountUid"),
                         ])
def test_parse_return_fields(return_fields, query, expected_query):
    from Absolute import parse_return_fields
    assert parse_return_fields(return_fields, query) == expected_query


def test_add_pagination(absolute_client_v3):
    """
    Given:
        page size and next page arguments
    When:
        Running the add_pagination client function
    Then:
        Validate the output
    """
    next_page = 'abcdefg'
    page_size = 5
    assert absolute_client_v3.add_pagination(next_page, page_size) == f"&nextPage={next_page}&pageSize={page_size}"

    next_page = ''
    assert absolute_client_v3.add_pagination(next_page, page_size) == f"&pageSize={page_size}"


def test_get_device_location_command(mocker, absolute_client_v3):
    from Absolute import get_device_location_command
    response = util_load_json('test_data/device_location_get.json')
    mocker.patch.object(absolute_client_v3, 'api_request_absolute', return_value=response)
    outputs = get_device_location_command(args={'device_ids': "1,2"}, client=absolute_client_v3).outputs
    assert outputs == [{'Accuracy': 10,
                        'City': 'TLV',
                        'Coordinates': [-123.13202, 49.288162],
                        'Country': 'Israel',
                        'CountryCode': 'IL',
                        'ID': '1',
                        'LastUpdate': 1605747972853,
                        'LocationTechnology': 'gps',
                        'State': 'Israel'},
                       {'Accuracy': 15,
                        'City': 'Jerusalem',
                        'Coordinates': [-124.1, 59.2],
                        'Country': 'Israel',
                        'CountryCode': 'IL',
                        'ID': '2',
                        'LastUpdate': 1605747972853,
                        'LocationTechnology': 'gps',
                        'State': 'Israel'}]


def test_fetch_events_case_no_events_exist(mocker, absolute_client_v3):
    """
    Given:
        - No events.

    When:
        - Running the fetch_events function.

    Then:
        - The events list should be empty.
    """
    from Absolute import fetch_events
    mock_response = {'data': [], 'metadata': {}}
    mocker.patch('Absolute.ClientV3.fetch_events_between_dates', return_value=(mock_response.get('data'), ''))
    mocker.patch('Absolute.process_events', return_value=(mock_response.get('data'), {}))
    events, last_run_object = fetch_events(absolute_client_v3, 10000, {})
    assert events == mock_response.get('data')


def test_fetch_events_first_fetch(mocker, absolute_client_v3):
    """
    Given:
        - No previous events have been fetched.

    When:
        - Running the fetch_events function.

    Then:
        - The events list should contain the fetched events.
    """
    from Absolute import fetch_events
    mock_response = util_load_json('test_data/siem_events.json')
    mocker.patch('Absolute.ClientV3.fetch_events_between_dates', return_value=(mock_response.get('data'), ''))
    mocker.patch('Absolute.process_events', return_value=(mock_response.get('data'), {}))
    events, last_run_object = fetch_events(absolute_client_v3, 10000, {})
    assert events == mock_response.get('data')


def test_fetch_events_with_last_run_object_and_handle_deduplication(mocker, absolute_client_v3):
    """
    Given:
        - A last_run_object containing information about the previous fetch.
        - The need to handle deduplication of fetched events.

    When:
        - Running the fetch_events function to fetch events in batches.

    Then:
        - The events list should contain all the fetched events, without duplicated events.
        - The last_run_object should be updated based on the fetched events.
    """
    from Absolute import fetch_events
    import Absolute
    mock_response = util_load_json('test_data/siem_events.json')
    Absolute.SEIM_EVENTS_PAGE_SIZE = 8
    first_mock_response = mock_response.get('data')[:Absolute.SEIM_EVENTS_PAGE_SIZE]
    second_mock_response = mock_response.get('data')[Absolute.SEIM_EVENTS_PAGE_SIZE - 1:]
    mocker.patch.object(ClientV3, 'fetch_events_between_dates', return_value=first_mock_response)
    events_first_batch, last_run_object = fetch_events(absolute_client_v3, Absolute.SEIM_EVENTS_PAGE_SIZE, {})
    mocker.patch.object(ClientV3, 'fetch_events_between_dates', return_value=second_mock_response)
    events_second_batch, _ = fetch_events(absolute_client_v3, Absolute.SEIM_EVENTS_PAGE_SIZE, last_run_object)
    all_events = events_first_batch + events_second_batch
    assert all_events == mock_response.get('data')


def test_fetch_events_between_dates_one_fetch(mocker, absolute_client_v3):
    """
    Given:
        - The fetch_events_between_dates function is called with no previous last run.

    When:
        - The fetch_events function is run.

    Then:
        - The fetched events list should contain the expected events.
    """
    from Absolute import ClientV3
    from datetime import timedelta
    mock_response = util_load_json('test_data/siem_events.json')
    mock_response['metadata']['pagination']['nextPage'] = ''
    mocker.patch.object(absolute_client_v3, 'send_request_to_api', return_value=mock_response)
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(minutes=1)
    fetch_events_spy = mocker.spy(absolute_client_v3, 'send_request_to_api')
    all_events = ClientV3.fetch_events_between_dates(absolute_client_v3, 10000, start_date, end_date)
    assert all_events == mock_response.get('data')
    fetch_events_spy.assert_called_once()


def test_fetch_events_between_dates_multiple_fetches(mocker, absolute_client_v3):
    """
    Given:
        - The fetch_events_between_dates function is called with multiple fetches. It happens when the amount of events
        is greater than the fetch limit.

    When:
        - The fetch_events function is called with different fetches.

    Then:
        - The fetched events list should contain the expected events.
        - The fetch_events_between_dates method should be called multiple times.
    """
    from Absolute import ClientV3
    from datetime import timedelta
    import Absolute

    Absolute.SEIM_EVENTS_PAGE_SIZE = 10
    mock_response = util_load_json('test_data/siem_events.json')
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(minutes=1)

    def fetch_events_side_effect(method: str, url_suffix: str, query_string: str, ok_codes: tuple):
        if fetch_events_side_effect.call_count == 1:
            fetch_events_side_effect.call_count += 1
            return {
                'data': mock_response.get('data')[:Absolute.SEIM_EVENTS_PAGE_SIZE],
                'metadata': {
                    'pagination': {
                        'nextPage': 'next_token'
                    }
                }
            }
        else:
            return {
                'data': mock_response.get('data')[Absolute.SEIM_EVENTS_PAGE_SIZE:],
                'metadata': {
                    'pagination': {}
                }
            }

    fetch_events_side_effect.call_count = 1
    mocker.patch.object(absolute_client_v3, 'send_request_to_api', side_effect=fetch_events_side_effect)
    fetch_events_spy = mocker.spy(absolute_client_v3, 'send_request_to_api')
    all_events = ClientV3.fetch_events_between_dates(absolute_client_v3, 10000, start_date, end_date)

    assert all_events == mock_response.get('data')
    assert fetch_events_spy.call_count == 2


def test_add_time_field(absolute_client_v3):
    """
    Given:
        - The add_time_field_to_events_and_get_latest_events function is called.

    When:
        - The function is invoked with a list of events.

    Then:
        - All the events in the list should have a "_time" field.
    """
    from Absolute import process_events
    mock_response = util_load_json('test_data/siem_events.json')
    events = mock_response.get('data')
    all_events, _ = process_events(events=events, last_run={})
    for event in all_events:
        assert event.get('_time')


def test_get_latest_events(absolute_client_v3):
    """
    Given:
        - The add_time_field_to_events_and_get_latest_events function is called.

    When:
        - The function is invoked with a list of events.

    Then:
        - The function should return the latest events based on the 'eventDateTimeUtc' field.
        - The latest_events_id list should contain the IDs of the latest events.
        - The IDs in the latest_events_id list should be unique.
        - The IDs in the latest_events_id list should match the expected IDs.
    """
    from Absolute import process_events
    mock_response = util_load_json('test_data/siem_events.json')
    events = mock_response.get('data')
    _, last_run = process_events(events=events, last_run={})
    assert len(last_run.get('latest_events_id')) == 2
    assert len(set(last_run.get('latest_events_id'))) == 2
    assert last_run.get('latest_events_id') == ['id14', 'id15']
    assert events[13].get('eventDateTimeUtc') == events[14].get('eventDateTimeUtc') == last_run.get('latest_events_time')


def test_get_events_command(mocker, absolute_client_v3):
    """
    Given:
        - The get_events function is called.

    When:
        - The function is invoked with an empty input and an Absolute client instance.

    Then:
        - The function should retrieve events using fetch_events_between_dates and process_events the events.
        - The retrieved events should match the expected events from 'test_data/siem_events.json'.
    """
    from Absolute import get_events
    mock_response = util_load_json('test_data/siem_events.json')
    mocker.patch('Absolute.ClientV3.fetch_events_between_dates', return_value=(mock_response.get('data'), ''))
    mocker.patch('Absolute.process_events', return_value=(mock_response.get('data'), ''))
    events, _ = get_events(absolute_client_v3, {})
    assert events == mock_response.get('data')


def test_get_events_command_wrong_dates(mocker, absolute_client_v3):
    """
    Given:
        - The get_events function is called with invalid dates.

    When:
        - The function is invoked with start_date being "now" and end_date being "one minute ago",
        and an Absolute client instance.

    Then:
        - The function should raise a ValueError.
    """
    from Absolute import get_events
    start_date = "now"
    end_date = "one minute ago"
    args = {'start_date': start_date, 'end_date': end_date}
    try:
        _, _ = get_events(absolute_client_v3, args)
    except ValueError as e:
        assert str(e) == "Start date is greater than the end date. Please provide valid dates."


def test_prepare_query_string_for_fetch_events(mocker, absolute_client_v3):
    """
    Given:
        - The prepare_query_string_for_fetch_events function is called.

    When:
        - The function is invoked with page_size, start_date, end_date, and next_page.

    Then:
        - The function should return a query string for fetching events.
    """
    from Absolute import ClientV3
    from datetime import timedelta
    mock_response = util_load_json('test_data/siem_events.json')
    event = mock_response.get('data')[0]
    start_date = datetime.strptime(event.get('createdDateTimeUtc'), "%Y-%m-%dT%H:%M:%S.%fZ")
    end_date = start_date + timedelta(minutes=1)
    page_size = 1000
    query = ClientV3.prepare_query_string_for_fetch_events(None,
                                                           page_size=page_size,
                                                           start_date=start_date,
                                                           end_date=end_date,
                                                           next_page="next_page_token")
    expected_query = (f'fromDateTimeUtc={start_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]}Z&toDateTimeUtc='
                      f'{end_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]}Z&pageSize={page_size}&nextPage=next_page_token')
    assert query == expected_query


def test_fetch_events_case_fetch_limit_equal_last_run_events_id(mocker, absolute_client_v3):
    """
    Given:
        - The fetch_events function is called.

    When:
        - The fetch limit is equal to the amount of last run events ID.

    Then:
        - The function should double the fetch limit.
    """
    from Absolute import ClientV3
    from Absolute import fetch_events
    mock_response = util_load_json('test_data/siem_events_test_fetch_limit.json')
    fetch_limit = 2
    first_mock_response = {'data': mock_response.get('data')[:fetch_limit]}
    second_mock_response = {'data': mock_response.get('data')[fetch_limit:]}
    mocker.patch.object(ClientV3, 'prepare_query_string_for_fetch_events', return_value='')
    mocker.patch.object(ClientV3, 'send_request_to_api', return_value=first_mock_response)
    events_first_batch, last_run_object = fetch_events(absolute_client_v3, fetch_limit, {})
    mocker.patch.object(ClientV3, 'send_request_to_api', return_value=second_mock_response)
    events_second_batch, _ = fetch_events(absolute_client_v3, fetch_limit, last_run_object)
    all_events = events_first_batch + events_second_batch
    assert len(events_first_batch) == 2
    assert len(events_second_batch) == 4
    assert all_events == mock_response.get('data')
