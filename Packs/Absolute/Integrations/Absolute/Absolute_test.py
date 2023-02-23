import json
import io
import re
from datetime import datetime
from freezegun import freeze_time

import pytest
from pytest import raises

from CommonServerPython import DemistoException
from Absolute import Client, DATE_FORMAT, INTEGRATION

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

FREEZE_REQ_EXPECTED_OUTPUT = [{'AccountUid': 'e7a9fb73-44b0-4f5d-990b-39ff884425eb',
                               'ActionRequestUid': 'e416f97e-dc43-4ed0-88c3-b33ea66c660f',
                               'ChangedBy': None,
                               'ChangedUTC': '2021-11-03T07:33:55.966+00:00',
                               'Configuration': {'action': 'DFZ',
                                                 'conditions': [{}],
                                                 'configurationUid': 'c132d6aa-03b5-483d-89ab-77f45f7346cc',
                                                 'disableFileSharing': True,
                                                 'disableRemoteLogin': True,
                                                 'forceReboot': False,
                                                 'freezeId': 'DeviceFreeze-0864',
                                                 'freezeMessage': 'This device has been frozen by a Company',
                                                 'html': None,
                                                 'htmlClear': 'some html',
                                                 'issuedUTC': '2021-11-03T07:33:55.966+00:00',
                                                 'messageName': 'On-demand Freeze message',
                                                 'passcodeClear': '12345678',
                                                 'passcodeHashed': '+AG=',
                                                 'passcodeLength': 8,
                                                 'passcodeOption': 'RandomForEach',
                                                 'passcodeSalt': 'P0efY',
                                                 'preLoginEnabled': True,
                                                 'serviceControlList': None,
                                                 'type': 'OnDemand'},
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
                               'RequesterUid': '1abc2de3-fa45-67b8-9cde-0f12a34bc567',
                               'Statuses': [{'ackClientTS': 1548265912126,
                                             'ackClientUTC': 1548294712126,
                                             'actionUid': None,
                                             'eventType': None,
                                             'instruction': '',
                                             'message': None,
                                             'messageKey': None,
                                             'messageParams': None,
                                             'scheduledFreezeDateUTC': 0,
                                             'status': 'Launching',
                                             'statusUid': '5336db35-ae66-435e-a29d-41ef2f10a86c',
                                             'triggerActionUid': None,
                                             'updatedBy': 'example@test.com',
                                             'updatedUTC': '2021-11-03T07:33:55.966+00:00'},
                                            {'ackClientTS': 0,
                                             'ackClientUTC': 0,
                                             'actionUid': None,
                                             'eventType': None,
                                             'instruction': None,
                                             'message': None,
                                             'messageKey': None,
                                             'messageParams': None,
                                             'scheduledFreezeDateUTC': 0,
                                             'status': 'FreezeRequested',
                                             'statusUid': None,
                                             'triggerActionUid': None,
                                             'updatedBy': 'example@test.com',
                                             'updatedUTC': 1548294707085}]}]


def create_client(base_url: str = 'https://api.absolute.com', token_id: str = 'token',
                  secret_key: str = 'secret', verify: bool = False, proxy: bool = False):
    x_abs_date = datetime.strptime('20170926T172213Z', DATE_FORMAT).strftime(DATE_FORMAT)
    headers = {"host": base_url.split('https://')[-1], "content-type": "application/json", "x-abs-date": x_abs_date}
    return Client(proxy=proxy, verify=verify, base_url=base_url, token_id=token_id,
                  secret_key=secret_key, headers=headers, x_abs_date=x_abs_date)


@pytest.fixture
def absolute_client():
    return create_client()


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('url', ['https://absolute.com', 'absolute.com'])
def test_invalid_absolute_api_url(url):
    from Absolute import validate_absolute_api_url
    with raises(DemistoException):
        validate_absolute_api_url(url)


@pytest.mark.parametrize('method, canonical_uri ,query_string, payload, expected_canonical_request',
                         [
                             ('GET', '/v2/reporting/devices', '', '', EXPECTED_CANONICAL_GET_REQ_NO_PAYLOAD_NO_QUERY),
                             ('PUT', '/v2/devices/e93f2464-2766-4a6b-8f00-66c8fb13e23a/cdf',
                              "substringof('760001', esn) eq true", '',
                              EXPECTED_CANONICAL_PUT_REQ_NO_PAYLOAD_WITH_QUERY),
                             ('POST', '/v2/devices/e93f2464-2766-4a6b-8f00-66c8fb13e23a/cdf',
                              "substringof('760001', esn) eq true or availablePhysicalMemroyBytes lt 1073741824",
                              json.dumps([{'deviceUid': 'e93f2464-2766-4a6b-8f00-66c8fb13e23a'}]),
                              EXPECTED_CANONICAL_POST_REQ_WITH_PAYLOAD_WITH_QUERY),
                         ])
def test_create_canonical_request(method, canonical_uri, query_string, payload, expected_canonical_request):
    client = create_client()
    canonical_res = client.create_canonical_request(method=method, canonical_uri=canonical_uri,
                                                    query_string=query_string,
                                                    payload=payload)
    assert canonical_res == expected_canonical_request


@pytest.mark.parametrize('canonical_req, expected_signing_string',
                         [(EXPECTED_CANONICAL_GET_REQ_NO_PAYLOAD_NO_QUERY, EXPECTED_SIGNING_STRING_GET),
                          (EXPECTED_CANONICAL_PUT_REQ_NO_PAYLOAD_WITH_QUERY, EXPECTED_SIGNING_STRING_PUT),
                          (EXPECTED_CANONICAL_POST_REQ_WITH_PAYLOAD_WITH_QUERY, EXPECTED_SIGNING_STRING_POST)])
@freeze_time("2017-09-26 17:22:13 UTC")
def test_create_signing_string(canonical_req, expected_signing_string):
    client = create_client()
    assert client.create_signing_string(canonical_req) == expected_signing_string


@freeze_time("2017-09-26 17:22:13 UTC")
def test_create_signing_key():
    client = create_client()
    assert client.create_signing_key() == SIGNING_KEY


@pytest.mark.parametrize('signing_string, expected_signature',
                         [(EXPECTED_SIGNING_STRING_GET, GET_REQUEST_SIGNATURE),
                          (EXPECTED_SIGNING_STRING_PUT, PUT_REQUEST_SIGNATURE),
                          (EXPECTED_SIGNING_STRING_POST, POST_REQUEST_SIGNATURE)])
def test_create_signature(signing_string, expected_signature):
    client = create_client()
    assert client.create_signature(signing_string, SIGNING_KEY) == expected_signature


@pytest.mark.parametrize('signature, expected_authorization_header',
                         [(GET_REQUEST_SIGNATURE, GET_REQUEST_AUTH_HEADER),
                          (PUT_REQUEST_SIGNATURE, PUT_REQUEST_AUTH_HEADER),
                          (POST_REQUEST_SIGNATURE, POST_REQUEST_AUTH_HEADER)])
@freeze_time("2017-09-26 17:22:13 UTC")
def test_add_authorization_header(signature, expected_authorization_header):
    client = create_client()
    assert client.add_authorization_header(signature) == expected_authorization_header


def test_get_custom_device_field_list_command(mocker, absolute_client):
    from Absolute import get_custom_device_field_list_command
    response = util_load_json('test_data/custom_device_field_list_response.json')
    mocker.patch.object(absolute_client, 'api_request_absolute', return_value=response)
    command_result = get_custom_device_field_list_command(client=absolute_client,
                                                          args={'device_id': '02b9daa4-8e60-4640-8b15-76d41ecf6a94'})
    assert command_result.outputs == {'DeviceUID': response.get('deviceUid'), 'ESN': response.get('esn'),
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
                          ({'device_freeze_type': 'Offline', 'offline_time_seconds': '1'},
                           "the offline_time_seconds arg is not valid. Must be between 1200 seconds "
                           "(20 minutes) and 172800000 seconds (2000 days)."),
                          # type is Offline and 'offline_time_seconds' is not valid
                          ({'passcode_type': 'UserDefined'},
                           "when setting passcode_type to be UserDefined, you must specify the passcode arg."),
                          # passcode_type is UserDefined and 'passcode' is missing
                          ({'passcode_type': 'RandomForEach'},
                           "when setting passcode_type to be RandomForEach or RandomForAl, "
                           "you must specify the passcode_length arg to be between 4 to 8."),
                          # passcode_type is RandomForEach and 'passcode_length' is missing
                          ({'passcode_type': 'RandomForAl', 'passcode_length': '1'},
                           "when setting passcode_type to be RandomForEach or RandomForAl, "
                           "you must specify the passcode_length arg to be between 4 to 8."),
                          # passcode_type is RandomForAl and 'passcode_length' is not valid number
                          ])
def test_prepare_payload_to_freeze_request_with_invalid_args(args, expected_error):
    from Absolute import prepare_payload_to_freeze_request
    with raises(DemistoException, match=re.escape(f'{INTEGRATION} error: {expected_error}')):
        prepare_payload_to_freeze_request(args)


@pytest.mark.parametrize('args, expected_payload',
                         [
                             # Scheduled
                             ({'request_name': 'name', 'html_message': 'test', 'message_name': 'name',
                               'device_ids': ["1", "2"], 'scheduled_freeze_date': '2017-09-26T17:22:13Z',
                               'device_freeze_type': 'Scheduled', 'passcode_type': 'UserDefined', 'passcode': '5'},
                              {'deviceUids': ['1', '2'],
                               'freezeDefinition': {'deviceFreezeType': 'Scheduled',
                                                    'scheduledFreezeDate': '2017-09-26T17:22:13Z'},
                               'message': 'test',
                               'messageName': 'name',
                               'name': 'name',
                               'notificationEmails': [],
                               'passcodeDefinition': {'option': 'UserDefined', 'passcode': '5'}}),
                             # Offline
                             ({'request_name': 'name', 'html_message': 'test', 'message_name': 'name',
                               'device_ids': ["1", "2"], 'offline_time_seconds': '1201',
                               'device_freeze_type': 'Offline', 'passcode_type': 'RandomForEach',
                               'passcode_length': '5'},
                              {'deviceUids': ['1', '2'],
                               'freezeDefinition': {'deviceFreezeType': 'Offline',
                                                    'offlineTimeSeconds': 1201},
                               'message': 'test',
                               'messageName': 'name',
                               'name': 'name',
                               'notificationEmails': [],
                               'passcodeDefinition': {'option': 'RandomForEach', 'length': 5}})
                         ])
def test_prepare_payload_to_freeze_request_valid_args(args, expected_payload):
    from Absolute import prepare_payload_to_freeze_request
    assert prepare_payload_to_freeze_request(args) == expected_payload


def test_get_device_freeze_request_command(mocker, absolute_client):
    from Absolute import get_device_freeze_request_command
    response = util_load_json('test_data/custom_get_device_freeze_request_response.json')
    mocker.patch.object(absolute_client, 'api_request_absolute', return_value=response)
    command_results = get_device_freeze_request_command(args={'request_uid': '1'}, client=absolute_client)
    assert command_results.outputs == FREEZE_REQ_EXPECTED_OUTPUT


def test_list_device_freeze_message_command(mocker, absolute_client):
    from Absolute import list_device_freeze_message_command
    response = util_load_json('test_data/device_freeze_message_list_response.json')
    mocker.patch.object(absolute_client, 'api_request_absolute', return_value=response)
    command_results = list_device_freeze_message_command(args={'message_id': "1"}, client=absolute_client)
    assert command_results.outputs == [{'ChangedBy': 'example2@test.com',
                                        'ChangedUTC': '2020-12-14T09:14:52.148+00:00',
                                        'Content': '<html><body>This device has been frozen by '
                                                   'company.</body></html>',
                                        'CreatedBy': 'example1@test.com',
                                        'CreatedUTC': '2020-11-26T22:29:17.687+00:00',
                                        'ID': '1',
                                        'Name': 'On-demand Freeze message'}]


def test_device_unenroll_command(mocker, absolute_client):
    from Absolute import device_unenroll_command
    response = util_load_json('test_data/unenroll_device_response.json')
    mocker.patch.object(absolute_client, 'api_request_absolute', return_value=response)
    outputs = device_unenroll_command(args={'device_ids': "1,2"}, client=absolute_client).outputs
    assert outputs == [{'DeviceUid': '1',
                        'ESN': '2BU2PJD28VAA1UYL0008',
                        'EligibleStatus': 0,
                        'Serial': 'CNF83051BN',
                        'SystemName': 'user1',
                        'Username': 'example@test.com'},
                       {'DeviceUid': '2',
                        'ESN': '2BU2PJ545L0008',
                        'EligibleStatus': 1,
                        'Serial': 'CNF43051BN',
                        'SystemName': 'user2',
                        'Username': 'example2@test.com'}]


def test_list_device_freeze_message_command_no_id(mocker, absolute_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - list_device_freeze_message command is executed with no message id

    Then:
        - The http request is called with the right arguments
    """
    from Absolute import list_device_freeze_message_command
    http_request = mocker.patch.object(absolute_client, '_http_request', return_value=[])
    list_device_freeze_message_command(client=absolute_client, args={})
    assert http_request.call_args.kwargs['method'] == 'GET'
    assert http_request.call_args.kwargs['url_suffix'] == '/v2/device-freeze/messages'


def test_delete_device_freeze_message_command(mocker, absolute_client):
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
    http_request = mocker.patch.object(absolute_client, '_http_request', return_value=[])
    delete_device_freeze_message_command(client=absolute_client, args={'message_id': message_id})
    assert http_request.call_args.kwargs['method'] == 'DELETE'
    assert http_request.call_args.kwargs['url_suffix'] == f'/v2/device-freeze/messages/{message_id}'


def test_update_device_freeze_message_command(mocker, absolute_client):
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
    http_request = mocker.patch.object(absolute_client, 'api_request_absolute', return_value=[])
    args = {'message_id': message_id, 'html_message': 'text', 'message_name': 'name'}
    update_device_freeze_message_command(client=absolute_client, args=args)
    assert http_request.call_args.args == ('PUT', f'/v2/device-freeze/messages/{message_id}')


def test_create_device_freeze_message_command(mocker, absolute_client):
    """
    Given:
        - All relevant arguments for the command that is executed

    When:
        - create_device_freeze_message_command command is executed

    Then:
        - The http request is called with the right arguments
    """
    from Absolute import create_device_freeze_message_command
    http_request = mocker.patch.object(absolute_client, 'api_request_absolute', return_value={})
    args = {'html_message': 'text', 'message_name': 'name'}
    create_device_freeze_message_command(client=absolute_client, args=args)
    assert http_request.call_args.args == ('POST', '/v2/device-freeze/messages')


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


@pytest.mark.parametrize('page, limit, query, expected_query',
                         [
                             (0, 50, "", "$skip=0&$top=50"),
                             (0, 50, "$filter=accountUid eq '1'&$select=deviceUid",
                              "$filter=accountUid eq '1'&$select=deviceUid&$skip=0&$top=50"),
                         ])
def test_parse_paging(page, limit, query, expected_query):
    from Absolute import parse_paging
    assert parse_paging(page, limit, query) == expected_query


def test_get_device_location_command(mocker, absolute_client):
    from Absolute import get_device_location_command
    response = util_load_json('test_data/device_location_get.json')
    mocker.patch.object(absolute_client, 'api_request_absolute', return_value=response)
    outputs = get_device_location_command(args={'device_ids': "1,2"}, client=absolute_client).outputs
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
