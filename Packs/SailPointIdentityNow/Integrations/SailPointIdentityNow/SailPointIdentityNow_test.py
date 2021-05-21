from CommonServerPython import *

import json
import io
from unittest import mock
from unittest.mock import patch
import SailPointIdentityNow

''' TEST CONSTANTS '''

MOCK_IDENTITYNOW_BASE_URL = 'https://org.api.identitynow.com'
MOCK_BEARER_TOKEN = 'RXAxTEQ0ZkhUVm94dmhIWDd1M2Q0TjU3NDRnQUYzN2ouZXVlV2h1WUk4OW9jMi95Zml'
MOCK_HEADERS = {
    'Authorization': 'Bearer %s' % MOCK_BEARER_TOKEN,
    'Content-Type': 'application/json'
}
MOCK_CLIENT = SailPointIdentityNow.Client(base_url=MOCK_IDENTITYNOW_BASE_URL, verify=False, proxy=False,
                                          headers=MOCK_HEADERS, max_results=250, request_timeout=10)

''' HELPER/UTILITY FUNCTIONS '''


def util_load_txt(path: str):
    """
    Utility to load text data from a local folder.
    """
    with io.open(path, mode='r', encoding='utf-8') as file:
        return file.read()


def util_load_json(path: str):
    """
    Utility to load json data from a local folder.
    """
    with io.open(path, mode='r', encoding='utf-8') as file:
        return json.loads(file.read())


def util_mock_http_resp(status: int, json_data=None):
    """
    Utility to mock http response.
    """
    response = mock.Mock()
    response.status_code = status
    if json_data is not None:
        response.json = mock.Mock(return_value=json_data)
    return response


def verify_identity(identity):
    """
    Verify IdentityNow Identity/User.
    """
    assert identity['id'] is not None
    assert identity['name'] is not None
    assert identity['displayName'] is not None
    assert identity['firstName'] is not None
    assert identity['lastName'] is not None
    assert identity['email'] is not None
    assert identity['created'] is not None
    assert identity['modified'] is not None
    assert isinstance(identity['inactive'], (bool))
    assert identity['protected'] is not None
    assert identity['status'] is not None
    assert isinstance(identity['isManager'], (bool))
    assert identity['identityProfile'] is not None
    assert identity['source'] is not None
    assert identity['attributes'] is not None
    assert identity['accounts'] is not None
    assert identity['accountCount'] >= 0
    assert identity['appCount'] >= 0
    assert identity['accessCount'] >= 0
    assert identity['entitlementCount'] >= 0
    assert identity['roleCount'] >= 0
    assert identity['accessProfileCount'] >= 0
    assert identity['pod'] is not None
    assert identity['org'] is not None
    assert identity['type'] == 'identity'


def verify_account(account):
    """
    Verify IdentityNow Account.
    """
    assert account['id'] is not None
    assert account['name'] is not None
    assert account['sourceId'] is not None
    # assert account['identityId'] is not None
    assert account['nativeIdentity'] is not None
    assert account['created'] is not None
    assert account['modified'] is not None
    assert isinstance(account['disabled'], (bool))
    assert isinstance(account['locked'], (bool))
    assert isinstance(account['authoritative'], (bool))
    assert isinstance(account['systemAccount'], (bool))
    assert isinstance(account['uncorrelated'], (bool))
    assert isinstance(account['manuallyCorrelated'], (bool))
    assert isinstance(account['hasEntitlements'], (bool))
    assert account['attributes'] is not None


def verify_account_activity(account_activity):
    """
    Verify IdentityNow Account Activity.
    """
    assert account_activity['id'] is not None
    assert account_activity['name'] is not None
    assert account_activity['created'] is not None
    assert account_activity['modified'] is not None
    assert account_activity['completed'] is not None
    assert account_activity['completionStatus'] is not None
    assert account_activity['type'] is not None
    assert account_activity['requesterIdentitySummary'] is not None
    assert account_activity['targetIdentitySummary'] is not None
    assert account_activity['items'] is not None
    assert account_activity['executionStatus'] is not None
    assert isinstance(account_activity['cancelable'], (bool))


def verify_access_profile(access_profile):
    """
    Verify IdentityNow Access profile.
    """
    assert access_profile['id'] is not None
    assert access_profile['name'] is not None
    assert access_profile['source'] is not None
    assert access_profile['entitlements'] is not None
    assert access_profile['entitlementCount'] is not None
    assert access_profile['created'] is not None
    assert access_profile['modified'] is not None
    assert access_profile['synced'] is not None
    assert isinstance(access_profile['enabled'], (bool))
    assert isinstance(access_profile['requestable'], (bool))
    assert isinstance(access_profile['requestCommentsRequired'], (bool))
    assert access_profile['owner'] is not None
    assert access_profile['pod'] is not None
    assert access_profile['org'] is not None
    assert access_profile['type'] == 'accessprofile'


def verify_role(role):
    """
    Verify IdentityNow Role.
    """
    assert role['id'] is not None
    assert role['name'] is not None
    assert role['accessProfiles'] is not None
    assert role['created'] is not None
    assert role['modified'] is not None
    assert role['synced'] is not None
    assert isinstance(role['enabled'], (bool))
    assert isinstance(role['requestable'], (bool))
    assert isinstance(role['requestCommentsRequired'], (bool))
    assert role['owner'] is not None
    assert role['pod'] is not None
    assert role['org'] is not None
    assert role['type'] == 'role'


def verify_entitlement(entitlement):
    """
    Verify IdentityNow Entitlement.
    """
    assert entitlement['id'] is not None
    assert entitlement['name'] is not None
    assert entitlement['displayName'] is not None
    assert entitlement['modified'] is not None
    assert entitlement['synced'] is not None
    assert entitlement['source'] is not None
    assert isinstance(entitlement['privileged'], (bool))
    # assert entitlement['identityCount'] >= 0
    assert entitlement['attribute'] is not None
    assert entitlement['value'] is not None
    assert entitlement['schema'] is not None
    assert entitlement['pod'] is not None
    assert entitlement['org'] is not None
    assert entitlement['type'] == 'entitlement'


def verify_event(event):
    """
    Verify IdentityNow Event.
    """
    assert event['id'] is not None
    assert event['name'] is not None
    assert event['stack'] is not None
    assert event['created'] is not None
    assert event['synced'] is not None
    assert event['objects'] is not None
    assert event['technicalName'] is not None
    assert event['target'] is not None
    assert event['actor'] is not None
    assert event['action'] is not None
    assert event['attributes'] is not None
    assert event['operation'] is not None
    assert event['status'] is not None
    assert event['pod'] is not None
    assert event['org'] is not None
    assert event['type'] is not None


''' TESTS (UTILITY)'''


def test_get_headers_all_none():
    headers = SailPointIdentityNow.get_headers(None, None, None, None)
    assert headers is None


def test_get_headers_base_url_none():
    headers = SailPointIdentityNow.get_headers(None, 'test', 'test', 'client_credentials')
    assert headers is None


def test_get_headers_client_id_none():
    headers = SailPointIdentityNow.get_headers(MOCK_IDENTITYNOW_BASE_URL, None, 'test', 'client_credentials')
    assert headers is None


def test_get_headers_client_secret_none():
    headers = SailPointIdentityNow.get_headers(MOCK_IDENTITYNOW_BASE_URL, 'test', None, 'client_credentials')
    assert headers is None


@patch('SailPointIdentityNow.get_headers')
def test_get_headers_grant_type(mock_header):
    mock_header.return_value = {
        'Authorization': 'Bearer RXAxTEQ0ZkhUVm94dmhIWDd1M2Q0TjU3NDRnQUYzN2ouZXVlV2h1WUk4OW9jMi95Zml',
        'Content-Type': 'application/json'
    }
    headers = SailPointIdentityNow.get_headers(MOCK_IDENTITYNOW_BASE_URL, 'test', 'test', None)
    assert headers['Authorization'] == 'Bearer RXAxTEQ0ZkhUVm94dmhIWDd1M2Q0TjU3NDRnQUYzN2ouZXVlV2h1WUk4OW9jMi95Zml'
    assert headers['Content-Type'] == 'application/json'


@patch('SailPointIdentityNow.get_headers')
def test_get_headers_success(mock_header):
    mock_header.return_value = {
        'Authorization': 'Bearer RXAxTEQ0ZkhUVm94dmhIWDd1M2Q0TjU3NDRnQUYzN2ouZXVlV2h1WUk4OW9jMi95Zml',
        'Content-Type': 'application/json'
    }
    headers = SailPointIdentityNow.get_headers(MOCK_IDENTITYNOW_BASE_URL, 'test', 'test', 'client_credentials')
    assert headers['Authorization'] == 'Bearer RXAxTEQ0ZkhUVm94dmhIWDd1M2Q0TjU3NDRnQUYzN2ouZXVlV2h1WUk4OW9jMi95Zml'
    assert headers['Content-Type'] == 'application/json'


def test_build_query_object_all_none():
    query_object = SailPointIdentityNow.build_query_object(None, None)
    assert query_object is None


def test_build_query_object_object_type_none():
    query_object = SailPointIdentityNow.build_query_object(None, "*")
    assert query_object is None


def test_build_query_object_query_none():
    query_object = SailPointIdentityNow.build_query_object("identities", None)
    assert query_object is None


def test_build_query_invalid_object_type():
    query_object = SailPointIdentityNow.build_query_object("test", "*")
    assert query_object is None


def test_build_query():
    query_object = SailPointIdentityNow.build_query_object("identities", "*")
    assert query_object['indices'] == ["identities"]
    assert query_object['query']['query'] == "*"


def test_get_markdown_none():
    markdown = SailPointIdentityNow.get_markdown(None, None)
    assert markdown == ''


def test_get_markdown_object_type_none():
    json_data = util_load_json('test_data/Identity.json')
    markdown = SailPointIdentityNow.get_markdown(None, json_data)
    assert markdown == ''


def test_get_markdown_objects_none():
    markdown = SailPointIdentityNow.get_markdown('IdentityNow.Identity', None)
    headers = ['id', 'name', 'displayName', 'firstName', 'lastName', 'email', 'created', 'modified', 'inactive',
               'protected', 'status', 'isManager', 'identityProfile', 'source', 'attributes', 'accounts',
               'accountCount', 'appCount', 'accessCount', 'entitlementCount', 'roleCount', 'accessProfileCount',
               'pod', 'org', 'type']
    assert markdown == tableToMarkdown('Identity(Identities)', None, headers=headers)


def test_get_markdown():
    json_data = util_load_json('test_data/Identity.json')
    markdown = SailPointIdentityNow.get_markdown('IdentityNow.Identity', json_data)
    headers = ['id', 'name', 'displayName', 'firstName', 'lastName', 'email', 'created', 'modified', 'inactive',
               'protected', 'status', 'isManager', 'identityProfile', 'source', 'attributes', 'accounts',
               'accountCount', 'appCount', 'accessCount', 'entitlementCount', 'roleCount', 'accessProfileCount',
               'pod', 'org', 'type']
    assert markdown == tableToMarkdown('Identity(Identities)', json_data, headers=headers)


def test_build_results_none():
    response = util_mock_http_resp(500, None)
    results = SailPointIdentityNow.build_results(None, None, response)
    assert results is None


def test_build_results_non_2xx_status():
    status_txt = util_load_txt('test_data/404_Not_Found.txt')
    response = util_mock_http_resp(404, status_txt)
    results = SailPointIdentityNow.build_results('Test.prefix', 'Test.key_field', response)
    assert results is None


def test_build_results_2xx_status():
    json_data = util_load_json('test_data/Identity.json')
    response = util_mock_http_resp(200, json_data)
    results = SailPointIdentityNow.build_results('IdentityNow.Identity', 'IdentityNow.Identity', response)
    assert results.readable_output == '### Results:\n' + SailPointIdentityNow.get_markdown('IdentityNow.Identity',
                                                                                           json_data)
    assert results.outputs_prefix == 'IdentityNow.Identity'
    assert results.outputs_key_field == 'IdentityNow.Identity'
    verify_identity(results.outputs)


''' TESTS (COMMAND)'''


@patch('SailPointIdentityNow.get_headers')
def test_connection_fail(mock_header):
    mock_header.side_effect = ConnectionError('Unable to fetch headers from IdentityNow!')
    test_connection = SailPointIdentityNow.test_connection(MOCK_IDENTITYNOW_BASE_URL, 'test', 'test',
                                                           'client_credentials')
    assert test_connection == 'Error Connecting : Unable to fetch headers from IdentityNow!'


@patch('SailPointIdentityNow.get_headers')
def test_connection_unauthorized(mock_header):
    mock_header.side_effect = ConnectionError('Bad client credentials')
    test_connection = SailPointIdentityNow.test_connection(MOCK_IDENTITYNOW_BASE_URL, 'test', 'test',
                                                           'client_credentials')
    assert test_connection == 'Error Connecting : Bad client credentials'


@patch('SailPointIdentityNow.get_headers')
def test_connection_success(mock_header):
    mock_header.return_value = {
        'Authorization': 'Bearer RXAxTEQ0ZkhUVm94dmhIWDd1M2Q0TjU3NDRnQUYzN2ouZXVlV2h1WUk4OW9jMi95Zml',
        'Content-Type': 'application/json'
    }
    test_connection = SailPointIdentityNow.test_connection(MOCK_IDENTITYNOW_BASE_URL, 'test', 'test',
                                                           'client_credentials')
    assert test_connection == 'ok'


def test_search_object_type_none():
    response = SailPointIdentityNow.search(MOCK_CLIENT, None, '*', 0, 0)
    assert response is None


def test_search_object_type_not_in_list():
    response = SailPointIdentityNow.search(MOCK_CLIENT, 'test', '*', 0, 0)
    assert response is None


@patch('SailPointIdentityNow.Client.send_request')
def test_search_negative_offset(mock_search_empty_response):
    json_data = util_load_json('test_data/200_Empty_Response.json')
    mock_search_empty_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.search(MOCK_CLIENT, 'identities', '*', -1, 0)
    assert response.status_code == 200
    assert response.json() == []


@patch('SailPointIdentityNow.Client.send_request')
def test_search_exceeds_limit(mock_search_empty_response):
    json_data = util_load_json('test_data/200_Empty_Response.json')
    mock_search_empty_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.search(MOCK_CLIENT, 'identities', '*', 0, 1000)
    assert response.status_code == 200
    assert response.json() == []


@patch('SailPointIdentityNow.Client.send_request')
def test_search_identity_not_found(mock_search_identity_response):
    json_data = util_load_json('test_data/200_Empty_Response.json')
    mock_search_identity_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.search(MOCK_CLIENT, 'identities', 'id:2c918084740346d5017408d79229489ex', 0, 250)
    assert response.status_code == 200
    assert response.json() == []


@patch('SailPointIdentityNow.Client.send_request')
def test_search_identity_found(mock_search_identity_response):
    json_data = util_load_json('test_data/Identity.json')
    mock_search_identity_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.search(MOCK_CLIENT, 'identities', 'id:2c918084740346d5017408d79229489e', 0, 250)
    assert response.status_code == 200
    verify_identity(response.json())
    assert response.json().get('id') == '2c918084740346d5017408d79229489e'


@patch('SailPointIdentityNow.Client.send_request')
def test_get_accounts_id_not_found(mock_account_response):
    text = util_load_txt('test_data/404_Not_Found.txt')
    mock_account_response.return_value = util_mock_http_resp(404, text)
    response = SailPointIdentityNow.get_accounts(MOCK_CLIENT, '2c918084705f18bd01706349f23e5eb3x', None, None, 0, 250)
    assert response.status_code == 404
    assert response.json() == 'Link with ID or name 2c918084705f18bd01706349f23e5eb3x was not found.'


@patch('SailPointIdentityNow.Client.send_request')
def test_get_accounts_id_found(mock_account_response):
    json_data = util_load_json('test_data/Account.json')
    mock_account_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.get_accounts(MOCK_CLIENT, '2c918084740346d30174088afa6d625e', None, None, 0, 250)
    assert response.status_code == 200
    verify_account(response.json())
    assert response.json().get('id') == '2c918084740346d30174088afa6d625e'


@patch('SailPointIdentityNow.Client.send_request')
def test_get_accounts_name_not_found(mock_account_response):
    json_data = util_load_json('test_data/200_Empty_Response.json')
    mock_account_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.get_accounts(MOCK_CLIENT, None, 'Tes.Testerson', None, 0, 250)
    assert response.status_code == 200
    assert response.json() == []


@patch('SailPointIdentityNow.Client.send_request')
def test_get_accounts_name_found(mock_account_response):
    json_data = util_load_json('test_data/Account.json')
    mock_account_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.get_accounts(MOCK_CLIENT, None, 'Testy.Testerson', 'native_identity', 0, 250)
    assert response.status_code == 200
    verify_account(response.json())
    assert response.json().get('name') == 'Testy.Testerson'


@patch('SailPointIdentityNow.Client.send_request')
def test_get_accounts_native_identity_not_found(mock_account_response):
    json_data = util_load_json('test_data/200_Empty_Response.json')
    mock_account_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.get_accounts(MOCK_CLIENT, None, None, '412632345', 0, 250)
    assert response.status_code == 200
    assert response.json() == []


@patch('SailPointIdentityNow.Client.send_request')
def test_get_accounts_native_identity_found(mock_account_response):
    json_data = util_load_json('test_data/Account.json')
    mock_account_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.get_accounts(MOCK_CLIENT, None, None, '41263', 0, 250)
    assert response.status_code == 200
    verify_account(response.json())
    assert response.json().get('nativeIdentity') == '41263'


@patch('SailPointIdentityNow.Client.send_request')
def test_get_account_activities_id_not_found(mock_account_activities_response):
    json_data = util_load_json('test_data/404_Not_Found.json')
    mock_account_activities_response.return_value = util_mock_http_resp(404, json_data)
    response = SailPointIdentityNow.get_account_activities(MOCK_CLIENT, '2c918084705f18bd01706349f23e5eb3x', None, None,
                                                           None, None, 0, 250)
    assert response.status_code == 404
    assert response.json().get('detailCode') == '404 Not found'


@patch('SailPointIdentityNow.Client.send_request')
def test_get_account_activities_id_found(mock_account_activities_response):
    json_data = util_load_json('test_data/Account_Activity.json')
    mock_account_activities_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.get_account_activities(MOCK_CLIENT, '4fcac89c839f4e4dbeef2810a435f9f6', None, None,
                                                           None, None, 0, 250)
    assert response.status_code == 200
    verify_account_activity(response.json())
    assert response.json().get('id') == '4fcac89c839f4e4dbeef2810a435f9f6'


@patch('SailPointIdentityNow.Client.send_request')
def test_get_account_activities_requested_for_not_found(mock_account_activities_response):
    json_data = util_load_json('test_data/400_Bad_Request_Content.json')
    mock_account_activities_response.return_value = util_mock_http_resp(400, json_data)
    response = SailPointIdentityNow.get_account_activities(MOCK_CLIENT, None, '2c91808a6fca28a6016fd7f5ec3f5228x', None,
                                                           None, None, 0, 250)
    assert response.status_code == 400
    assert response.json().get('detailCode') == '400.1 Bad request content'


@patch('SailPointIdentityNow.Client.send_request')
def test_get_account_activities_requested_for_found(mock_account_activities_response):
    json_data = util_load_json('test_data/Account_Activity.json')
    mock_account_activities_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.get_account_activities(MOCK_CLIENT, None, '2c91808a6fca28a6016fd7f5ec3f5228', None,
                                                           None, None, 0, 250)
    assert response.status_code == 200
    verify_account_activity(response.json())
    assert response.json().get('targetIdentitySummary').get('id') == '2c91808a6fca28a6016fd7f5ec3f5228'


@patch('SailPointIdentityNow.Client.send_request')
def test_get_account_activities_requested_by_not_found(mock_account_activities_response):
    json_data = util_load_json('test_data/400_Bad_Request_Content.json')
    mock_account_activities_response.return_value = util_mock_http_resp(400, json_data)
    response = SailPointIdentityNow.get_account_activities(MOCK_CLIENT, None, None, '2c91808363f06ad80163fb690fae55b8x',
                                                           None, None, 0, 250)
    assert response.status_code == 400
    assert response.json().get('detailCode') == '400.1 Bad request content'


@patch('SailPointIdentityNow.Client.send_request')
def test_get_account_activities_requested_by_found(mock_account_activities_response):
    json_data = util_load_json('test_data/Account_Activity.json')
    mock_account_activities_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.get_account_activities(MOCK_CLIENT, None, None, '2c91808363f06ad80163fb690fae55b8',
                                                           None, None, 0, 250)
    assert response.status_code == 200
    verify_account_activity(response.json())
    assert response.json().get('requesterIdentitySummary').get('id') == '2c91808363f06ad80163fb690fae55b8'


@patch('SailPointIdentityNow.Client.send_request')
def test_get_account_activities_regarding_identity_not_found(mock_account_activities_response):
    json_data = util_load_json('test_data/400_Bad_Request_Content.json')
    mock_account_activities_response.return_value = util_mock_http_resp(400, json_data)
    response = SailPointIdentityNow.get_account_activities(MOCK_CLIENT, None, None, None,
                                                           '2c91808a6fca28a6016fd7f5ec3f5228x', None, 0, 250)
    assert response.status_code == 400
    assert response.json().get('detailCode') == '400.1 Bad request content'


@patch('SailPointIdentityNow.Client.send_request')
def test_get_account_activities_regarding_identity_found(mock_account_activities_response):
    json_data = util_load_json('test_data/Account_Activity.json')
    mock_account_activities_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.get_account_activities(MOCK_CLIENT, None, None, None,
                                                           '2c91808a6fca28a6016fd7f5ec3f5228', None, 0, 250)
    assert response.status_code == 200
    verify_account_activity(response.json())
    assert response.json().get('requesterIdentitySummary').get('id') == '2c91808363f06ad80163fb690fae55b8'


@patch('SailPointIdentityNow.Client.send_request')
def test_get_account_activities_type_not_found(mock_account_activities_response):
    json_data = util_load_json('test_data/200_Empty_Response.json')
    mock_account_activities_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.get_account_activities(MOCK_CLIENT, None, None, None, None, 'Test', 0, 250)
    assert response.status_code == 200


@patch('SailPointIdentityNow.Client.send_request')
def test_get_account_activities_type_found(mock_account_activities_response):
    json_data = util_load_json('test_data/Account_Activity.json')
    mock_account_activities_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.get_account_activities(MOCK_CLIENT, None, None, None, None, 'appRequest', 0, 250)
    assert response.status_code == 200
    verify_account_activity(response.json())
    assert response.json().get('type') == 'appRequest'


@patch('SailPointIdentityNow.Client.send_request')
def test_get_account_activities(mock_account_activities_response):
    json_data = util_load_json('test_data/Account_Activity.json')
    mock_account_activities_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.get_account_activities(MOCK_CLIENT, None, '2c91808a6fca28a6016fd7f5ec3f5228',
                                                           '2c91808363f06ad80163fb690fae55b8', None, None, 0, 250)
    assert response.status_code == 200
    verify_account_activity(response.json())
    assert response.json().get('targetIdentitySummary').get('id') == '2c91808a6fca28a6016fd7f5ec3f5228'
    assert response.json().get('requesterIdentitySummary').get('id') == '2c91808363f06ad80163fb690fae55b8'


@patch('SailPointIdentityNow.Client.send_request')
def test_search_access_profile_not_found(mock_search_access_profile_response):
    json_data = util_load_json('test_data/200_Empty_Response.json')
    mock_search_access_profile_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.search(MOCK_CLIENT, 'accessprofiles', 'id:2c91808a700d408901701223fb6b007d', 0, 250)
    assert response.status_code == 200
    assert response.json() == []


@patch('SailPointIdentityNow.Client.send_request')
def test_search_access_profile_found(mock_search_access_profile_response):
    json_data = util_load_json('test_data/Access_Profile.json')
    mock_search_access_profile_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.search(MOCK_CLIENT, 'accessprofiles', 'id:2c91808a700d408901701223fb6b0077', 0, 250)
    assert response.status_code == 200
    verify_access_profile(response.json())
    assert response.json().get('id') == '2c91808a700d408901701223fb6b0077'


@patch('SailPointIdentityNow.Client.send_request')
def test_search_role_not_found(mock_search_role_response):
    json_data = util_load_json('test_data/200_Empty_Response.json')
    mock_search_role_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.search(MOCK_CLIENT, 'roles', 'id:2c9180846ff9c50201700beb2e9000dd', 0, 250)
    assert response.status_code == 200
    assert response.json() == []


@patch('SailPointIdentityNow.Client.send_request')
def test_search_role_found(mock_search_role_response):
    json_data = util_load_json('test_data/Role.json')
    mock_search_role_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.search(MOCK_CLIENT, 'roles', 'id:2c9180846ff9c50201700beb2e9000da', 0, 250)
    assert response.status_code == 200
    verify_role(response.json())
    assert response.json().get('id') == '2c9180846ff9c50201700beb2e9000da'


@patch('SailPointIdentityNow.Client.send_request')
def test_search_entitlement_not_found(mock_search_entitlement_response):
    json_data = util_load_json('test_data/200_Empty_Response.json')
    mock_search_entitlement_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.search(MOCK_CLIENT, 'entitlements', 'id:2c9180846ff7e56b01700bb399f60ead', 0, 250)
    assert response.status_code == 200
    assert response.json() == []


@patch('SailPointIdentityNow.Client.send_request')
def test_search_entitlement_found(mock_search_entitlement_response):
    json_data = util_load_json('test_data/Entitlement.json')
    mock_search_entitlement_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.search(MOCK_CLIENT, 'entitlements', 'id:2c9180846ff7e56b01700bb399f60eaa', 0, 250)
    assert response.status_code == 200
    verify_entitlement(response.json())
    assert response.json().get('id') == '2c9180846ff7e56b01700bb399f60eaa'


@patch('SailPointIdentityNow.Client.send_request')
def test_search_event_not_found(mock_search_event_response):
    json_data = util_load_json('test_data/200_Empty_Response.json')
    mock_search_event_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.search(MOCK_CLIENT, 'events', 'id:2bd61299-d986-4c27-bd37-408b9c9ba11d', 0, 250)
    assert response.status_code == 200
    assert response.json() == []


@patch('SailPointIdentityNow.Client.send_request')
def test_search_event_found(mock_search_event_response):
    json_data = util_load_json('test_data/Event.json')
    mock_search_event_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityNow.search(MOCK_CLIENT, 'events', 'id:2bd61299-d986-4c27-bd37-408b9c9ba118', 0, 250)
    assert response.status_code == 200
    verify_event(response.json())
    assert response.json().get('id') == '2bd61299-d986-4c27-bd37-408b9c9ba118'


def test_access_request_requested_for_none():
    response = SailPointIdentityNow.access_request(MOCK_CLIENT, 'GRANT_ACCESS', None,
                                                   '2c918086775e1f5d0177653720ea0381', 'ROLE', 'Testing')
    assert response is None


def test_access_request_requested_item_none():
    response = SailPointIdentityNow.access_request(MOCK_CLIENT, 'GRANT_ACCESS', '2c91808363f06ad80163fb690fae55b8',
                                                   None, 'ROLE', 'Testing')
    assert response is None


def test_access_request_requested_item_type_none():
    response = SailPointIdentityNow.access_request(MOCK_CLIENT, 'GRANT_ACCESS', '2c91808363f06ad80163fb690fae55b8',
                                                   '2c918086775e1f5d0177653720ea0381', None, 'Testing')
    assert response is None


@patch('SailPointIdentityNow.Client.send_request')
def test_access_request_requested_for_not_found(mock_access_request_grant_response):
    json_data = util_load_json('test_data/400_Bad_Request_Object_Not_Found.json')
    mock_access_request_grant_response.return_value = util_mock_http_resp(400, json_data)
    response = SailPointIdentityNow.access_request(MOCK_CLIENT, 'GRANT_ACCESS', '2c9180886ccef167016cdb658fb6547d',
                                                   '2c918086775e1f5d0177653720ea0381', 'ROLE', 'Testing')
    assert response.get('detailCode') == '400.1.404 Referenced object not found'


@patch('SailPointIdentityNow.Client.send_request')
def test_access_request_requested_item_not_found(mock_access_request_grant_response):
    json_data = util_load_json('test_data/400_Bad_Request_Object_Not_Found.json')
    mock_access_request_grant_response.return_value = util_mock_http_resp(400, json_data)
    response = SailPointIdentityNow.access_request(MOCK_CLIENT, 'GRANT_ACCESS', '2c9180886ccef167016cdb658fb6547d',
                                                   '2c918086775e1f5d0177653720ea038d', 'ROLE', 'Testing')
    assert response.get('detailCode') == '400.1.404 Referenced object not found'


@patch('SailPointIdentityNow.Client.send_request')
def test_access_request_requested_item_type_invalid(mock_access_request_grant_response):
    json_data = util_load_json('test_data/400_Bad_Request_Illegal_Value.json')
    mock_access_request_grant_response.return_value = util_mock_http_resp(400, json_data)
    response = SailPointIdentityNow.access_request(MOCK_CLIENT, 'GRANT_ACCESS', '2c9180886ccef167016cdb658fb6547d',
                                                   '2c918086775e1f5d0177653720ea038d', 'TEST', 'Testing')
    assert response.get('detailCode') == '400.1.3 Illegal value'


@patch('SailPointIdentityNow.Client.send_request')
def test_access_request_re_grant(mock_access_request_grant_response):
    json_data = util_load_json('test_data/400_Bad_Request_Content.json')
    mock_access_request_grant_response.return_value = util_mock_http_resp(400, json_data)
    response = SailPointIdentityNow.access_request(MOCK_CLIENT, 'GRANT_ACCESS', '2c9180886ccef167016cdb658fb6547a',
                                                   '2c918086775e1f5d01776530eb67037b', 'TEST', 'Testing')
    assert response.get('detailCode') == '400.1 Bad request content'


@patch('SailPointIdentityNow.Client.send_request')
def test_access_request_grant(mock_access_request_grant_response):
    mock_access_request_grant_response.return_value = util_mock_http_resp(200, None)
    response = SailPointIdentityNow.access_request(MOCK_CLIENT, 'GRANT_ACCESS', '2c91808363f06ad80163fb690fae55b8',
                                                   '2c918086775e1f5d0177653720ea0381', 'ROLE', 'Testing')
    assert response == 'Access request was successful!'


@patch('SailPointIdentityNow.Client.send_request')
def test_access_request_revoke(mock_access_request_revoke_response):
    mock_access_request_revoke_response.return_value = util_mock_http_resp(200, None)
    response = SailPointIdentityNow.access_request(MOCK_CLIENT, 'REVOKE_ACCESS', '2c91808363f06ad80163fb690fae55b8',
                                                   '2c918086775e1f5d0177653720ea0381', 'ROLE', 'Testing')
    assert response == 'Access request was successful!'
