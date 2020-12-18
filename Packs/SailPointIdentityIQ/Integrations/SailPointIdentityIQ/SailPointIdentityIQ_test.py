from CommonServerPython import *

import json
import io
import pytest
from unittest import mock
from unittest.mock import patch
import SailPointIdentityIQ

''' TEST CONSTANTS '''

MOCK_IIQ_BASE_URL = 'https://identityiq-server.com/identityiq'

''' HELPER/UTILITY FUNCTIONS '''


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


def verify_scim_list_response(response, total_results):
    """
    Verify SCIM structure for list response.
    """
    assert response['totalResults'] == total_results
    assert len(response['Resources']) == total_results

    if 'startIndex' in response:
        assert response['startIndex'] == 1

    if 'schemas' in response:
        assert 'urn:ietf:params:scim:api:messages:2.0:ListResponse' in response['schemas']


def verify_user(user):
    """
    Verify SCIM structure for IdentityIQ User.
    """
    assert user['id'] is not None
    assert user['userName'] is not None
    assert user['active'] is True
    assert user['displayName'] is not None
    assert 'urn:ietf:params:scim:schemas:core:2.0:User' in user['schemas']


def verify_policy_violation(policy_violation):
    """
    Verify SCIM structure for IdentityIQ PolicyViolation.
    """
    assert policy_violation['id'] is not None
    assert policy_violation['constraintName'] is not None
    assert policy_violation['status'] in ['Open', 'Closed', 'Mitigated']
    assert policy_violation['policyName'] is not None
    assert 'urn:ietf:params:scim:schemas:sailpoint:1.0:PolicyViolation' in policy_violation['schemas']
    assert policy_violation['identity']['displayName'] is not None
    assert policy_violation['identity']['value'] is not None


def verify_task_result(task_result):
    """
    Verify SCIM structure for IdentityIQ TaskResult.
    """
    assert task_result['id'] is not None
    assert task_result['taskDefinition'] is not None
    assert task_result['name'] is not None
    assert task_result['host'] is not None
    assert task_result['type'] is not None
    assert task_result['pendingSignoffs'] is not None
    assert task_result['completionStatus'] in ['Success', 'Error']
    assert task_result['launcher'] is not None
    assert task_result['completed'] is not None


def verify_account(account):
    """
    Verify SCIM structure for IdentityIQ Account response.
    """
    assert account['id'] is not None
    assert account['nativeIdentity'] is not None
    assert account['identity']['displayName'] is not None
    assert account['identity']['value'] is not None
    assert account['application']['displayName'] is not None
    assert account['application']['value'] is not None
    assert account['hasEntitlements'] is not None
    assert account['active'] is not None


def verify_launched_workflow(launched_workflow):
    """
    Verify SCIM structure for IdentityIQ Launched Workflow response.
    """
    assert launched_workflow['id'] is not None
    assert launched_workflow['name'] is not None
    assert launched_workflow['launcher'] is not None
    assert launched_workflow['type'] is not None
    assert launched_workflow['completionStatus'] in ['Success', 'Error']
    assert launched_workflow['terminated'] is not None
    assert launched_workflow['targetClass'] is not None


def verify_role(role):
    """
    Verify SCIM structure for IdentityIQ Role response.
    """
    assert role['id'] is not None
    assert role['name'] is not None
    assert role['displayableName'] is not None
    assert role['active'] is not None
    assert role['owner']['displayName'] is not None
    assert role['owner']['value'] is not None
    assert role['type']['name'] is not None
    assert role['type']['autoAssignment'] is not None
    assert role['type']['displayName'] is not None
    assert role['type']['manualAssignment'] is not None


def verify_entitlement(entitlement):
    """
    Verify SCIM structure for IdentityIQ Entitlement response.
    """
    assert entitlement['id'] is not None
    assert entitlement['type'] is not None
    assert entitlement['requestable'] is not None
    assert entitlement['aggregated'] is not None
    assert entitlement['application']['displayName'] is not None
    assert entitlement['application']['value'] is not None
    assert entitlement['owner']['displayName'] is not None
    assert entitlement['owner']['value'] is not None


def verify_alert(alert):
    """
    Verify SCIM structure for IdentityIQ Alert response.
    """
    assert alert['id'] is not None
    assert alert['name'] is not None
    assert alert['displayName'] is not None
    assert alert['meta']['created'] is not None


''' TESTS (UTILITY)'''


def test_get_oauth_headers_none():
    headers = SailPointIdentityIQ.get_oauth_headers(None, None, None)
    assert headers is None


def test_get_oauth_headers_client_id_none():
    headers = SailPointIdentityIQ.get_oauth_headers(None, 'test', 'client_credentials')
    assert headers is None


def test_get_oauth_headers_client_secret_none():
    headers = SailPointIdentityIQ.get_oauth_headers('test', None, 'client_credentials')
    assert headers is None


@patch('SailPointIdentityIQ.get_oauth_headers')
def test_get_oauth_headers_grant_type(mock_oauth_header):
    mock_oauth_header.return_value = {
        'Authorization': 'Bearer RXAxTEQ0ZkhUVm94dmhIWDd1M2Q0TjU3NDRnQUYzN2ouZXVlV2h1WUk4OW9jMi95Zml',
        'Content-Type': 'application/json'
    }
    headers = SailPointIdentityIQ.get_oauth_headers('test', 'test', None)
    assert headers['Authorization'] == 'Bearer RXAxTEQ0ZkhUVm94dmhIWDd1M2Q0TjU3NDRnQUYzN2ouZXVlV2h1WUk4OW9jMi95Zml'
    assert headers['Content-Type'] == 'application/json'


@patch('SailPointIdentityIQ.get_oauth_headers')
def test_get_oauth_headers_success(mock_oauth_header):
    mock_oauth_header.return_value = {
        'Authorization': 'Bearer RXAxTEQ0ZkhUVm94dmhIWDd1M2Q0TjU3NDRnQUYzN2ouZXVlV2h1WUk4OW9jMi95Zml',
        'Content-Type': 'application/json'
    }
    headers = SailPointIdentityIQ.get_oauth_headers('test', 'test', 'client_credentials')
    assert headers['Authorization'] == 'Bearer RXAxTEQ0ZkhUVm94dmhIWDd1M2Q0TjU3NDRnQUYzN2ouZXVlV2h1WUk4OW9jMi95Zml'
    assert headers['Content-Type'] == 'application/json'


def test_get_basic_auth_headers_none():
    headers = SailPointIdentityIQ.get_basic_auth_headers(None, None)
    assert headers is None


def test_get_basic_auth_headers_username_none():
    headers = SailPointIdentityIQ.get_basic_auth_headers(None, 'test')
    assert headers is None


def test_get_basic_auth_headers_password_none():
    headers = SailPointIdentityIQ.get_basic_auth_headers('test', None)
    assert headers is None


def test_get_basic_auth_headers_success():
    headers = SailPointIdentityIQ.get_basic_auth_headers('test', 'test')
    assert headers['Authorization'] == 'Basic dGVzdDp0ZXN0'
    assert headers['Content-Type'] == 'application/json'


def test_get_headers_none():
    headers = SailPointIdentityIQ.get_headers(None)
    assert headers is None


@patch('SailPointIdentityIQ.get_headers')
def test_get_headers_oauth_success(mock_header):
    mock_header.return_value = {
        'Authorization': 'Bearer RXAxTEQ0ZkhUVm94dmhIWDd1M2Q0TjU3NDRnQUYzN2ouZXVlV2h1WUk4OW9jMi95Zml',
        'Content-Type': 'application/json'
    }
    headers = SailPointIdentityIQ.get_headers('OAUTH')
    assert headers['Authorization'] == 'Bearer RXAxTEQ0ZkhUVm94dmhIWDd1M2Q0TjU3NDRnQUYzN2ouZXVlV2h1WUk4OW9jMi95Zml'
    assert headers['Content-Type'] == 'application/json'


@patch('SailPointIdentityIQ.get_headers')
def test_get_headers_basic_success(mock_header):
    mock_header.return_value = {
        'Authorization': 'Basic dGVzdDp0ZXN0',
        'Content-Type': 'application/json'
    }
    headers = SailPointIdentityIQ.get_headers('BASIC')
    assert headers['Authorization'] == 'Basic dGVzdDp0ZXN0'
    assert headers['Content-Type'] == 'application/json'


@patch('SailPointIdentityIQ.send_request')
def test_send_request_none(mock_response):
    mock_response.return_value = None
    response = SailPointIdentityIQ.send_request(None, None, None)
    assert response is None


@patch('SailPointIdentityIQ.send_request')
def test_send_request_url_none(mock_response):
    mock_response.return_value = None
    response = SailPointIdentityIQ.send_request(None, 'GET', None)
    assert response is None


@patch('SailPointIdentityIQ.send_request')
def test_send_request_method_none(mock_response):
    mock_response.return_value = None
    response = SailPointIdentityIQ.send_request(MOCK_IIQ_BASE_URL, None, None)
    assert response is None


@patch('SailPointIdentityIQ.send_request')
def test_send_request_non_200_status(mock_response):
    """
    Send request should return None in case of 3XX, 4XX or 5XX HTTP status from IdentityIQ.
    """
    json_data = util_load_json('test_data/404_Not_Found.json')
    mock_response.return_value = util_mock_http_resp(404, json_data)
    response = SailPointIdentityIQ.send_request(MOCK_IIQ_BASE_URL, 'GET', None)
    assert response.status_code == 404
    assert 'urn:ietf:params:scim:api:messages:2.0:Error' in response.json()['schemas']
    assert response.json()['status'] == '404'


@patch('SailPointIdentityIQ.send_request')
def test_send_request_success(mock_response):
    """
    Send request should return response json in case of 2XX HTTP status from IdentityIQ.
    """
    json_data = util_load_json('test_data/ResourceTypes.json')
    mock_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.send_request(MOCK_IIQ_BASE_URL, 'GET', None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), response.json()['totalResults'])


def test_transform_object_list_none_all():
    data_list = SailPointIdentityIQ.transform_object_list(None, None)
    assert data_list is None


def test_transform_object_list_type_none():
    json_data = util_load_json('test_data/Users.json')
    data_list = SailPointIdentityIQ.transform_object_list(None, json_data['Resources'])
    assert data_list == json_data['Resources']


def test_transform_object_list_none():
    data_list = SailPointIdentityIQ.transform_object_list('IdentityIQ.Identity', None)
    assert data_list is None


def test_transform_object_list():
    json_data = util_load_json('test_data/Users.json')
    data_list = SailPointIdentityIQ.transform_object_list('IdentityIQ.Identity', json_data['Resources'])
    assert data_list == json_data['Resources']

    for data in data_list:
        assert 'sailpointUser' in data

    for resource in json_data['Resources']:
        assert 'sailpointUser' in resource


def test_transform_object_none_all():
    data = SailPointIdentityIQ.transform_object(None, None)
    assert data is None


def test_transform_object_type_none():
    json_data = util_load_json('test_data/User.json')
    data = SailPointIdentityIQ.transform_object(None, json_data)
    assert data == json_data


def test_transform_object_none():
    data = SailPointIdentityIQ.transform_object('IdentityIQ.Identity', None)
    assert data is None


def test_transform_object():
    json_data = util_load_json('test_data/User.json')
    data = SailPointIdentityIQ.transform_object('IdentityIQ.Identity', json_data)
    assert data == json_data
    assert 'sailpointUser' in data
    assert 'sailpointUser' in json_data


def test_get_markdown_none():
    markdown = SailPointIdentityIQ.get_markdown(None, None)
    assert markdown == ''


def test_get_markdown_object_type_none():
    json_data = util_load_json('test_data/User.json')
    markdown = SailPointIdentityIQ.get_markdown(None, json_data)
    assert markdown == ''


def test_get_markdown_objects_none():
    markdown = SailPointIdentityIQ.get_markdown('IdentityIQ.Identity', None)
    headers = ['id', 'userName', 'displayName', 'name', 'emails', 'sailpointUser', 'extendedUser', 'entitlements',
               'roles', 'capabilities', 'active']
    assert markdown == tableToMarkdown('Identity', None, headers=headers)


def test_get_markdown():
    json_data = util_load_json('test_data/User.json')
    markdown = SailPointIdentityIQ.get_markdown('IdentityIQ.Identity', json_data)
    headers = ['id', 'userName', 'displayName', 'name', 'emails', 'sailpointUser', 'extendedUser', 'entitlements',
               'roles', 'capabilities', 'active']
    assert markdown == tableToMarkdown('Identity', json_data, headers=headers)


def test_build_results_none():
    response = util_mock_http_resp(500, None)
    with pytest.raises(TypeError):
        SailPointIdentityIQ.build_results(None, None, response)


def test_build_results_non_2xx_status():
    json_data = util_load_json('test_data/404_Not_Found.json')
    response = util_mock_http_resp(404, json_data)
    results = SailPointIdentityIQ.build_results('Test.prefix', 'Test.key_field', response)
    assert results == '404 : Resource 7f000001705911b4817059d30cf50348 not found.'


def test_build_results_2xx_status():
    json_data = util_load_json('test_data/User.json')
    response = util_mock_http_resp(200, json_data)
    results = SailPointIdentityIQ.build_results('IdentityIQ.Identity', 'IdentityIQ.Identity', response)
    assert results.readable_output == '### Results:\n' + SailPointIdentityIQ.get_markdown('IdentityIQ.Identity',
                                                                                          json_data)
    assert results.outputs_prefix == 'IdentityIQ.Identity'
    assert results.outputs_key_field == 'IdentityIQ.Identity'
    verify_user(results.outputs)


''' TESTS (COMMAND)'''


@patch('SailPointIdentityIQ.send_request')
def test_connection_fail(mock_response):
    mock_response.return_value = util_mock_http_resp(404, None)
    test_connection = SailPointIdentityIQ.test_connection()
    assert test_connection == 'Unable to connect to IdentityIQ!'


@patch('SailPointIdentityIQ.send_request')
def test_connection_success(mock_response):
    mock_response.return_value = util_mock_http_resp(200, None)
    test_connection = SailPointIdentityIQ.test_connection()
    assert test_connection == 'ok'


@patch('SailPointIdentityIQ.send_request')
def test_search_identities_no_resources(mock_search_identities_response):
    json_data = util_load_json('test_data/NoResources.json')
    mock_search_identities_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.search_identities(None, None, 0, False)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 0)


@patch('SailPointIdentityIQ.send_request')
def test_search_identities_id_not_found(mock_search_identities_response):
    json_data = util_load_json('test_data/404_Not_Found.json')
    mock_search_identities_response.return_value = util_mock_http_resp(404, json_data)
    response = SailPointIdentityIQ.search_identities('7f000001705911b4817059d30cf50348', None, 0, True)
    assert response.status_code == 404
    assert response.json()['status'] == '404'
    assert response.json()['detail'] == 'Resource 7f000001705911b4817059d30cf50348 not found.'


@patch('SailPointIdentityIQ.send_request')
def test_search_identities_id_found(mock_search_identities_response):
    json_data = util_load_json('test_data/User.json')
    mock_search_identities_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.search_identities('7f00000174441779817444c8842b0017', None, 0, True)
    assert response.status_code == 200
    verify_user(response.json())
    assert response.json()['id'] == '7f00000174441779817444c8842b0017'


@patch('SailPointIdentityIQ.send_request')
def test_search_identities_email_not_found(mock_search_identities_response):
    json_data = util_load_json('test_data/NoResources.json')
    mock_search_identities_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.search_identities(None, 'test@sailpointdemo.com', 0, True)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 0)


@patch('SailPointIdentityIQ.send_request')
def test_search_identities_email_found(mock_search_identities_response):
    json_data = util_load_json('test_data/User_Filtered.json')
    mock_search_identities_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.search_identities(None, 'serviceaccount@sailpointdemo.com', 0, True)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 1)
    user = response.json()['Resources'][0]
    verify_user(user)
    assert user['id'] == '7f000001705914d1817059d59e18000e'
    has_email = False
    for email in user['emails']:
        if email['value'] == 'serviceaccount@sailpointdemo.com':
            has_email = True
    assert has_email is True


@patch('SailPointIdentityIQ.send_request')
def test_search_identities_risk_score_not_matched(mock_search_identities_response):
    json_data = util_load_json('test_data/NoResources.json')
    mock_search_identities_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.search_identities(None, None, 1600, True)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 0)


@patch('SailPointIdentityIQ.send_request')
def test_search_identities_risk_score_invalid(mock_search_identities_response):
    json_data = util_load_json('test_data/400_Bad_Request.json')
    mock_search_identities_response.return_value = util_mock_http_resp(400, json_data)
    response = SailPointIdentityIQ.search_identities(None, None, -1, True)
    assert response.status_code == 400
    assert response.json()['status'] == '400'
    assert response.json()['detail'] == 'Invalid filter:urn:ietf:params:scim:schemas:sailpoint:1.0:User:riskScore eq -1'
    assert 'urn:ietf:params:scim:api:messages:2.0:Error' in response.json()['schemas']


@patch('SailPointIdentityIQ.send_request')
def test_search_identities_risk_score_matched(mock_search_identities_response):
    json_data = util_load_json('test_data/User_Filtered.json')
    mock_search_identities_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.search_identities(None, None, 100, True)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 1)
    user = response.json()['Resources'][0]
    verify_user(user)
    assert user['id'] == '7f000001705914d1817059d59e18000e'
    assert user['urn:ietf:params:scim:schemas:sailpoint:1.0:User']['riskScore'] >= 100


@patch('SailPointIdentityIQ.send_request')
def test_search_identities_active_false(mock_search_identities_response):
    json_data = util_load_json('test_data/NoResources.json')
    mock_search_identities_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.search_identities(None, None, 0, True)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 0)


@patch('SailPointIdentityIQ.send_request')
def test_search_identities_active_true(mock_search_identities_response):
    json_data = util_load_json('test_data/Users.json')
    mock_search_identities_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.search_identities(None, None, 0, True)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 5)
    for user in response.json()['Resources']:
        verify_user(user)
        assert user['active'] is True


@patch('SailPointIdentityIQ.send_request')
def test_get_policy_violations_id_not_found(mock_policy_violations_response):
    json_data = util_load_json('test_data/404_Not_Found.json')
    mock_policy_violations_response.return_value = util_mock_http_resp(404, json_data)
    response = SailPointIdentityIQ.get_policy_violations('8a8080824df45873014df46036521343')
    assert response.status_code == 404
    assert 'urn:ietf:params:scim:api:messages:2.0:Error' in response.json()['schemas']
    assert response.json()['status'] == '404'


@patch('SailPointIdentityIQ.send_request')
def test_get_policy_violations_id_found(mock_policy_violations_response):
    json_data = util_load_json('test_data/PolicyViolation.json')
    mock_policy_violations_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_policy_violations('8a8080824df45873014df46036521328')
    assert response.status_code == 200
    verify_policy_violation(response.json())
    assert response.json()['id'] == '8a8080824df45873014df46036521328'


@patch('SailPointIdentityIQ.send_request')
def test_get_policy_violations_no_resources(mock_policy_violations_response):
    json_data = util_load_json('test_data/NoResources.json')
    mock_policy_violations_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_policy_violations(None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 0)


@patch('SailPointIdentityIQ.send_request')
def test_get_policy_violations(mock_policy_violations_response):
    json_data = util_load_json('test_data/PolicyViolations.json')
    mock_policy_violations_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_policy_violations(None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 2)
    for policy_violation in response.json()['Resources']:
        verify_policy_violation(policy_violation)


@patch('SailPointIdentityIQ.send_request')
def test_get_task_results_id_not_found(mock_task_results_response):
    json_data = util_load_json('test_data/404_Not_Found.json')
    mock_task_results_response.return_value = util_mock_http_resp(404, json_data)
    response = SailPointIdentityIQ.get_task_results('7f00000175891f4b81763bd218de1d64')
    assert response.status_code == 404
    assert 'urn:ietf:params:scim:api:messages:2.0:Error' in response.json()['schemas']
    assert response.json()['status'] == '404'


@patch('SailPointIdentityIQ.send_request')
def test_get_task_results_id_found(mock_task_results_response):
    json_data = util_load_json('test_data/TaskResult.json')
    mock_task_results_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_task_results('7f00000175891f4b81763bd2181c1d5f')
    assert response.status_code == 200
    verify_task_result(response.json())


@patch('SailPointIdentityIQ.send_request')
def test_get_task_results_no_resources(mock_task_results_response):
    json_data = util_load_json('test_data/NoResources.json')
    mock_task_results_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_task_results(None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 0)


@patch('SailPointIdentityIQ.send_request')
def test_get_task_results(mock_task_results_response):
    json_data = util_load_json('test_data/TaskResults.json')
    mock_task_results_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_task_results(None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 5)
    for task_result in response.json()['Resources']:
        verify_task_result(task_result)


@patch('SailPointIdentityIQ.send_request')
def test_get_accounts_no_resources(mock_accounts_response):
    json_data = util_load_json('test_data/NoResources.json')
    mock_accounts_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_accounts(None, None, None, None, None, None, None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 0)


@patch('SailPointIdentityIQ.send_request')
def test_get_accounts_id_not_found(mock_accounts_response):
    json_data = util_load_json('test_data/404_Not_Found.json')
    mock_accounts_response.return_value = util_mock_http_resp(404, json_data)
    response = SailPointIdentityIQ.get_accounts('7f00000174441779817444c8837c5373', None, None, None, None, None, None)
    assert response.status_code == 404
    assert 'urn:ietf:params:scim:api:messages:2.0:Error' in response.json()['schemas']
    assert response.json()['status'] == '404'


@patch('SailPointIdentityIQ.send_request')
def test_get_accounts_id_found(mock_accounts_response):
    json_data = util_load_json('test_data/Account.json')
    mock_accounts_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_accounts('7f00000174441779817444c8837c0014', None, None, None, None, None, None)
    assert response.status_code == 200
    verify_account(response.json())


@patch('SailPointIdentityIQ.send_request')
def test_get_accounts_display_name_not_found(mock_accounts_response):
    json_data = util_load_json('test_data/NoResources.json')
    mock_accounts_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_accounts(None, 'Black Jack', None, None, None, None, None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 0)


@patch('SailPointIdentityIQ.send_request')
def test_get_accounts_display_name_found(mock_accounts_response):
    json_data = util_load_json('test_data/Account_Filtered.json')
    mock_accounts_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_accounts(None, 'bjack', None, None, None, None, None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 1)
    account = response.json()['Resources'][0]
    verify_account(account)
    assert account['id'] == '7f00000174441779817444c883c30016'
    assert account['displayName'] == 'bjack'


@patch('SailPointIdentityIQ.send_request')
def test_get_accounts_last_refresh_not_matched(mock_accounts_response):
    json_data = util_load_json('test_data/NoResources.json')
    mock_accounts_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_accounts(None, None, '2020-12-10T08:50:25Z', None, None, None, None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 0)


@patch('SailPointIdentityIQ.send_request')
def test_get_accounts_last_refresh_matched(mock_accounts_response):
    json_data = util_load_json('test_data/Account_Filtered.json')
    mock_accounts_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_accounts(None, None, '2020-08-31T00:00:00Z', None, None, None, None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 1)
    account = response.json()['Resources'][0]
    verify_account(account)
    assert account['id'] == '7f00000174441779817444c883c30016'
    assert account['lastRefresh'] >= '2020-08-31T00:00:00Z'


@patch('SailPointIdentityIQ.send_request')
def test_get_accounts_native_identity_not_found(mock_accounts_response):
    json_data = util_load_json('test_data/NoResources.json')
    mock_accounts_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_accounts(None, None, None, 'Black Jack', None, None, None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 0)


@patch('SailPointIdentityIQ.send_request')
def test_get_accounts_native_identity_found(mock_accounts_response):
    json_data = util_load_json('test_data/Account_Filtered.json')
    mock_accounts_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_accounts(None, None, None, 'bjack', None, None, None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 1)
    account = response.json()['Resources'][0]
    verify_account(account)
    assert account['id'] == '7f00000174441779817444c883c30016'
    assert account['nativeIdentity'] == 'bjack'


@patch('SailPointIdentityIQ.send_request')
def test_get_accounts_last_target_agg_not_matched(mock_accounts_response):
    json_data = util_load_json('test_data/NoResources.json')
    mock_accounts_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_accounts(None, None, None, None, '2020-12-10T00:00:00Z', None, None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 0)


@patch('SailPointIdentityIQ.send_request')
def test_get_accounts_last_target_agg_matched(mock_accounts_response):
    json_data = util_load_json('test_data/Account_Filtered.json')
    mock_accounts_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_accounts(None, None, None, None, '2020-08-31T00:00:00Z', None, None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 1)
    account = response.json()['Resources'][0]
    verify_account(account)
    assert account['id'] == '7f00000174441779817444c883c30016'
    assert account['lastTargetAggregation'] == '2020-09-05T09:22:45.432-05:00'


@patch('SailPointIdentityIQ.send_request')
def test_get_accounts_identity_name_not_matched(mock_accounts_response):
    json_data = util_load_json('test_data/NoResources.json')
    mock_accounts_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_accounts(None, None, None, None, None, 'Black Jack', None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 0)


@patch('SailPointIdentityIQ.send_request')
def test_get_accounts_identity_name_matched(mock_accounts_response):
    json_data = util_load_json('test_data/Account_Filtered.json')
    mock_accounts_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_accounts(None, None, None, None, None, 'bjack', None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 1)
    account = response.json()['Resources'][0]
    verify_account(account)
    assert account['id'] == '7f00000174441779817444c883c30016'
    assert account['identity']['displayName'] == 'bjack'
    assert account['identity']['userName'] == 'bjack'


@patch('SailPointIdentityIQ.send_request')
def test_get_accounts_application_name_not_matched(mock_accounts_response):
    json_data = util_load_json('test_data/NoResources.json')
    mock_accounts_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_accounts(None, None, None, None, None, None, 'SCIM Server')
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 0)


@patch('SailPointIdentityIQ.send_request')
def test_get_accounts_application_name_matched(mock_accounts_response):
    json_data = util_load_json('test_data/Account_Filtered.json')
    mock_accounts_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_accounts(None, None, None, None, None, None, 'SCIM SDK')
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 1)
    account = response.json()['Resources'][0]
    verify_account(account)
    assert account['id'] == '7f00000174441779817444c883c30016'
    assert account['application']['displayName'] == 'SCIM SDK'


@patch('SailPointIdentityIQ.send_request')
def test_get_accounts(mock_accounts_response):
    json_data = util_load_json('test_data/Accounts.json')
    mock_accounts_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_accounts(None, None, '2020-05-01T00:00:00Z', None, None, None, None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 3)
    for account in response.json()['Resources']:
        verify_account(account)


@patch('SailPointIdentityIQ.change_account_status')
def test_change_account_id_not_found(mock_account):
    mock_account.return_value = util_load_json('test_data/404_Not_Found.json')
    accounts = SailPointIdentityIQ.change_account_status('7f00000174441779817444c8837c5373', True)
    assert 'urn:ietf:params:scim:api:messages:2.0:Error' in accounts['schemas']
    assert accounts['status'] == '404'


@patch('SailPointIdentityIQ.change_account_status')
def test_change_account_enable(mock_account):
    mock_account.return_value = util_load_json('test_data/Account.json')
    account = SailPointIdentityIQ.change_account_status('7f00000174441779817444c883c30016', True)
    verify_account(account)
    assert account['active'] is True


@patch('SailPointIdentityIQ.change_account_status')
def test_change_account_disable(mock_account):
    mock_account.return_value = util_load_json('test_data/Account_Disabled.json')
    account = SailPointIdentityIQ.change_account_status('7f00000174441779817444c883c30016', False)
    verify_account(account)
    assert account['active'] is False


@patch('SailPointIdentityIQ.delete_account')
def test_delete_account_id_none(mock_account_response):
    mock_account_response.return_value = '405'
    response = SailPointIdentityIQ.delete_account(None)
    assert response == '405'


@patch('SailPointIdentityIQ.delete_account')
def test_delete_account_id_not_found(mock_account_response):
    mock_account_response.return_value = '404 : Resource 7f00000174441779817444c8837c5373 not found.'
    response = SailPointIdentityIQ.delete_account('7f00000174441779817444c8837c5373')
    assert response == '404 : Resource 7f00000174441779817444c8837c5373 not found.'


@patch('SailPointIdentityIQ.delete_account')
def test_delete_account_deleted(mock_account_response):
    mock_account_response.return_value = '404 : Resource 7f00000174441779817444c8837c5373 not found.'
    response = SailPointIdentityIQ.delete_account('7f00000174441779817444c8837c5373')
    assert response == '404 : Resource 7f00000174441779817444c8837c5373 not found.'


@patch('SailPointIdentityIQ.delete_account')
def test_delete_account(mock_account_response):
    mock_account_response.return_value = 'Account deleted successfully!'
    response = SailPointIdentityIQ.delete_account('7f00000174441779817444c8837c5373')
    assert response == 'Account deleted successfully!'


@patch('SailPointIdentityIQ.send_request')
def test_get_launched_workflows_id_not_found(mock_launched_workflows_response):
    json_data = util_load_json('test_data/404_Not_Found.json')
    mock_launched_workflows_response.return_value = util_mock_http_resp(404, json_data)
    response = SailPointIdentityIQ.get_launched_workflows('7f00000173de18fa8173deb1064e0453')
    assert response.status_code == 404
    assert 'urn:ietf:params:scim:api:messages:2.0:Error' in response.json()['schemas']
    assert response.json()['status'] == '404'


@patch('SailPointIdentityIQ.send_request')
def test_get_launched_workflows_id_found(mock_launched_workflows_response):
    json_data = util_load_json('test_data/LaunchedWorkflow.json')
    mock_launched_workflows_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_launched_workflows('7f00000173de18fa8173deb1064e001c')
    assert response.status_code == 200
    verify_launched_workflow(response.json())


@patch('SailPointIdentityIQ.send_request')
def test_get_launched_workflows_no_resources(mock_launched_workflows_response):
    json_data = util_load_json('test_data/NoResources.json')
    mock_launched_workflows_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_launched_workflows(None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 0)


@patch('SailPointIdentityIQ.send_request')
def test_get_launched_workflows(mock_launched_workflows_response):
    json_data = util_load_json('test_data/LaunchedWorkflows.json')
    mock_launched_workflows_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_launched_workflows(None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 5)
    for launched_workflow in response.json()['Resources']:
        verify_launched_workflow(launched_workflow)


@patch('SailPointIdentityIQ.send_request')
def test_get_roles_id_not_found(mock_roles_response):
    json_data = util_load_json('test_data/404_Not_Found.json')
    mock_roles_response.return_value = util_mock_http_resp(404, json_data)
    response = SailPointIdentityIQ.get_roles('7f000001705911b4817059d312394432')
    assert response.status_code == 404
    assert 'urn:ietf:params:scim:api:messages:2.0:Error' in response.json()['schemas']
    assert response.json()['status'] == '404'


@patch('SailPointIdentityIQ.send_request')
def test_get_roles_id_found(mock_roles_response):
    json_data = util_load_json('test_data/Role.json')
    mock_roles_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_roles('7f000001705911b4817059d31239035f')
    assert response.status_code == 200
    verify_role(response.json())


@patch('SailPointIdentityIQ.send_request')
def test_get_roles_no_resources(mock_roles_response):
    json_data = util_load_json('test_data/NoResources.json')
    mock_roles_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_roles(None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 0)


@patch('SailPointIdentityIQ.send_request')
def test_get_roles(mock_roles_response):
    json_data = util_load_json('test_data/Roles.json')
    mock_roles_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_roles(None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 5)
    for role in response.json()['Resources']:
        verify_role(role)


@patch('SailPointIdentityIQ.send_request')
def test_get_entitlements_id_not_found(mock_entitlements_response):
    json_data = util_load_json('test_data/404_Not_Found.json')
    mock_entitlements_response.return_value = util_mock_http_resp(404, json_data)
    response = SailPointIdentityIQ.get_entitlements('7f000001705911b4817059d355844443')
    assert response.status_code == 404
    assert 'urn:ietf:params:scim:api:messages:2.0:Error' in response.json()['schemas']
    assert response.json()['status'] == '404'


@patch('SailPointIdentityIQ.send_request')
def test_get_entitlements_id_found(mock_entitlements_response):
    json_data = util_load_json('test_data/Entitlement.json')
    mock_entitlements_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_entitlements('7f000001705911b4817059d355840657')
    assert response.status_code == 200
    verify_entitlement(response.json())


@patch('SailPointIdentityIQ.send_request')
def test_get_entitlements_no_resources(mock_entitlements_response):
    json_data = util_load_json('test_data/NoResources.json')
    mock_entitlements_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_entitlements(None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 0)


@patch('SailPointIdentityIQ.send_request')
def test_get_entitlements(mock_entitlements_response):
    json_data = util_load_json('test_data/Entitlements.json')
    mock_entitlements_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_entitlements(None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 5)
    for entitlement in response.json()['Resources']:
        verify_entitlement(entitlement)


@patch('SailPointIdentityIQ.send_request')
def test_get_alerts_id_not_found(mock_alerts_response):
    json_data = util_load_json('test_data/404_Not_Found.json')
    mock_alerts_response.return_value = util_mock_http_resp(404, json_data)
    response = SailPointIdentityIQ.get_alerts('0a000001758a173e81763f81205e6453')
    assert response.status_code == 404
    assert 'urn:ietf:params:scim:api:messages:2.0:Error' in response.json()['schemas']
    assert response.json()['status'] == '404'


@patch('SailPointIdentityIQ.send_request')
def test_get_alerts_id_found(mock_alerts_response):
    json_data = util_load_json('test_data/Alert.json')
    mock_alerts_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_alerts('0a000001758a173e81763f81205e0062')
    assert response.status_code == 200
    verify_alert(response.json())


@patch('SailPointIdentityIQ.send_request')
def test_get_alerts_no_resources(mock_alerts_response):
    json_data = util_load_json('test_data/NoResources.json')
    mock_alerts_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_alerts(None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 0)


@patch('SailPointIdentityIQ.send_request')
def test_get_alerts(mock_alerts_response):
    json_data = util_load_json('test_data/Alerts.json')
    mock_alerts_response.return_value = util_mock_http_resp(200, json_data)
    response = SailPointIdentityIQ.get_alerts(None)
    assert response.status_code == 200
    verify_scim_list_response(response.json(), 3)
    for alert in response.json()['Resources']:
        verify_alert(alert)


@patch('SailPointIdentityIQ.send_request')
def test_create_alert(mock_alerts_response):
    json_data = util_load_json('test_data/Alert.json')
    mock_alerts_response.return_value = util_mock_http_resp(201, json_data)
    response = SailPointIdentityIQ.create_alert('Test Alert')
    assert response.status_code == 201
    verify_alert(response.json())
