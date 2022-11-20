from http import HTTPStatus
from urllib.parse import urljoin
from FortinetFortiwebVM import ClientV1, ClientV2, Client
from CommonServerPython import *
import json
import pytest
import os
import demistomock as demisto


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    file_path = os.path.join('test_data', file_name)
    with open(file_path, mode='r', encoding='utf-8') as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture(autouse=True)
def mock_client(version: str) -> Client:
    """Create a test client for v1/v2

    Args:
        version (str): Version (V1/V2)

    Returns:
        Client: Fortieweb VM Client.
    """
    client_class = ClientV1 if version == ClientV1.API_VER else ClientV2
    client: Client = client_class('http://1.1.1.1/', 'api_key', version, True, False)  # type: ignore
    return client


@pytest.mark.parametrize(
    ('version', 'endpoint', 'args', 'jsonpath', 'expected_key', 'expected_value', 'status_code', 'assert_flag'), (
        (ClientV1.API_VER, 'ServerObjects/ProtectedHostnames/ProtectedHostnames', {
            'name': 'check'
        }, 'protected_hostname/v1_success.json', 'name', 'check', HTTPStatus.OK, False),
        (ClientV1.API_VER, 'ServerObjects/ProtectedHostnames/ProtectedHostnames', {
            'name': 'check'
        }, 'protected_hostname/v1_failed_exist.json', 'name', 'check', HTTPStatus.INTERNAL_SERVER_ERROR, True),
        (ClientV2.API_VER, 'server-policy/allow-hosts', {
            'name': 'check'
        }, 'protected_hostname/v2_success.json', 'name', 'check', HTTPStatus.OK, False),
        (ClientV2.API_VER, 'server-policy/allow-hosts', {
            'name': 'check'
        }, 'protected_hostname/v2_failed_exist.json', 'name', 'check', HTTPStatus.INTERNAL_SERVER_ERROR, True),
    ))
def test_protected_hostname_create_command(requests_mock, mock_client, version, endpoint, args, jsonpath, expected_key,
                                           expected_value, status_code, assert_flag):
    """
    Scenario: Create a protected hostname group.
    Given:
     - User has provided correct parameters.
     - User has provided exist name.
    When:
     - fortiwebvm-protected-hostname-group-create called.
    Then:
     - Ensure that protected hostname created.
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import protected_hostname_create_command
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response, status_code=status_code)
    try:
        result = protected_hostname_create_command(mock_client, args)
        assert expected_value in result.readable_output
        # assert result.outputs_prefix == 'FortiwebVM.ProtectedHostnameGroup'
    except DemistoException:
        assert assert_flag


@pytest.mark.parametrize(
    ('version', 'endpoint', 'args', 'jsonpath', 'expected_key', 'expected_value', 'status_code', 'assert_flag'), (
        (ClientV1.API_VER, 'ServerObjects/ProtectedHostnames/ProtectedHostnames/check', {
            'name': 'check'
        }, 'protected_hostname/v1_success.json', 'name', 'check', HTTPStatus.OK, False),
        (ClientV1.API_VER, 'ServerObjects/ProtectedHostnames/ProtectedHostnames/check', {
            'name': 'check'
        }, 'protected_hostname/v1_failed_exist.json', 'name', 'check', HTTPStatus.INTERNAL_SERVER_ERROR, True),
        (ClientV2.API_VER, 'server-policy/allow-hosts?mkey=check', {
            'name': 'check'
        }, 'protected_hostname/v2_success.json', 'name', 'check', HTTPStatus.OK, False),
        (ClientV2.API_VER, 'server-policy/allow-hosts?mkey=check', {
            'name': 'check'
        }, 'protected_hostname/v2_failed_exist.json', 'name', 'check', HTTPStatus.INTERNAL_SERVER_ERROR, True),
    ))
def test_protected_hostname_update_command(requests_mock, mock_client, version, endpoint, args, jsonpath, expected_key,
                                           expected_value, status_code, assert_flag):
    """
    Scenario: Update a protected hostname group.
    Given:
     - User has provided correct parameters.
     - User has provided not exist name.
    When:
     - fortiwebvm-protected-hostname-group-update called.
    Then:
     - Ensure that protected hostname updated.
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import protected_hostname_update_command
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response, status_code=status_code)
    try:
        result = protected_hostname_update_command(mock_client, args)
        assert expected_value in result.readable_output
        # assert result.outputs_prefix == 'FortiwebVM.ProtectedHostnameGroup'
    except DemistoException:
        assert assert_flag


@pytest.mark.parametrize(
    ('version', 'endpoint', 'args', 'jsonpath', 'expected_key', 'expected_value', 'status_code', 'assert_flag'), (
        (ClientV1.API_VER, 'ServerObjects/ProtectedHostnames/ProtectedHostnames/check', {
            'name': 'check'
        }, 'protected_hostname/v1_success.json', 'name', 'check', HTTPStatus.OK, False),
        (ClientV1.API_VER, 'ServerObjects/ProtectedHostnames/ProtectedHostnames/check', {
            'name': 'check'
        }, 'protected_hostname/v1_failed_exist.json', 'name', 'check', HTTPStatus.INTERNAL_SERVER_ERROR, True),
        (ClientV2.API_VER, 'server-policy/allow-hosts?mkey=check', {
            'name': 'check'
        }, 'protected_hostname/v2_success.json', 'name', 'check', HTTPStatus.OK, False),
        (ClientV2.API_VER, 'server-policy/allow-hosts?mkey=check', {
            'name': 'check'
        }, 'protected_hostname/v2_failed_exist.json', 'name', 'check', HTTPStatus.INTERNAL_SERVER_ERROR, True),
    ))
def test_protected_hostname_delete_command(requests_mock, mock_client, version, endpoint, args, jsonpath, expected_key,
                                           expected_value, status_code, assert_flag):
    """
    Scenario: Delete a protected hostname group.
    Given:
     - User has provided correct parameters.
     - User has provided not exist name.
    When:
     - fortiwebvm-protected-hostname-group-delete called.
    Then:
     - Ensure that protected hostname deleted.
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import protected_hostname_delete_command
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(url=url, json=json_response, status_code=status_code)
    try:
        result = protected_hostname_delete_command(mock_client, args)
        assert expected_value in result.readable_output
    except DemistoException:
        assert assert_flag


@pytest.mark.parametrize(
    ('version', 'endpoint', 'args', 'jsonpath', 'expected'),
    (
        (ClientV1.API_VER, 'ServerObjects/ProtectedHostnames/ProtectedHostnames', {
            'page': '1',
            'page_size': 3
        }, 'protected_hostname/v1_get_list_success.json', 3),
        (ClientV2.API_VER, 'server-policy/allow-hosts', {
            'page': '1',
            'page_size': 3
        }, 'protected_hostname/v2_get_list_success.json', 3),
    ),
)
def test_protected_hostname_list_command(requests_mock, mock_client, version, endpoint, args, jsonpath, expected):
    """
    Scenario: List a protected hostname groups.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-protected-hostname-group-list called.
    Then:
     - Ensure that protected hostname listed.
    """
    from FortinetFortiwebVM import protected_hostname_list_command
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = protected_hostname_list_command(mock_client, args)
    assert len(result.outputs) == expected
    assert result.outputs_prefix == 'FortiwebVM.ProtectedHostnameGroup'


@pytest.mark.parametrize(('version', 'endpoint', 'args', 'jsonpath', 'expected_value', 'status_code', 'assert_flag'), (
    (ClientV1.API_VER, 'ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost', {
        'group_name': '1234',
        'action': 'Allow',
        'host': '1.2.3.4'
    }, 'protected_hostname_member/v1_success.json', '3', HTTPStatus.OK, False),
    (ClientV1.API_VER, 'ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost', {
        'group_name': '1234',
        'action': 'Allow',
        'host': '1.2.3.4'
    }, 'protected_hostname_member/v1_failed_exist.json', 'A duplicate entry already exists.', 500, True),
    (ClientV2.API_VER, 'server-policy/allow-hosts/host-list?mkey=1234', {
        'group_name': '1234',
        'action': 'Allow',
        'host': '1.2.3.4',
        'ignore_port': 'disable',
        'include_subdomains': 'disable'
    }, 'protected_hostname_member/v2_success.json', '5', HTTPStatus.OK, False),
    (ClientV2.API_VER, 'server-policy/allow-hosts/host-list?mkey=1234', {
        'group_name': '1234',
        'action': 'Allow',
        'host': '1.2.3.4',
        'ignore_port': 'disable',
        'include_subdomains': 'disable'
    }, 'protected_hostname_member/v2_failed_exist.json', "{'results': {'errcode': -5}",
     HTTPStatus.INTERNAL_SERVER_ERROR, True),
))
def test_protected_hostname_member_create_command(requests_mock, mock_client, version, endpoint, args, jsonpath,
                                                  expected_value, status_code, assert_flag):
    """
    Scenario: Create a protected hostname member.
    Given:
     - User has provided correct parameters.
     - User has provided exist host.
    When:
     - fortiwebvm-protected-hostname-member-create called.
    Then:
     - Ensure that protected hostname created.
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import protected_hostname_member_create_command
    json_response = load_mock_response(jsonpath)
    json_response_get = load_mock_response('protected_hostname_member/v1_get_list_success.json')
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response, status_code=status_code)
    requests_mock.get(url=url, json=json_response_get, status_code=200)
    try:
        result = protected_hostname_member_create_command(mock_client, args)
        assert result.outputs_prefix == 'FortiwebVM.ProtectedHostnameMember'
        assert result.outputs['id'] == expected_value
    except DemistoException as error:
        assert expected_value in error.message
        assert assert_flag


@pytest.mark.parametrize(('version', 'endpoint', 'args', 'jsonpath', 'status_code', 'assert_flag', 'expected_value'), (
    (ClientV1.API_VER, 'ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost/1', {
        'group_name': '1234',
        'member_id': '1',
        'action': 'Allow',
        'host': '1.2.3.4'
    }, 'protected_hostname_member/v1_success.json', HTTPStatus.OK, False, '1'),
    (ClientV1.API_VER, 'ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost/1', {
        'group_name': '1234',
        'member_id': '1',
        'action': 'Allow',
        'host': '1.2.3.4'
    }, 'protected_hostname_member/v1_failed_not_exist.json', HTTPStatus.INTERNAL_SERVER_ERROR, True,
     'Invalid length of value.'),
    (ClientV2.API_VER, 'server-policy/allow-hosts/host-list?mkey=1234&sub_mkey=1', {
        'group_name': '1234',
        'member_id': '1',
        'action': 'Allow',
        'host': '1.2.3.4',
        'ignore_port': 'disable',
        'include_subdomains': 'disable'
    }, 'protected_hostname_member/v2_success.json', HTTPStatus.OK, False, '1'),
    (ClientV2.API_VER, 'server-policy/allow-hosts/host-list?mkey=1234&sub_mkey=1', {
        'group_name': '1234',
        'member_id': '1',
        'action': 'Allow',
        'host': '1.2.3.4',
        'ignore_port': 'disable',
        'include_subdomains': 'disable'
    }, 'protected_hostname_member/v2_failed_not_exist.json', HTTPStatus.INTERNAL_SERVER_ERROR, True,
     "'results': {'errcode': -3}"),
))
def test_protected_hostname_member_update_command(requests_mock, mock_client, version, endpoint, args, jsonpath,
                                                  status_code, assert_flag, expected_value):
    """
    Scenario: Update a protected hostname member.
    Given:
     - User has provided correct parameters.
     - User has provided exist host.
    When:
     - fortiwebvm-protected-hostname-member-create called.
    Then:
     - Ensure that protected hostname created.
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import protected_hostname_member_update_command
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response, status_code=status_code)
    try:
        result = protected_hostname_member_update_command(mock_client, args)
        assert expected_value in result.readable_output
    except DemistoException as error:
        assert expected_value in error.message
        assert assert_flag


@pytest.mark.parametrize(('version', 'endpoint', 'args', 'jsonpath', 'status_code', 'assert_flag', 'expected_value'), (
    (ClientV1.API_VER, 'ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost/1', {
        'group_name': '1234',
        'member_id': '1',
    }, 'protected_hostname_member/v1_delete_success.json', HTTPStatus.OK, False, ''),
    (ClientV1.API_VER, 'ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost/1', {
        'group_name': '1234',
        'member_id': '1',
    }, 'protected_hostname_member/v1_delete_failed.json', HTTPStatus.INTERNAL_SERVER_ERROR, True,
     'Invalid length of value.'),
    (ClientV2.API_VER, 'server-policy/allow-hosts/host-list?mkey=1234&sub_mkey=1', {
        'group_name': '1234',
        'member_id': '1',
    }, 'protected_hostname_member/v2_delete_success.json', HTTPStatus.OK, False, ''),
    (ClientV2.API_VER, 'server-policy/allow-hosts/host-list?mkey=1234&sub_mkey=1', {
        'group_name': '1234',
        'member_id': '1',
    }, 'protected_hostname_member/v2_delete_failed.json', HTTPStatus.INTERNAL_SERVER_ERROR, True, "'errcode': -1"),
))
def test_protected_hostname_member_delete_command(requests_mock, mock_client, version, endpoint, args, jsonpath,
                                                  status_code, assert_flag, expected_value):
    """
    Scenario: Update a protected hostname member.
    Given:
     - User has provided correct parameters.
     - User has provided exist host.
    When:
     - fortiwebvm-protected-hostname-member-create called.
    Then:
     - Ensure that protected hostname created.
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import protected_hostname_member_delete_command
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(url=url, json=json_response, status_code=status_code)
    try:
        result = protected_hostname_member_delete_command(mock_client, args)
        assert expected_value in result.readable_output
    except DemistoException as error:
        assert expected_value in error.message
        assert assert_flag


@pytest.mark.parametrize(
    ('version', 'endpoint', 'args', 'jsonpath', 'expected'),
    (
        (ClientV1.API_VER, 'ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost', {
            'group_name': '1234',
            'page': '1',
            'page_size': 3
        }, 'protected_hostname_member/v1_get_list_success.json', 3),
        (ClientV2.API_VER, 'server-policy/allow-hosts/host-list?mkey=1234', {
            'group_name': '1234',
            'page': '1',
            'page_size': 3
        }, 'protected_hostname_member/v2_get_list_success.json', 3),
    ),
)
def test_protected_hostname_member_list_command(requests_mock, mock_client, version, endpoint, args, jsonpath,
                                                expected):
    """
    Scenario: List a protected hostname groups.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-protected-hostname-group-list called.
    Then:
     - Ensure that protected hostname listed.
    """
    from FortinetFortiwebVM import protected_hostname_member_list_command
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = protected_hostname_member_list_command(mock_client, args)
    assert len(result.outputs) == expected
    assert result.outputs_prefix == 'FortiwebVM.ProtectedHostnameMember'


@pytest.mark.parametrize(
    ('version', 'endpoint', 'args', 'jsonpath', 'expected_key', 'expected_value', 'status_code', 'assert_flag'), (
        (ClientV1.API_VER, 'WebProtection/Access/IPList', {
            'name': 'check',
            'action': 'deny and no log',
        }, 'ip_list_group/v1_create_success.json', 'id', 'check', HTTPStatus.OK, False),
        (ClientV1.API_VER, 'WebProtection/Access/IPList', {
            'name': 'check',
            'action': 'deny and no log',
        }, 'ip_list_group/v1_create_exist.json', 'id', 'check', HTTPStatus.INTERNAL_SERVER_ERROR, True),
        (ClientV2.API_VER, 'waf/ip-list', {
            'name': 'check',
            'action': 'deny and no log',
        }, 'ip_list_group/v2_create_success.json', 'id', 'check', HTTPStatus.OK, False),
        (ClientV2.API_VER, 'waf/ip-list', {
            'name': 'check',
            'action': 'deny and no log',
        }, 'ip_list_group/v2_create_exist.json', 'id', 'check', HTTPStatus.INTERNAL_SERVER_ERROR, True),
    ))
def test_ip_list_group_create_command(requests_mock, mock_client, version, endpoint, args, jsonpath, expected_key,
                                      expected_value, status_code, assert_flag):
    """
    Scenario: Create an IP list group.
    Given:
     - User has provided correct parameters.
     - User has provided exist name.
    When:
     - fortiwebvm-ip-list-group-create called.
    Then:
     - Ensure that protected hostname created.
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import ip_list_group_create_command
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response, status_code=status_code)
    try:
        result = ip_list_group_create_command(mock_client, args)
        assert expected_value in result.readable_output
    except DemistoException:
        assert assert_flag


@pytest.mark.parametrize(
    ('version', 'endpoint', 'args', 'jsonpath', 'expected_key', 'expected_value', 'status_code', 'assert_flag'), (
        (ClientV2.API_VER, 'waf/ip-list?mkey=check', {
            'name': 'check',
            'action': 'block period',
        }, 'ip_list_group/v2_update_success.json', 'id', 'check', HTTPStatus.OK, False),
        (ClientV2.API_VER, 'waf/ip-list?mkey=check', {
            'name': 'check',
            'action': 'block period',
        }, 'ip_list_group/v2_not_exist.json', 'id', 'check', HTTPStatus.INTERNAL_SERVER_ERROR, True),
    ))
def test_ip_list_group_upadte_command(requests_mock, mock_client, version, endpoint, args, jsonpath, expected_key,
                                      expected_value, status_code, assert_flag):
    """
    Scenario: Update an IP list group.
    Given:
     - User has provided correct parameters.
     - User has provided exist name.
    When:
     - fortiwebvm-ip-list-group-update called.
    Then:
     - Ensure that protected hostname created.
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import ip_list_group_update_command
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response, status_code=status_code)
    try:
        result = ip_list_group_update_command(mock_client, args)
        assert expected_value in result.readable_output
    except DemistoException:
        assert assert_flag


@pytest.mark.parametrize(('version', 'endpoint', 'args', 'jsonpath', 'status_code', 'assert_flag'), (
    (ClientV1.API_VER, 'WebProtection/Access/IPList/Example', {
        'name': 'Example'
    }, 'protected_hostname/v1_success.json', HTTPStatus.OK, False),
    (ClientV1.API_VER, 'WebProtection/Access/IPList/Example', {
        'name': 'Example'
    }, 'protected_hostname/v1_failed_exist.json', HTTPStatus.INTERNAL_SERVER_ERROR, True),
    (ClientV2.API_VER, 'waf/ip-list?mkey=Example', {
        'name': 'Example'
    }, 'protected_hostname/v2_success.json', HTTPStatus.OK, False),
    (ClientV2.API_VER, 'waf/ip-list?mkey=Example', {
        'name': 'Example'
    }, 'protected_hostname/v2_failed_exist.json', HTTPStatus.INTERNAL_SERVER_ERROR, True),
))
def test_ip_list_group_delete_command(requests_mock, mock_client, version, endpoint, args, jsonpath, status_code,
                                      assert_flag):
    """
    Scenario: Delete an IP list group.
    Given:
     - User has provided correct parameters.
     - User has provided not exist name.
    When:
     - fortiwebvm-ip-list-group-delete called.
    Then:
     - Ensure that protected hostname deleted.
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import ip_list_group_delete_command
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(url=url, json=json_response, status_code=status_code)
    try:
        result = ip_list_group_delete_command(mock_client, args)
    except DemistoException:
        assert assert_flag


@pytest.mark.parametrize(
    ('version', 'endpoint', 'args', 'jsonpath', 'expected'),
    (
        (ClientV1.API_VER, 'WebProtection/Access/IPList', {
            'page': '1',
            'page_size': 3
        }, 'ip_list_group/v1_list_success.json', 3),
        (ClientV2.API_VER, 'waf/ip-list', {
            'page': '1',
            'page_size': 3
        }, 'ip_list_group/v2_list_success.json', 3),
    ),
)
def test_ip_list_group_list_command(requests_mock, mock_client, version, endpoint, args, jsonpath, expected):
    """
    Scenario: List an IP list groups.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-ip-list-group-list called.
    Then:
     - Ensure that protected hostname listed.
    """
    from FortinetFortiwebVM import ip_list_group_list_command
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = ip_list_group_list_command(mock_client, args)
    assert len(result.outputs) == expected
    assert result.outputs_prefix == 'FortiwebVM.IpListGroup'


@pytest.mark.parametrize(
    ('version', 'endpoint', 'args', 'jsonpath', 'expected_key', 'expected_value', 'status_code', 'assert_flag'), (
        (ClientV1.API_VER, 'WebProtection/Access/IPList/1234/IPListCreateIPListPolicyMember', {
            'group_name': '1234',
            'ip_address': '1.2.3.89',
            'type': 'black ip'
        }, 'ip_list_member/v1_create_success.json', 'id', '6', HTTPStatus.OK, False),
        (ClientV1.API_VER, 'WebProtection/Access/IPList/1234/IPListCreateIPListPolicyMember', {
            'group_name': '1234',
            'ip_address': '1.1.1.1',
            'type': 'black ip'
        }, 'ip_list_member/v1_exist.json', 'id', 'The IP has already existed in the table.',
         HTTPStatus.INTERNAL_SERVER_ERROR, True),
        (ClientV2.API_VER, 'waf/ip-list/members?mkey=1234', {
            'group_name': '1234',
            'ip_address': '1.1.1.1',
            'type': 'black ip'
        }, 'ip_list_member/v2_create_success.json', 'id', '5', HTTPStatus.OK, False),
        (ClientV2.API_VER, 'waf/ip-list/members?mkey=1234', {
            'group_name': '1234',
            'ip_address': '1.1.1.1',
            'type': 'black ip'
        }, 'ip_list_member/v2_exist.json', 'id', "'results': {'errcode': -6014}", HTTPStatus.INTERNAL_SERVER_ERROR,
         True),
    ))
def test_ip_list_member_create_command(requests_mock, mock_client, version, endpoint, args, jsonpath, expected_key,
                                       expected_value, status_code, assert_flag):
    """
    Scenario: Create an IP list member.
    Given:
     - User has provided correct parameters.
     - User has provided exist host.
    When:
     - fortiwebvm-ip-list-member-create called.
    Then:
     - Ensure that protected hostname created.
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import ip_list_member_create_command
    json_response = load_mock_response(jsonpath)
    json_response_get = load_mock_response('ip_list_member/v1_list_success.json')
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response, status_code=status_code)
    requests_mock.get(url=url, json=json_response_get, status_code=200)
    try:
        result = ip_list_member_create_command(mock_client, args)
        assert expected_value in result.readable_output
    except DemistoException as error:
        assert expected_value in error.message
        assert assert_flag


@pytest.mark.parametrize(
    ('version', 'endpoint', 'args', 'jsonpath', 'expected_key', 'expected_value', 'status_code', 'assert_flag'), (
        (ClientV1.API_VER, 'WebProtection/Access/IPList/1234/IPListCreateIPListPolicyMember/1', {
            'group_name': '1234',
            'member_id': '1',
            'ip_address': '1.1.1.1',
            'type': 'black ip'
        }, 'ip_list_member/v1_create_success.json', 'id', '1', HTTPStatus.OK, False),
        (ClientV1.API_VER, 'WebProtection/Access/IPList/1234/IPListCreateIPListPolicyMember/1', {
            'group_name': '1234',
            'member_id': '1',
            'ip_address': '1.1.1.1',
            'type': 'black ip'
        }, 'ip_list_member/v1_not_exist.json', 'id', 'Invalid length of value.', HTTPStatus.INTERNAL_SERVER_ERROR,
         True),
        (ClientV2.API_VER, 'waf/ip-list/members?mkey=1234&sub_mkey=1', {
            'group_name': '1234',
            'member_id': '1',
            'ip_address': '1.1.1.1',
            'type': 'black ip'
        }, 'ip_list_member/v2_create_success.json', 'id', '1', HTTPStatus.OK, False),
        (ClientV2.API_VER, 'waf/ip-list/members?mkey=1234&sub_mkey=1', {
            'group_name': '1234',
            'member_id': '1',
            'ip_address': '1.1.1.1',
            'type': 'black ip'
        }, 'ip_list_member/v2_not_exist.json', 'id', "'results': {'errcode': -3}", HTTPStatus.INTERNAL_SERVER_ERROR,
         True),
    ))
def test_ip_list_member_update_command(requests_mock, mock_client, version, endpoint, args, jsonpath, expected_key,
                                       expected_value, status_code, assert_flag):
    """
    Scenario: Update an IP list member.
    Given:
     - User has provided correct parameters.
     - User has provided exist host.
    When:
     - fortiwebvm-ip-list-member-update called.
    Then:
     - Ensure that protected hostname created.
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import ip_list_member_update_command
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response, status_code=status_code)
    try:
        result = ip_list_member_update_command(mock_client, args)
        assert expected_value in result.readable_output
    except DemistoException as error:
        assert expected_value in error.message
        assert assert_flag


@pytest.mark.parametrize(('version', 'endpoint', 'args', 'jsonpath', 'expected_value', 'status_code', 'assert_flag'), (
    (ClientV1.API_VER, 'WebProtection/Access/IPList/1234/IPListCreateIPListPolicyMember/1', {
        'group_name': '1234',
        'member_id': '1',
    }, 'ip_list_member/v1_delete_success.json', '1', HTTPStatus.OK, False),
    (ClientV1.API_VER, 'WebProtection/Access/IPList/1234/IPListCreateIPListPolicyMember/1', {
        'group_name': '1234',
        'member_id': '1',
    }, 'ip_list_member/v1_not_exist.json', 'Invalid length of value.', HTTPStatus.INTERNAL_SERVER_ERROR, True),
    (ClientV2.API_VER, 'waf/ip-list/members?mkey=1234&sub_mkey=1', {
        'group_name': '1234',
        'member_id': '1',
    }, 'ip_list_member/v2_delete_success.json', '1', HTTPStatus.OK, False),
    (ClientV2.API_VER, 'waf/ip-list/members?mkey=1234&sub_mkey=1', {
        'group_name': '1234',
        'member_id': '1',
    }, 'ip_list_member/v2_not_exist.json', "'results': {'errcode': -3}", HTTPStatus.INTERNAL_SERVER_ERROR, True),
))
def test_ip_list_member_delete_command(requests_mock, mock_client, version, endpoint, args, jsonpath, expected_value,
                                       status_code, assert_flag):
    """
    Scenario: Delete an IP list member.
    Given:
     - User has provided correct parameters.
     - User has provided exist host.
    When:
     - fortiwebvm-protected-hostname-member-create called.
    Then:
     - Ensure that protected hostname created.
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import ip_list_member_delete_command
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(url=url, json=json_response, status_code=status_code)
    try:
        result = ip_list_member_delete_command(mock_client, args)
        assert expected_value in result.readable_output
    except DemistoException as error:
        assert expected_value in error.message
        assert assert_flag


@pytest.mark.parametrize(
    ('version', 'endpoint', 'args', 'jsonpath', 'expected'),
    (
        (ClientV1.API_VER, 'WebProtection/Access/IPList/ronhadad/IPListCreateIPListPolicyMember', {
            'group_name': 'ronhadad',
            'page': '1',
            'page_size': 3
        }, 'ip_list_member/v1_list_success.json', 3),
        (ClientV2.API_VER, 'waf/ip-list/members?mkey=ronhadad', {
            'group_name': 'ronhadad',
            'page': '1',
            'page_size': 3
        }, 'ip_list_member/v2_list_success.json', 3),
    ),
)
def test_ip_list_member_list_command(requests_mock, mock_client, version, endpoint, args, jsonpath, expected):
    """
    Scenario: List an IP list members.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-ip-list-member-list called.
    Then:
     - Ensure that protected hostname listed.
    """
    from FortinetFortiwebVM import ip_list_member_list_command
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = ip_list_member_list_command(mock_client, args)
    assert len(result.outputs) == expected
    assert result.outputs_prefix == 'FortiwebVM.IpListPolicyMember'


@pytest.mark.parametrize(('version', 'endpoint', 'jsonpath', 'expected_value', 'status_code'), (
    (ClientV1.API_VER, 'Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting',
     'http_content_routing_member/v1_create_success.json', '1', HTTPStatus.OK),
    (ClientV1.API_VER, 'Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting',
     'http_content_routing_member/v1_exist.json', 'The object already exist.', HTTPStatus.INTERNAL_SERVER_ERROR),
    (ClientV1.API_VER, 'Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting',
     'http_content_routing_member/v1_wrong_content_routing.json', 'There is a problem with one or more arguments.',
     HTTPStatus.INTERNAL_SERVER_ERROR),
    (ClientV2.API_VER, 'server-policy/policy/http-content-routing-list?mkey=policy',
     'http_content_routing_member/v2_create_success.json', '2', HTTPStatus.OK),
    (ClientV2.API_VER, 'server-policy/policy/http-content-routing-list?mkey=policy',
     'http_content_routing_member/v2_exist.json', "The object already exist.", HTTPStatus.INTERNAL_SERVER_ERROR),
    (ClientV2.API_VER, 'server-policy/policy/http-content-routing-list?mkey=policy',
     'http_content_routing_member/v2_wrong_content_routing.json', "There is a problem with one or more arguments.",
     HTTPStatus.INTERNAL_SERVER_ERROR),
))
def test_http_content_routing_member_add_command(requests_mock, mock_client, version, endpoint, jsonpath,
                                                 expected_value, status_code):
    """
    Scenario: Create an HTTP content routing member.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-http-content-routing-member-create called.
    Then:
     - Ensure that HTTP content routing member created.
    """

    from FortinetFortiwebVM import http_content_routing_member_add_command
    json_response = load_mock_response(jsonpath)
    json_response_get = load_mock_response('http_content_routing_member/v1_list_success.json')
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response, status_code=status_code)
    requests_mock.get(url=url, json=json_response_get, status_code=status_code)
    args = {
        'policy_name': 'policy',
        'http_content_routing_policy': '1234',
    }
    try:
        result = http_content_routing_member_add_command(mock_client, args)
        assert expected_value in result.readable_output
    except DemistoException as error:
        assert expected_value in error.message
        assert status_code == HTTPStatus.INTERNAL_SERVER_ERROR


@pytest.mark.parametrize(('version', 'endpoint', 'jsonpath', 'expected_value', 'status_code'), (
    (ClientV1.API_VER, 'Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting/1',
     'http_content_routing_member/v1_update_success.json', '1', HTTPStatus.OK),
    (ClientV1.API_VER, 'Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting/1',
     'http_content_routing_member/v1_not_exist.json', 'The object does not exist.', HTTPStatus.INTERNAL_SERVER_ERROR),
    (ClientV1.API_VER, 'Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting/1',
     'http_content_routing_member/v1_wrong_content_routing.json', 'There is a problem with one or more arguments.',
     HTTPStatus.INTERNAL_SERVER_ERROR),
    (ClientV2.API_VER, 'server-policy/policy/http-content-routing-list?mkey=policy&sub_mkey=1',
     'http_content_routing_member/v2_update_success.json', '1', HTTPStatus.OK),
    (ClientV2.API_VER, 'server-policy/policy/http-content-routing-list?mkey=policy&sub_mkey=1',
     'http_content_routing_member/v2_not_exist.json', "The object does not exist.", HTTPStatus.INTERNAL_SERVER_ERROR),
    (ClientV2.API_VER, 'server-policy/policy/http-content-routing-list?mkey=policy&sub_mkey=1',
     'http_content_routing_member/v2_wrong_content_routing.json', "There is a problem with one or more arguments.",
     HTTPStatus.INTERNAL_SERVER_ERROR),
))
def test_http_content_routing_member_update_command(requests_mock, mock_client, version, endpoint, jsonpath,
                                                    expected_value, status_code):
    """
    Scenario: Update an HTTP content routing member.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-http-content-routing-member-update called.
    Then:
     - Ensure that HTTP content routing member updated.
    """

    from FortinetFortiwebVM import http_content_routing_member_update_command
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response, status_code=status_code)
    args = {'policy_name': 'policy', 'http_content_routing_policy': '1234', 'id': 1}
    try:
        result = http_content_routing_member_update_command(mock_client, args)
        assert expected_value in result.readable_output
    except DemistoException as error:
        assert expected_value in error.message
        assert status_code == HTTPStatus.INTERNAL_SERVER_ERROR


@pytest.mark.parametrize(('version', 'endpoint', 'jsonpath', 'expected_value', 'status_code'), (
    (ClientV1.API_VER, 'Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting/1',
     'http_content_routing_member/v1_delete_success.json', '1', HTTPStatus.OK),
    (ClientV1.API_VER, 'Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting/1',
     'http_content_routing_member/v1_not_exist.json', 'The object does not exist.', HTTPStatus.INTERNAL_SERVER_ERROR),
    (ClientV2.API_VER, 'server-policy/policy/http-content-routing-list?mkey=policy&sub_mkey=1',
     'http_content_routing_member/v2_delete_success.json', '1', HTTPStatus.OK),
    (ClientV2.API_VER, 'server-policy/policy/http-content-routing-list?mkey=policy&sub_mkey=1',
     'http_content_routing_member/v2_not_exist.json', "The object does not exist.", HTTPStatus.INTERNAL_SERVER_ERROR),
))
def test_http_content_routing_member_delete_command(requests_mock, mock_client, version, endpoint, jsonpath,
                                                    expected_value, status_code):
    """
    Scenario: Delete an HTTP content routing member.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-http-content-routing-member-delete called.
    Then:
     - Ensure that HTTP content routing member deleted.
    """
    from FortinetFortiwebVM import http_content_routing_member_delete_command
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(url=url, json=json_response, status_code=status_code)
    args = {'policy_name': 'policy', 'id': 1}
    try:
        result = http_content_routing_member_delete_command(mock_client, args)
        assert expected_value in result.readable_output
    except DemistoException as error:
        assert expected_value in error.message
        assert status_code == HTTPStatus.INTERNAL_SERVER_ERROR


@pytest.mark.parametrize(
    ('version', 'endpoint', 'args', 'jsonpath', 'expected'),
    (
        (ClientV1.API_VER, 'Policy/ServerPolicy/ServerPolicy/Example/EditContentRouting', {
            'policy_name': 'Example',
            'page': '1',
            'page_size': '2'
        }, 'http_content_routing_member/v1_list_success.json', 2),
        (ClientV1.API_VER, 'Policy/ServerPolicy/ServerPolicy/Example/EditContentRouting', {
            'policy_name': 'Example',
            'page': '1',
            'page_size': '1'
        }, 'http_content_routing_member/v1_list_success.json', 1),
        (ClientV2.API_VER, 'server-policy/policy/http-content-routing-list?mkey=Example', {
            'policy_name': 'Example',
            'page': '1',
            'page_size': '2'
        }, 'http_content_routing_member/v2_list_success.json', 2),
        (ClientV2.API_VER, 'server-policy/policy/http-content-routing-list?mkey=Example', {
            'policy_name': 'Example',
            'page': '1',
            'page_size': '1'
        }, 'http_content_routing_member/v2_list_success.json', 1),
    ),
)
def test_http_content_routing_member_command(requests_mock, mock_client, version, endpoint, args, jsonpath, expected):
    """
    Scenario: List HTTP content routing members.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-http-content-routing-member-list called.
    Then:
     - Ensure that HTTP content routing member listed.
    """
    from FortinetFortiwebVM import http_content_routing_member_list_command
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = http_content_routing_member_list_command(mock_client, args)
    assert len(result.outputs) == expected
    assert result.outputs_prefix == 'FortiwebVM.HttpContentRoutingMember'
