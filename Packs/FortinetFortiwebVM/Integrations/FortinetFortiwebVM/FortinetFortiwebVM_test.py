import json
import os
from http import HTTPStatus
from urllib.parse import urljoin
from collections.abc import Callable

import pytest
from CommonServerPython import *
from FortinetFortiwebVM import Client, ClientV1, ClientV2, ErrorMessage, OutputTitle, ArgumentValues

JSON_MIME_TYPE = "application/json"


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    file_path = os.path.join("test_data", file_name)
    with open(file_path, encoding="utf-8") as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture(autouse=True)
def mock_client(version: str) -> Client:
    """Create a test client for V1/V2.

    Args:
        version (str): Version (V1/V2).

    Returns:
        Client: Fortieweb VM Client.
    """
    client_class = ClientV1 if version == ClientV1.API_VER else ClientV2
    client: Client = client_class("http://1.1.1.1/", "usn", "pwd", version, True, False)
    return client


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames",
            {"name": "check", "default_action": "Allow"},
            "protected_hostname/v1_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts",
            {"name": "check", "default_action": "Allow"},
            "protected_hostname/v2_success.json",
        ),
    ),
)
def test_protected_hostname_group_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Create a Protected hostname group.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-protected-hostname-group-create called.
    Then:
     - Ensure that Protected hostname created.
    """
    from FortinetFortiwebVM import protected_hostname_group_create_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = protected_hostname_group_create_command(mock_client, args)
    output = f'{OutputTitle.PROTECTED_HOSTNAME_GROUP.value} {args["name"]} {OutputTitle.CREATED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames",
            {"name": "check", "default_action": "Allow"},
            "protected_hostname/v1_failed_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts",
            {"name": "check", "default_action": "Allow"},
            "protected_hostname/v2_failed_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
        ),
    ),
)
def test_api_fail_protected_hostname_group_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create a protected hostname group.
    Given:
     - User has provided exist name.
    When:
     - fortiwebvm-protected-hostname-group-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import protected_hostname_group_create_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(DemistoException) as error_info:
        protected_hostname_group_create_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames",
            {"name": "check", "default_action": "wrong_action"},
            "protected_hostname/v1_failed_exist.json",
            ErrorMessage.DEFAULT_ACTION.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts",
            {"name": "check", "default_action": "wrong_action"},
            "protected_hostname/v2_failed_exist.json",
            ErrorMessage.DEFAULT_ACTION.value,
        ),
    ),
)
def test_input_fail_protected_hostname_group_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create a protected hostname group.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-protected-hostname-group-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import protected_hostname_group_create_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(ValueError) as error_info:
        protected_hostname_group_create_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames/check",
            {"name": "check", "default_action": "Deny"},
            "protected_hostname/v1_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts?mkey=check",
            {"name": "check", "default_action": "Deny"},
            "protected_hostname/v2_success.json",
        ),
    ),
)
def test_protected_hostname_group_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Update a protected hostname group.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-protected-hostname-group-update called.
    Then:
     - Ensure that protected hostname updated.
    """
    from FortinetFortiwebVM import protected_hostname_group_update_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response)
    result = protected_hostname_group_update_command(mock_client, args)
    output = f'{OutputTitle.PROTECTED_HOSTNAME_GROUP.value} {args["name"]} {OutputTitle.UPDATED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames/check",
            {
                "name": "check",
            },
            "protected_hostname/v1_failed_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts?mkey=check",
            {
                "name": "check",
            },
            "protected_hostname/v2_failed_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_api_fail_protected_hostname_group_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Update a protected hostname group.
    Given:
     - User has provided not exist name.
    When:
     - fortiwebvm-protected-hostname-group-update called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import protected_hostname_group_update_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(DemistoException) as error_info:
        protected_hostname_group_update_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames/check",
            {"name": "check", "default_action": "wrong_action"},
            "protected_hostname/v1_success.json",
            ErrorMessage.DEFAULT_ACTION.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts?mkey=check",
            {"name": "check", "default_action": "wrong_action"},
            "protected_hostname/v2_success.json",
            ErrorMessage.DEFAULT_ACTION.value,
        ),
    ),
)
def test_input_fail_protected_hostname_group_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Update a protected hostname group.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-protected-hostname-group-update called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import protected_hostname_group_update_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(ValueError) as error_info:
        protected_hostname_group_update_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames/check",
            {"name": "check"},
            "protected_hostname/v1_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts?mkey=check",
            {"name": "check"},
            "protected_hostname/v2_success.json",
        ),
    ),
)
def test_protected_hostname_group_delete_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Delete a protected hostname group.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-protected-hostname-group-delete called.
    Then:
     - Ensure that protected hostname deleted.
    """
    from FortinetFortiwebVM import protected_hostname_group_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(url=url, json=json_response)
    result = protected_hostname_group_delete_command(mock_client, args)
    output = f'{OutputTitle.PROTECTED_HOSTNAME_GROUP.value} {args["name"]} {OutputTitle.DELETED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames/check",
            {"name": "check"},
            "protected_hostname/v1_failed_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts?mkey=check",
            {"name": "check"},
            "protected_hostname/v2_failed_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_api_fail_protected_hostname_group_delete_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Delete a protected hostname group.
    Given:
     - User has provided not exist name.
    When:
     - fortiwebvm-protected-hostname-group-delete called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import protected_hostname_group_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(DemistoException) as error_info:
        protected_hostname_group_delete_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "expected"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames",
            {"page": "1", "page_size": 3},
            "protected_hostname/v1_get_list_success.json",
            3,
        ),
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames",
            {
                "limit": 2,
            },
            "protected_hostname/v1_get_list_success.json",
            2,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts",
            {"page": "1", "page_size": 3},
            "protected_hostname/v2_get_list_success.json",
            3,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts",
            {
                "limit": 2,
            },
            "protected_hostname/v2_get_list_success.json",
            2,
        ),
    ),
)
def test_protected_hostname_group_list_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    expected,
):
    """
    Scenario: List a protected hostname groups.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-protected-hostname-group-list called.
    Then:
     - Ensure that protected hostname listed.
    """
    from FortinetFortiwebVM import protected_hostname_group_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = protected_hostname_group_list_command(mock_client, args)
    if isinstance(result.outputs, list):
        assert len(result.outputs) == expected
    assert result.outputs_prefix == "FortiwebVM.ProtectedHostnameGroup"


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "expected_value"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost",
            {"group_name": "1234", "action": "Allow", "host": "1.2.3.4"},
            "protected_hostname_member/v1_success.json",
            "3",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts/host-list?mkey=1234",
            {
                "group_name": "1234",
                "action": "Allow",
                "host": "1.2.3.4",
                "ignore_port": "disable",
                "include_subdomains": "disable",
            },
            "protected_hostname_member/v2_success.json",
            "5",
        ),
    ),
)
def test_protected_hostname_member_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    expected_value: str,
):
    """
    Scenario: Create a protected hostname member.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-protected-hostname-member-create called.
    Then:
     - Ensure that protected hostname created.
    """
    from FortinetFortiwebVM import protected_hostname_member_create_command

    json_response = load_mock_response(jsonpath)
    json_response_get = load_mock_response(
        "protected_hostname_member/v1_get_list_success.json"
    )
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response)
    requests_mock.get(url=url, json=json_response_get, status_code=200)
    result = protected_hostname_member_create_command(mock_client, args)
    assert result.outputs_prefix == "FortiwebVM.ProtectedHostnameMember"
    assert isinstance(result.outputs, dict)
    assert result.outputs["id"] == expected_value


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost",
            {"group_name": "1234", "action": "Allow", "host": "1.2.3.4"},
            "protected_hostname_member/v1_failed_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts/host-list?mkey=1234",
            {
                "group_name": "1234",
                "action": "Allow",
                "host": "1.2.3.4",
                "ignore_port": "disable",
                "include_subdomains": "disable",
            },
            "protected_hostname_member/v2_failed_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
        ),
    ),
)
def test_api_fail_protected_hostname_member_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create a protected hostname member.
    Given:
     - User has provided exist host.
    When:
     - fortiwebvm-protected-hostname-member-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import protected_hostname_member_create_command

    json_response = load_mock_response(jsonpath)
    json_response_get = load_mock_response(
        "protected_hostname_member/v1_get_list_success.json"
    )
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    requests_mock.get(url=url, json=json_response_get, status_code=HTTPStatus.OK)
    with pytest.raises(DemistoException) as error_info:
        protected_hostname_member_create_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost",
            {"group_name": "1234", "action": "wrong_action", "host": "1.2.3.4"},
            "protected_hostname_member/v1_failed_exist.json",
            ErrorMessage.ACTION.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts/host-list?mkey=1234",
            {
                "group_name": "1234",
                "action": "wrong_action",
                "host": "1.2.3.4",
                "ignore_port": "disable",
                "include_subdomains": "disable",
            },
            "protected_hostname_member/v2_failed_exist.json",
            ErrorMessage.ACTION.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts/host-list?mkey=1234",
            {
                "group_name": "1234",
                "action": "Allow",
                "host": "1.2.3.4",
                "ignore_port": "wrong",
                "include_subdomains": "disable",
            },
            "protected_hostname_member/v2_failed_exist.json",
            ErrorMessage.IGNORE_PORT.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts/host-list?mkey=1234",
            {
                "group_name": "1234",
                "action": "Allow",
                "host": "1.2.3.4",
                "ignore_port": "disable",
                "include_subdomains": "wrong",
            },
            "protected_hostname_member/v2_failed_exist.json",
            ErrorMessage.INCLUDE_SUBDOMAINS.value,
        ),
    ),
)
def test_input_fail_protected_hostname_member_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create a protected hostname member.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-protected-hostname-member-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import protected_hostname_member_create_command

    json_response = load_mock_response(jsonpath)
    json_response_get = load_mock_response(
        "protected_hostname_member/v1_get_list_success.json"
    )
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    requests_mock.get(url=url, json=json_response_get, status_code=HTTPStatus.OK)
    with pytest.raises(ValueError) as error_info:
        protected_hostname_member_create_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    (
        "version",
        "endpoint",
        "args",
        "jsonpath",
    ),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost/1",
            {
                "group_name": "1234",
                "member_id": "1",
                "action": "Allow",
                "host": "1.2.3.4",
            },
            "protected_hostname_member/v1_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts/host-list?mkey=1234&sub_mkey=1",
            {
                "group_name": "1234",
                "member_id": "1",
                "action": "Allow",
                "host": "1.2.3.4",
                "ignore_port": "disable",
                "include_subdomains": "disable",
            },
            "protected_hostname_member/v2_success.json",
        ),
    ),
)
def test_protected_hostname_member_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Update a protected hostname member.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-protected-hostname-member-create called.
    Then:
     - Ensure that protected hostname updated.
    """
    from FortinetFortiwebVM import protected_hostname_member_update_command

    if version == ClientV1.API_VER:
        url = urljoin(
            mock_client.base_url,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost",
        )
        get_response = load_mock_response(
            "protected_hostname_member/v1_get_list_success.json"
        )
        requests_mock.get(url=url, json=get_response)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response)
    result = protected_hostname_member_update_command(mock_client, args)
    output = f'{OutputTitle.PROTECTED_HOSTNAME_MEMBER.value} {args["member_id"]} {OutputTitle.UPDATED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost/1",
            {
                "group_name": "1234",
                "member_id": "1",
                "action": "Allow",
                "host": "1.2.3.4",
            },
            "protected_hostname_member/v1_failed_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts/host-list?mkey=1234&sub_mkey=1",
            {
                "group_name": "1234",
                "member_id": "1",
                "action": "Allow",
                "host": "1.2.3.4",
                "ignore_port": "disable",
                "include_subdomains": "disable",
            },
            "protected_hostname_member/v2_failed_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_api_fail_protected_hostname_member_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Update a protected hostname member.
    Given:
     - User has provided exist host.
    When:
     - fortiwebvm-protected-hostname-member-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import protected_hostname_member_update_command

    if version == ClientV1.API_VER:
        url = urljoin(
            mock_client.base_url,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost",
        )
        get_response = load_mock_response(
            "protected_hostname_member/v1_get_list_success.json"
        )
        requests_mock.get(url=url, json=get_response)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(DemistoException) as error_info:
        protected_hostname_member_update_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost/1",
            {
                "group_name": "1234",
                "member_id": "1",
                "action": "wrong",
                "host": "1.2.3.4",
            },
            "protected_hostname_member/v1_failed_not_exist.json",
            ErrorMessage.ACTION.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts/host-list?mkey=1234&sub_mkey=1",
            {
                "group_name": "1234",
                "member_id": "1",
                "action": "wrong",
                "host": "1.2.3.4",
                "ignore_port": "disable",
                "include_subdomains": "disable",
            },
            "protected_hostname_member/v2_failed_not_exist.json",
            ErrorMessage.ACTION.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts/host-list?mkey=1234&sub_mkey=1",
            {
                "group_name": "1234",
                "member_id": "1",
                "action": "Allow",
                "host": "1.2.3.4",
                "ignore_port": "wrong",
                "include_subdomains": "disable",
            },
            "protected_hostname_member/v2_failed_not_exist.json",
            ErrorMessage.IGNORE_PORT.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts/host-list?mkey=1234&sub_mkey=1",
            {
                "group_name": "1234",
                "member_id": "1",
                "action": "Allow",
                "host": "1.2.3.4",
                "ignore_port": "disable",
                "include_subdomains": "wrong",
            },
            "protected_hostname_member/v2_failed_not_exist.json",
            ErrorMessage.INCLUDE_SUBDOMAINS.value,
        ),
    ),
)
def test_input_fail_protected_hostname_member_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Update a protected hostname member.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-protected-hostname-member-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import protected_hostname_member_update_command

    if version == ClientV1.API_VER:
        url = urljoin(
            mock_client.base_url,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost",
        )
        get_response = load_mock_response(
            "protected_hostname_member/v1_get_list_success.json"
        )
        requests_mock.get(url=url, json=get_response)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(ValueError) as error_info:
        protected_hostname_member_update_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost/1",
            {
                "group_name": "1234",
                "member_id": "1",
            },
            "protected_hostname_member/v1_delete_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts/host-list?mkey=1234&sub_mkey=1",
            {
                "group_name": "1234",
                "member_id": "1",
            },
            "protected_hostname_member/v2_delete_success.json",
        ),
    ),
)
def test_protected_hostname_member_delete_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Delete a protected hostname member.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-protected-hostname-member-delete called.
    Then:
     - Ensure that protected hostname member deleted.
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import protected_hostname_member_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(url=url, json=json_response)
    result = protected_hostname_member_delete_command(mock_client, args)
    output = f'{OutputTitle.PROTECTED_HOSTNAME_MEMBER.value} {args["member_id"]} {OutputTitle.DELETED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost/1",
            {
                "group_name": "1234",
                "member_id": "1",
            },
            "protected_hostname_member/v1_delete_failed.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts/host-list?mkey=1234&sub_mkey=1",
            {
                "group_name": "1234",
                "member_id": "1",
            },
            "protected_hostname_member/v2_delete_failed.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_fail_protected_hostname_member_delete_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Delete a protected hostname member.
    Given:
     - User has provided not exist host.
    When:
     - fortiwebvm-protected-hostname-member-delete called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import protected_hostname_member_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(DemistoException) as error_info:
        protected_hostname_member_delete_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "expected"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost",
            {"group_name": "1234", "page": "1", "page_size": 3},
            "protected_hostname_member/v1_get_list_success.json",
            3,
        ),
        (
            ClientV1.API_VER,
            "ServerObjects/ProtectedHostnames/ProtectedHostnames/1234/ProtectedHostnamesNewHost",
            {
                "group_name": "1234",
                "limit": 2,
            },
            "protected_hostname_member/v1_get_list_success.json",
            2,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts/host-list?mkey=1234",
            {"group_name": "1234", "page": "1", "page_size": 3},
            "protected_hostname_member/v2_get_list_success.json",
            3,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/allow-hosts/host-list?mkey=1234",
            {
                "group_name": "1234",
                "limit": 2,
            },
            "protected_hostname_member/v2_get_list_success.json",
            2,
        ),
    ),
)
def test_protected_hostname_member_list_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    expected,
):
    """
    Scenario: List a protected hostname members.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-protected-hostname-member-list called.
    Then:
     - Ensure that protected hostname members listed.
    """
    from FortinetFortiwebVM import protected_hostname_member_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = protected_hostname_member_list_command(mock_client, args)
    assert isinstance(result.outputs, dict)
    assert isinstance(result.outputs["Members"], list)
    assert len(result.outputs["Members"]) == expected
    assert result.outputs_prefix == "FortiwebVM.ProtectedHostnameMember"


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/IPList",
            {
                "name": "check",
            },
            "ip_list_group/v1_create_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list",
            {
                "name": "check",
                "action": "Alert deny",
                "block_period": 600,
                "severity": "Low",
                "ignore_x_forwarded_for": "disable",
            },
            "ip_list_group/v2_create_success.json",
        ),
    ),
)
def test_ip_list_group_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Create an IP list group.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-ip-list-group-create called.
    Then:
     - Ensure that protected hostname created.
    """
    from FortinetFortiwebVM import ip_list_group_create_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response)
    result = ip_list_group_create_command(mock_client, args)
    output = (
        f'{OutputTitle.IP_LIST_GROUP.value} {args["name"]} {OutputTitle.CREATED.value}'
    )
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/IPList",
            {
                "name": "check",
            },
            "ip_list_group/v1_create_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list",
            {
                "name": "check",
                "action": "Alert deny",
                "block_period": 600,
                "severity": "Low",
                "ignore_x_forwarded_for": "disable",
            },
            "ip_list_group/v2_create_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
        ),
    ),
)
def test_api_fail_ip_list_group_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create an IP list group.
    Given:
     - User has provided exist name.
    When:
     - fortiwebvm-ip-list-group-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import ip_list_group_create_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(DemistoException) as error_info:
        ip_list_group_create_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list",
            {
                "name": "check",
                "action": "wrong",
                "block_period": 0,
                "severity": "Low",
                "ignore_x_forwarded_for": "disable",
            },
            "ip_list_group/v2_create_success.json",
            ErrorMessage.IP_ACTION.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list",
            {
                "name": "check",
                "action": "Alert deny",
                "block_period": -1,
                "severity": "Low",
                "ignore_x_forwarded_for": "disable",
            },
            "ip_list_group/v2_create_success.json",
            ErrorMessage.BLOCK_PERIOD.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list",
            {
                "name": "check",
                "action": "wrong",
                "block_period": 600,
                "severity": "Low",
                "ignore_x_forwarded_for": "disable",
            },
            "ip_list_group/v2_create_success.json",
            ErrorMessage.IP_ACTION.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list",
            {
                "name": "check",
                "action": "Alert deny",
                "block_period": 601,
                "severity": "Low",
                "ignore_x_forwarded_for": "disable",
            },
            "ip_list_group/v2_create_success.json",
            ErrorMessage.BLOCK_PERIOD.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list",
            {
                "name": "check",
                "action": "Alert deny",
                "block_period": 600,
                "severity": "wrong",
                "ignore_x_forwarded_for": "disable",
            },
            "ip_list_group/v2_create_success.json",
            ErrorMessage.SEVERITY.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list",
            {
                "name": "check",
                "action": "Alert deny",
                "block_period": 600,
                "severity": "Low",
                "ignore_x_forwarded_for": "wrong",
            },
            "ip_list_group/v2_create_success.json",
            "ignore_x_forwarded_for should be enable/disable",
        ),
    ),
)
def test_input_fail_ip_list_group_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create an IP list group.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-ip-list-group-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import ip_list_group_create_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(ValueError) as error_info:
        ip_list_group_create_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list?mkey=check",
            {
                "name": "check",
                "action": "Alert deny",
            },
            "ip_list_group/v2_update_success.json",
        ),
    ),
)
def test_ip_list_group_upadte_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Update an IP list group.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-ip-list-group-update called.
    Then:
     - Ensure that protected hostname updated.
    """
    from FortinetFortiwebVM import ip_list_group_update_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response)
    result = ip_list_group_update_command(mock_client, args)
    output = (
        f'{OutputTitle.IP_LIST_GROUP.value} {args["name"]} {OutputTitle.UPDATED.value}'
    )
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list?mkey=check",
            {
                "name": "check",
                "action": "Alert deny",
            },
            "ip_list_group/v2_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_api_fail_ip_list_group_upadte_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Update an IP list group.
    Given:
     - User has provided not exist name.
    When:
     - fortiwebvm-ip-list-group-update called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import ip_list_group_update_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(DemistoException) as error_info:
        ip_list_group_update_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "no_matter",
            {
                "name": "check",
                "action": "Alert deny",
            },
            "ip_list_group/v2_not_exist.json",
            ErrorMessage.V1_NOT_SUPPORTED.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list?mkey=check",
            {
                "name": "check",
                "action": "wrong",
            },
            "ip_list_group/v2_not_exist.json",
            'The action should be "Alert deny"/"Block period"/"Deny (no log)"',
        ),
    ),
)
def test_input_fail_ip_list_group_upadte_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Update an IP list group.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-ip-list-group-update called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import ip_list_group_update_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(ValueError) as error_info:
        ip_list_group_update_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/IPList/Example",
            {"name": "Example"},
            "protected_hostname/v1_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list?mkey=Example",
            {"name": "Example"},
            "protected_hostname/v2_success.json",
        ),
    ),
)
def test_ip_list_group_delete_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Delete an IP list group.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-ip-list-group-delete called.
    Then:
     - Ensure that protected hostname deleted.
    """
    from FortinetFortiwebVM import ip_list_group_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(url=url, json=json_response)

    result = ip_list_group_delete_command(mock_client, args)
    output = (
        f'{OutputTitle.IP_LIST_GROUP.value} {args["name"]} {OutputTitle.DELETED.value}'
    )
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/IPList/Example",
            {"name": "Example"},
            "protected_hostname/v1_failed_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list?mkey=Example",
            {"name": "Example"},
            "protected_hostname/v2_failed_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_fail_ip_list_group_delete_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Delete an IP list group.
    Given:
     - User has provided not exist name.
    When:
     - fortiwebvm-ip-list-group-delete called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import ip_list_group_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(DemistoException) as error_info:
        ip_list_group_delete_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "expected"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/IPList",
            {"page": "1", "page_size": 3},
            "ip_list_group/v1_list_success.json",
            3,
        ),
        (
            ClientV1.API_VER,
            "WebProtection/Access/IPList",
            {
                "limit": 2,
            },
            "ip_list_group/v1_list_success.json",
            2,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list",
            {"page": "1", "page_size": 3},
            "ip_list_group/v2_list_success.json",
            3,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list",
            {
                "limit": 2,
            },
            "ip_list_group/v2_list_success.json",
            2,
        ),
    ),
)
def test_ip_list_group_list_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    expected,
):
    """
    Scenario: List an IP list groups.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-ip-list-group-list called.
    Then:
     - Ensure that IP list groups listed.
    """
    from FortinetFortiwebVM import ip_list_group_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = ip_list_group_list_command(mock_client, args)
    if isinstance(result.outputs, list):
        assert len(result.outputs) == expected
    assert result.outputs_prefix == "FortiwebVM.IpListGroup"


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "expected_value"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/IPList/1234/IPListCreateIPListPolicyMember",
            {
                "group_name": "1234",
                "ip_address": "1.2.3.89",
                "type": "Black IP",
                "severity": "Low",
            },
            "ip_list_member/v1_create_success.json",
            "6",
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list/members?mkey=1234",
            {
                "group_name": "1234",
                "ip_address": "1.1.1.1",
                "type": "Black IP",
                "severity": "Low",
            },
            "ip_list_member/v2_create_success.json",
            "5",
        ),
    ),
)
def test_ip_list_member_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    expected_value: str,
):
    """
    Scenario: Create an IP list member.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-ip-list-member-create called.
    Then:
     - Ensure that IP list member created.
    """
    from FortinetFortiwebVM import ip_list_member_create_command

    json_response = load_mock_response(jsonpath)
    json_response_get = load_mock_response("ip_list_member/v1_list_success.json")
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response)
    requests_mock.get(url=url, json=json_response_get)

    result = ip_list_member_create_command(mock_client, args)
    assert result.outputs_prefix == "FortiwebVM.IpListMember"
    assert isinstance(result.outputs, dict)
    assert result.outputs["id"] == expected_value


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/IPList/1234/IPListCreateIPListPolicyMember",
            {
                "group_name": "1234",
                "ip_address": "1.1.1.1",
                "type": "Black IP",
                "severity": "Low",
            },
            "ip_list_member/v1_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list/members?mkey=1234",
            {
                "group_name": "1234",
                "ip_address": "1.1.1.1",
                "type": "Black IP",
                "severity": "Low",
            },
            "ip_list_member/v2_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
        ),
    ),
)
def test_api_fail_ip_list_member_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create an IP list member.
    Given:
     - User has provided exist host.
    When:
     - fortiwebvm-ip-list-member-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import ip_list_member_create_command

    json_response = load_mock_response(jsonpath)
    json_response_get = load_mock_response("ip_list_member/v1_list_success.json")
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    requests_mock.get(url=url, json=json_response_get)

    with pytest.raises(DemistoException) as error_info:
        ip_list_member_create_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/IPList/1234/IPListCreateIPListPolicyMember",
            {
                "group_name": "1234",
                "ip_address": "1.1.1.1",
                "type": "Allow Only Ip",
                "severity": "Low",
            },
            "ip_list_member/v1_exist.json",
            ErrorMessage.ALLOW_IP_V1.value,
        ),
        (
            ClientV1.API_VER,
            "WebProtection/Access/IPList/1234/IPListCreateIPListPolicyMember",
            {
                "group_name": "1234",
                "ip_address": "wrong",
                "type": "Black IP",
                "severity": "Low",
            },
            "ip_list_member/v1_exist.json",
            "wrong is not a valid IPv4/IPv6 address.",
        ),
        (
            ClientV1.API_VER,
            "WebProtection/Access/IPList/1234/IPListCreateIPListPolicyMember",
            {
                "group_name": "1234",
                "ip_address": "1.1.1.1",
                "type": "wrong",
                "severity": "Low",
            },
            "ip_list_member/v1_exist.json",
            'The type should be "Allow Only Ip"/"Black IP"/"Trust IP"',
        ),
        (
            ClientV1.API_VER,
            "WebProtection/Access/IPList/1234/IPListCreateIPListPolicyMember",
            {
                "group_name": "1234",
                "ip_address": "1.1.1.1",
                "type": "Black IP",
                "severity": "wrong",
            },
            "ip_list_member/v1_exist.json",
            "The severity should be High/Medium/Low/Info",
        ),
    ),
)
def test_input_fail_ip_list_member_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create an IP list member.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-ip-list-member-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import ip_list_member_create_command

    json_response = load_mock_response(jsonpath)
    json_response_get = load_mock_response("ip_list_member/v1_list_success.json")
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    requests_mock.get(url=url, json=json_response_get)

    with pytest.raises(ValueError) as error_info:
        ip_list_member_create_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/IPList/1234/IPListCreateIPListPolicyMember/1",
            {
                "group_name": "1234",
                "member_id": "1",
                "ip_address": "1.1.1.1",
                "type": "Black IP",
            },
            "ip_list_member/v1_create_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list/members?mkey=1234&sub_mkey=1",
            {
                "group_name": "1234",
                "member_id": "1",
                "ip_address": "1.1.1.1",
                "type": "Black IP",
            },
            "ip_list_member/v2_create_success.json",
        ),
    ),
)
def test_ip_list_member_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Update an IP list member.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-ip-list-member-update called.
    Then:
     - Ensure that protected hostname updated.
    """
    from FortinetFortiwebVM import ip_list_member_update_command

    if version == ClientV1.API_VER:
        url = urljoin(
            mock_client.base_url,
            "WebProtection/Access/IPList/1234/IPListCreateIPListPolicyMember",
        )
        get_response = load_mock_response("ip_list_member/v1_list_success.json")
        requests_mock.get(url=url, json=get_response)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response)
    result = ip_list_member_update_command(mock_client, args)
    output = f'{OutputTitle.IP_LIST_MEMBER.value} {args["member_id"]} {OutputTitle.UPDATED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/IPList/1234/IPListCreateIPListPolicyMember/1",
            {
                "group_name": "1234",
                "member_id": "1",
                "ip_address": "1.1.1.1",
                "type": "Black IP",
            },
            "ip_list_member/v1_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list/members?mkey=1234&sub_mkey=1",
            {
                "group_name": "1234",
                "member_id": "1",
                "ip_address": "1.1.1.1",
                "type": "Black IP",
            },
            "ip_list_member/v2_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_api_fail_ip_list_member_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Update an IP list member.
    Given:
     - User has provided not exist host.
    When:
     - fortiwebvm-ip-list-member-update called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import ip_list_member_update_command

    if version == ClientV1.API_VER:
        url = urljoin(
            mock_client.base_url,
            "WebProtection/Access/IPList/1234/IPListCreateIPListPolicyMember",
        )
        get_response = load_mock_response("ip_list_member/v1_list_success.json")
        requests_mock.get(url=url, json=get_response, status_code=HTTPStatus.OK)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(DemistoException) as error_info:
        ip_list_member_update_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/IPList/1234/IPListCreateIPListPolicyMember/1",
            {
                "group_name": "1234",
                "member_id": "1",
            },
            "ip_list_member/v1_delete_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list/members?mkey=1234&sub_mkey=1",
            {
                "group_name": "1234",
                "member_id": "1",
            },
            "ip_list_member/v2_delete_success.json",
        ),
    ),
)
def test_ip_list_member_delete_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Delete an IP list member.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-protected-ip-list-member-delete called.
    Then:
     - Ensure that IP list member deletedd.
    """
    from FortinetFortiwebVM import ip_list_member_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(url=url, json=json_response)
    result = ip_list_member_delete_command(mock_client, args)
    output = f'{OutputTitle.IP_LIST_MEMBER.value} {args["member_id"]} {OutputTitle.DELETED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/IPList/1234/IPListCreateIPListPolicyMember/1",
            {
                "group_name": "1234",
                "member_id": "1",
            },
            "ip_list_member/v1_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list/members?mkey=1234&sub_mkey=1",
            {
                "group_name": "1234",
                "member_id": "1",
            },
            "ip_list_member/v2_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_fail_ip_list_member_delete_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Delete an IP list member.
    Given:
     - User has provided not exist host.
    When:
     - fortiwebvm-protected-ip-list-member-delete called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import ip_list_member_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(DemistoException) as error_info:
        ip_list_member_delete_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "expected"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/IPList/ronhadad/IPListCreateIPListPolicyMember",
            {"group_name": "ronhadad", "page": "1", "page_size": 3},
            "ip_list_member/v1_list_success.json",
            3,
        ),
        (
            ClientV1.API_VER,
            "WebProtection/Access/IPList/ronhadad/IPListCreateIPListPolicyMember",
            {
                "group_name": "ronhadad",
                "member_id": "2",
            },
            "ip_list_member/v1_list_success.json",
            1,
        ),
        (
            ClientV1.API_VER,
            "WebProtection/Access/IPList/ronhadad/IPListCreateIPListPolicyMember",
            {"group_name": "ronhadad", "limit": 1},
            "ip_list_member/v1_list_success.json",
            1,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list/members?mkey=ronhadad",
            {"group_name": "ronhadad", "page": "1", "page_size": 3},
            "ip_list_member/v2_list_success.json",
            3,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list/members?mkey=ronhadad",
            {
                "group_name": "ronhadad",
                "member_id": "2",
            },
            "ip_list_member/v2_list_success.json",
            1,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/ip-list/members?mkey=ronhadad",
            {"group_name": "ronhadad", "limit": 1},
            "ip_list_member/v2_list_success.json",
            1,
        ),
    ),
)
def test_ip_list_member_list_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    expected,
):
    """
    Scenario: List an IP list members.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-ip-list-member-list called.
    Then:
     - Ensure that IP list members listed.
    """
    from FortinetFortiwebVM import ip_list_member_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = ip_list_member_list_command(mock_client, args)
    assert isinstance(result.outputs, dict)
    assert isinstance(result.outputs["Members"], list)
    assert len(result.outputs["Members"]) == expected
    assert result.outputs_prefix == "FortiwebVM.IpListMember"


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath", "expected_value"),
    (
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting",
            "http_content_routing_member/v1_create_success.json",
            "1",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy/http-content-routing-list?mkey=policy",
            "http_content_routing_member/v2_create_success.json",
            "2",
        ),
    ),
)
def test_http_content_routing_member_add_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    jsonpath: str,
    expected_value: str,
):
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
    json_response_get = load_mock_response(
        "http_content_routing_member/v1_list_success.json"
    )
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response)
    requests_mock.get(url=url, json=json_response_get)
    args = {
        "policy_name": "policy",
        "http_content_routing_policy": "1234",
        "is_default": "yes",
        "inherit_web_protection_profile": "disable",
        "status": "enable",
    }
    result = http_content_routing_member_add_command(mock_client, args)
    assert result.outputs_prefix == "FortiwebVM.HttpContentRoutingMember"
    assert isinstance(result.outputs, dict)
    assert expected_value == result.outputs["id"]


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath", "error_msg", "additional_args"),
    (
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting",
            "http_content_routing_member/v1_wrong_content_routing.json",
            ErrorMessage.ARGUMENTS.value,
            {},
        ),
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting",
            "http_content_routing_member/v1_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
            {},
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy/http-content-routing-list?mkey=policy",
            "http_content_routing_member/v2_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
            {},
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy/http-content-routing-list?mkey=policy",
            "http_content_routing_member/v2_wrong_content_routing.json",
            ErrorMessage.ARGUMENTS.value,
            {},
        ),
    ),
)
def test_api_fail_http_content_routing_member_add_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    jsonpath: str,
    error_msg: str,
    additional_args: dict,
):
    """
    Scenario: Create an HTTP content routing member.
    Given:
     - User has an existed host.
    When:
     - fortiwebvm-http-content-routing-member-add called.
    Then:
     - Ensure relevant error raised.
    """

    from FortinetFortiwebVM import http_content_routing_member_add_command

    json_response = load_mock_response(jsonpath)
    json_response_get = load_mock_response(
        "http_content_routing_member/v1_list_success.json"
    )
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response_get)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    args = {
        "policy_name": "policy",
        "http_content_routing_policy": "1234",
        "is_default": "yes",
        "inherit_web_protection_profile": "disable",
        "status": "enable",
    }
    args.update(additional_args)
    with pytest.raises(DemistoException) as error_info:
        http_content_routing_member_add_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath", "error_msg", "additional_args"),
    (
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting",
            "http_content_routing_member/v1_wrong_content_routing.json",
            ErrorMessage.IS_DEFAULT.value,
            {"is_default": "wrong"},
        ),
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting",
            "http_content_routing_member/v1_wrong_content_routing.json",
            ErrorMessage.INHERIT_WEB_PROTECTION_PROFILE.value,
            {"inherit_web_protection_profile": "wrong"},
        ),
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting",
            "http_content_routing_member/v1_wrong_content_routing.json",
            ErrorMessage.STATUS.value,
            {"status": "wrong"},
        ),
    ),
)
def test_input_fail_http_content_routing_member_add_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    jsonpath: str,
    error_msg: str,
    additional_args: dict,
):
    """
    Scenario: Create an HTTP content routing member.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-http-content-routing-member-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import http_content_routing_member_add_command

    json_response = load_mock_response(jsonpath)
    json_response_get = load_mock_response(
        "http_content_routing_member/v1_list_success.json"
    )
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response_get)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    args = {
        "policy_name": "policy",
        "http_content_routing_policy": "1234",
        "is_default": "yes",
        "inherit_web_protection_profile": "disable",
        "status": "enable",
    }
    args.update(additional_args)
    with pytest.raises(ValueError) as error_info:
        http_content_routing_member_add_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting/1",
            "http_content_routing_member/v1_update_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy/http-content-routing-list?mkey=policy&sub_mkey=1",
            "http_content_routing_member/v2_update_success.json",
        ),
    ),
)
def test_http_content_routing_member_update_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
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

    if version == ClientV1.API_VER:
        url = urljoin(
            mock_client.base_url,
            "Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting",
        )
        get_response = load_mock_response(
            "http_content_routing_member/v1_list_success.json"
        )
        requests_mock.get(url=url, json=get_response)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response)
    args = {"policy_name": "policy", "http_content_routing_policy": "1234", "id": 1}

    result = http_content_routing_member_update_command(mock_client, args)
    output = f'{OutputTitle.HTTP_CONTENT_ROUTING_MEMBER.value} {args["id"]} {OutputTitle.UPDATED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting/1",
            "http_content_routing_member/v1_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting/1",
            "http_content_routing_member/v1_wrong_content_routing.json",
            ErrorMessage.ARGUMENTS.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy/http-content-routing-list?mkey=policy&sub_mkey=1",
            "http_content_routing_member/v2_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy/http-content-routing-list?mkey=policy&sub_mkey=1",
            "http_content_routing_member/v2_wrong_content_routing.json",
            ErrorMessage.ARGUMENTS.value,
        ),
    ),
)
def test_api_fail_http_content_routing_member_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Update an HTTP content routing member.
    Given:
     - User has provided not exist host.
     - User has provided wrong parameters.
    When:
     - fortiwebvm-http-content-routing-member-update called.
    Then:
     - Ensure relevant error raised.
    """

    from FortinetFortiwebVM import http_content_routing_member_update_command

    if version == ClientV1.API_VER:
        url = urljoin(
            mock_client.base_url,
            "Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting",
        )
        get_response = load_mock_response(
            "http_content_routing_member/v1_list_success.json"
        )
        requests_mock.get(url=url, json=get_response, status_code=HTTPStatus.OK)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    args = {"policy_name": "policy", "http_content_routing_policy": "1234", "id": 1}

    with pytest.raises(DemistoException) as error_info:
        http_content_routing_member_update_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting/1",
            "http_content_routing_member/v1_delete_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy/http-content-routing-list?mkey=policy&sub_mkey=1",
            "http_content_routing_member/v2_delete_success.json",
        ),
    ),
)
def test_http_content_routing_member_delete_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
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
    requests_mock.delete(url=url, json=json_response)
    args = {"policy_name": "policy", "id": 1}

    result = http_content_routing_member_delete_command(mock_client, args)
    output = f'{OutputTitle.HTTP_CONTENT_ROUTING_MEMBER.value} {args["id"]} {OutputTitle.DELETED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy/policy/EditContentRouting/1",
            "http_content_routing_member/v1_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy/http-content-routing-list?mkey=policy&sub_mkey=1",
            "http_content_routing_member/v2_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_fail_http_content_routing_member_delete_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Delete an HTTP content routing member.
    Given:
     - User has provided not exist host.
    When:
     - fortiwebvm-http-content-routing-member-delete called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import http_content_routing_member_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    args = {"policy_name": "policy", "id": 1}
    with pytest.raises(DemistoException) as error_info:
        http_content_routing_member_delete_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "expected"),
    (
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy/Example/EditContentRouting",
            {"policy_name": "Example", "page": "1", "page_size": "2"},
            "http_content_routing_member/v1_list_success.json",
            2,
        ),
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy/Example/EditContentRouting",
            {
                "policy_name": "Example",
                "limit": 1,
            },
            "http_content_routing_member/v1_list_success.json",
            1,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy/http-content-routing-list?mkey=Example",
            {"policy_name": "Example", "page": "1", "page_size": "2"},
            "http_content_routing_member/v2_list_success.json",
            2,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy/http-content-routing-list?mkey=Example",
            {
                "policy_name": "Example",
                "limit": 1,
            },
            "http_content_routing_member/v2_list_success.json",
            1,
        ),
    ),
)
def test_http_content_routing_member_list_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    expected,
):
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
    assert isinstance(result.outputs, dict)
    assert isinstance(result.outputs["Members"], list)
    assert len(result.outputs["Members"]) == expected
    assert result.outputs_prefix == "FortiwebVM.HttpContentRoutingMember"


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/GeoIP",
            "geo_ip_group/v1_create_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/geo-block-list",
            "geo_ip_group/v2_create_success.json",
        ),
    ),
)
def test_geo_ip_group_create_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
    """
    Scenario: Create Geo IP group.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-geo-ip-group-create called.
    Then:
     - Ensure that Geo IP group created.
    """
    from FortinetFortiwebVM import geo_ip_group_create_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response)
    args = {
        "name": "check",
        "action": "Alert deny",
        "block_period": "50",
        "severity": "High",
        "ignore_x_forwarded_for": "enable",
    }

    result = geo_ip_group_create_command(mock_client, args)
    output = (
        f'{OutputTitle.GEO_IP_GROUP.value} {args["name"]} {OutputTitle.CREATED.value}'
    )
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath", "error_msg", "additional_args"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/GeoIP",
            "geo_ip_group/v1_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
            {},
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/geo-block-list",
            "geo_ip_group/v2_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
            {},
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/geo-block-list",
            "geo_ip_group/v2_wrong_parameters.json",
            ErrorMessage.ARGUMENTS.value,
            {},
        ),
    ),
)
def test_api_fail_geo_ip_group_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    jsonpath: str,
    error_msg: str,
    additional_args: dict,
):
    """
    Scenario: Create Geo IP group.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-geo-ip-group-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import geo_ip_group_create_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    args = {
        "name": "check",
        "action": "Alert deny",
        "block_period": "50",
        "severity": "High",
        "ignore_x_forwarded_for": "enable",
    }
    args.update(additional_args)
    with pytest.raises(DemistoException) as error_info:
        geo_ip_group_create_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath", "error_msg", "additional_args"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/GeoIP",
            "geo_ip_group/v1_create_success.json",
            ErrorMessage.IP_ACTION.value,
            {"action": "wrong"},
        ),
        (
            ClientV1.API_VER,
            "WebProtection/Access/GeoIP",
            "geo_ip_group/v1_create_success.json",
            ErrorMessage.SEVERITY.value,
            {"severity": "wrong"},
        ),
        (
            ClientV1.API_VER,
            "WebProtection/Access/GeoIP",
            "geo_ip_group/v1_create_success.json",
            ErrorMessage.IGNORE_X_FORWARDED_FOR.value,
            {"ignore_x_forwarded_for": "wrong"},
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/geo-block-list",
            "geo_ip_group/v2_wrong_parameters.json",
            ErrorMessage.BLOCK_PERIOD.value,
            {"block_period": "-1"},
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/geo-block-list",
            "geo_ip_group/v2_wrong_parameters.json",
            ErrorMessage.BLOCK_PERIOD.value,
            {"block_period": "601"},
        ),
    ),
)
def test_input_fail_geo_ip_group_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    jsonpath: str,
    error_msg: str,
    additional_args: dict,
):
    """
    Scenario: Create Geo IP group.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-geo-ip-group-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import geo_ip_group_create_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    args = {
        "name": "check",
        "action": "Alert deny",
        "block_period": "50",
        "severity": "High",
        "ignore_x_forwarded_for": "enable",
    }
    args.update(additional_args)
    with pytest.raises(ValueError) as error_info:
        geo_ip_group_create_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/GeoIP/check",
            "geo_ip_group/v1_update_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/geo-block-list?mkey=check",
            "geo_ip_group/v2_update_success.json",
        ),
    ),
)
def test_geo_ip_group_update_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
    """
    Scenario: Update Geo IP group.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-geo-ip-group-update called.
    Then:
     - Ensure that Geo IP group updated.
    """
    from FortinetFortiwebVM import geo_ip_group_update_command

    if version == ClientV1.API_VER:
        url = urljoin(mock_client.base_url, "WebProtection/Access/GeoIP")
        get_response = load_mock_response("geo_ip_group/v1_list_success.json")
        requests_mock.get(url=url, json=get_response)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response)
    args = {
        "name": "check",
        "action": "Alert deny",
        "block_period": "50",
        "severity": "High",
        "ignore_x_forwarded_for": "enable",
    }

    result = geo_ip_group_update_command(mock_client, args)
    output = (
        f'{OutputTitle.GEO_IP_GROUP.value} {args["name"]} {OutputTitle.UPDATED.value}'
    )
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/GeoIP/check",
            "geo_ip_group/v1_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/geo-block-list?mkey=check",
            "geo_ip_group/v2_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_fail_geo_ip_group_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Update Geo IP group.
    Given:
     - User has provided exist host.
    When:
     - fortiwebvm-geo-ip-group-update called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import geo_ip_group_update_command

    if version == ClientV1.API_VER:
        url = urljoin(mock_client.base_url, "WebProtection/Access/GeoIP")
        get_response = load_mock_response("geo_ip_group/v1_list_success.json")
        requests_mock.get(url=url, json=get_response)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    args = {
        "name": "check",
        "action": "Alert deny",
        "block_period": "50",
        "severity": "High",
        "ignore_x_forwarded_for": "enable",
    }
    with pytest.raises(DemistoException) as error_info:
        geo_ip_group_update_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/GeoIP/check",
            "geo_ip_group/v1_delete_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/geo-block-list?mkey=check",
            "geo_ip_group/v2_delete_success.json",
        ),
    ),
)
def test_geo_ip_group_delete_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
    """
    Scenario: Delete Geo IP group.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-geo-ip-group-delete called.
    Then:
     - Ensure that Geo IP group deleted.
    """
    from FortinetFortiwebVM import geo_ip_group_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(url=url, json=json_response)
    args = {"name": "check"}
    result = geo_ip_group_delete_command(mock_client, args)
    output = (
        f'{OutputTitle.GEO_IP_GROUP.value} {args["name"]} {OutputTitle.DELETED.value}'
    )
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/GeoIP/check",
            "geo_ip_group/v1_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/geo-block-list?mkey=check",
            "geo_ip_group/v2_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_fail_geo_ip_group_delete_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Delete Geo IP group.
    Given:
     - User has provided exist host.
    When:
     - fortiwebvm-geo-ip-group-delete called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import geo_ip_group_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    args = {"name": "check"}
    with pytest.raises(DemistoException) as error_info:
        geo_ip_group_delete_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath", "expected"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/GeoIP",
            "geo_ip_group/v1_list_success.json",
            3,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/geo-block-list",
            "geo_ip_group/v2_list_success.json",
            3,
        ),
    ),
)
def test_geo_ip_group_list_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    jsonpath: str,
    expected,
):
    """
    Scenario: List an Geo IP groups.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-geo-ip-group-list called.
    Then:
     - Ensure that Geo IP groups listed.
    """
    from FortinetFortiwebVM import geo_ip_group_list_command

    args = {"page": "1", "page_size": 3}
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = geo_ip_group_list_command(mock_client, args)
    if isinstance(result.outputs, list):
        assert len(result.outputs) == expected
    assert result.outputs_prefix == "FortiwebVM.GeoIpGroup"


@pytest.mark.parametrize(
    (
        "version",
        "post_endpoint",
        "get_endpoint",
        "post_jsonpath",
        "get_jsonpath",
        "args",
        "expected_value",
    ),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/GeoIP/ron/AddCountry",
            "WebProtection/Access/GeoIP/ron/AddCountry",
            "geo_ip_member/v1_add_success.json",
            "geo_ip_member/v1_list_success.json",
            {"group_name": "ron", "countries": "Spain"},
            1,
        ),
        (
            ClientV1.API_VER,
            "WebProtection/Access/GeoIP/ron/AddCountry",
            "WebProtection/Access/GeoIP/ron/AddCountry",
            "geo_ip_member/v1_add_success.json",
            "geo_ip_member/v1_list_success.json",
            {"group_name": "ron", "countries": "Spain,France"},
            2,
        ),
        (
            ClientV2.API_VER,
            "waf/geoip.setCountrys?mkey=ron",
            "cmdb/waf/geo-block-list/country-list?mkey=ron",
            "geo_ip_member/v2_add_success.json",
            "geo_ip_member/v2_list_success.json",
            {"group_name": "ron", "countries": "Spain,France"},
            2,
        ),
    ),
)
def test_geo_ip_member_add_command(
    requests_mock,
    mock_client: Client,
    version: str,
    post_endpoint: str,
    get_endpoint: str,
    post_jsonpath: str,
    get_jsonpath: str,
    args: Dict[str, Any],
    expected_value: int,
):
    """
    Scenario: Add a Geo IP member.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-geo-ip-member-add called.
    Then:
     - Ensure that Geo IP member created.
    """
    from FortinetFortiwebVM import geo_ip_member_add_command

    post_json_response = load_mock_response(post_jsonpath)
    get_json_response = load_mock_response(get_jsonpath)
    get_url = urljoin(mock_client.base_url, get_endpoint)
    post_url = urljoin(mock_client.base_url, post_endpoint)
    requests_mock.get(url=get_url, json=get_json_response)
    requests_mock.post(url=post_url, json=post_json_response)
    result = geo_ip_member_add_command(mock_client, args)
    assert OutputTitle.GEO_IP_MEMBER_ADD.value in str(result.readable_output)
    assert result.outputs_prefix == "FortiwebVM.GeoIpMember"
    if isinstance(result.outputs, list):
        assert len(result.outputs) == expected_value


@pytest.mark.parametrize(
    (
        "version",
        "post_endpoint",
        "get_endpoint",
        "post_jsonpath",
        "get_jsonpath",
        "error_msg",
    ),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/GeoIP/ron/AddCountry",
            "WebProtection/Access/GeoIP/ron/AddCountry",
            "geo_ip_member/v1_not_exist.json",
            "geo_ip_member/v1_list_success.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "waf/geoip.setCountrys?mkey=ron",
            "cmdb/waf/geo-block-list/country-list?mkey=ron",
            "geo_ip_member/v2_not_exist.json",
            "geo_ip_member/v2_list_success.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_api_fail_geo_ip_member_add_command(
    requests_mock,
    mock_client: Client,
    version: str,
    post_endpoint: str,
    get_endpoint: str,
    post_jsonpath: str,
    get_jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Add a Geo IP member.
    Given:
     - User has provided exist host.
    When:
     - fortiwebvm-geo-ip-member-add called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import geo_ip_member_add_command

    post_json_response = load_mock_response(post_jsonpath)
    get_json_response = load_mock_response(get_jsonpath)
    post_url = urljoin(mock_client.base_url, post_endpoint)
    get_url = urljoin(mock_client.base_url, get_endpoint)
    requests_mock.get(url=get_url, json=get_json_response)
    requests_mock.post(
        url=post_url,
        json=post_json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    args = {"group_name": "ron", "countries": "Spain,France"}
    with pytest.raises(DemistoException) as error_info:
        geo_ip_member_add_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/GeoIP/ron/AddCountry/1",
            "ip_list_member/v1_delete_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/geo-block-list/country-list?mkey=ron&sub_mkey=1",
            "geo_ip_member/v2_delete_success.json",
        ),
    ),
)
def test_geo_ip_member_delete_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
    """
    Scenario: Delete a Geo IP member.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-geo-ip-member-delete called.
    Then:
     - Ensure that protected hostname created.
    """
    from FortinetFortiwebVM import geo_ip_member_delete_command

    args = {"group_name": "ron", "member_id": 1}
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(url=url, json=json_response)
    result = geo_ip_member_delete_command(mock_client, args)
    output = f"{OutputTitle.GEO_IP_MEMBER.value} 1 {OutputTitle.DELETED.value}"
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/GeoIP/ron/AddCountry/1",
            "geo_ip_member/v1_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/geo-block-list/country-list?mkey=ron&sub_mkey=1",
            "geo_ip_member/v2_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_fail_geo_ip_member_delete_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Delete a Geo IP member.
    Given:
     - User has provided not exist host.
    When:
     - fortiwebvm-geo-ip-member-delete called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import geo_ip_member_delete_command

    args = {"group_name": "ron", "member_id": 1}
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(DemistoException) as error_info:
        geo_ip_member_delete_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "args", "endpoint", "jsonpath", "expected"),
    (
        (
            ClientV1.API_VER,
            {"group_name": "ron", "limit": 1},
            "WebProtection/Access/GeoIP/ron/AddCountry",
            "geo_ip_member/v1_list_success.json",
            1,
        ),
        (
            ClientV1.API_VER,
            {"group_name": "ron", "page": 1, "page_size": 2},
            "WebProtection/Access/GeoIP/ron/AddCountry",
            "geo_ip_member/v1_list_success.json",
            2,
        ),
        (
            ClientV2.API_VER,
            {"group_name": "ron", "limit": 1},
            "cmdb/waf/geo-block-list/country-list?mkey=ron",
            "geo_ip_member/v2_list_success.json",
            1,
        ),
        (
            ClientV2.API_VER,
            {"group_name": "ron", "page": 1, "page_size": 2},
            "cmdb/waf/geo-block-list/country-list?mkey=ron",
            "geo_ip_member/v2_list_success.json",
            2,
        ),
    ),
)
def test_geo_ip_member_list_command(
    requests_mock,
    mock_client: Client,
    version: str,
    args,
    endpoint,
    jsonpath: str,
    expected,
):
    """
    Scenario: List the Geo IP members.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-geo-ip-member-list called.
    Then:
     - Ensure that Geo IP members listed.
    """
    from FortinetFortiwebVM import geo_ip_member_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = geo_ip_member_list_command(mock_client, args)
    if isinstance(result.outputs, dict) and isinstance(
        result.outputs["countries"], list
    ):
        assert len(result.outputs["countries"]) == expected
    assert result.outputs_prefix == "FortiwebVM.GeoIpMember"


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "System/Status/StatusOperation",
            "system_status/v1_operation_status.json",
        ),
        (
            ClientV2.API_VER,
            "system/status.systemoperation",
            "system_status/v2_operation_status.json",
        ),
    ),
)
def test_operation_status_get_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
    """
    Scenario: Get operation status.
    When:
     - fortiwebvm-system-operation-status-get.
    Then:
     - Ensure that the output is correct.
    """

    from FortinetFortiwebVM import operation_status_get_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = operation_status_get_command(mock_client, {})
    assert result.outputs_prefix == "FortiwebVM.SystemOperation"


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "System/Status/PolicyStatus",
            "system_status/v1_policy_status.json",
        ),
        (
            ClientV2.API_VER,
            "policy/policystatus",
            "system_status/v2_policy_status.json",
        ),
    ),
)
def test_policy_status_get_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
    """
    Scenario: Get policy status.
    When:
     - fortiwebvm-system-policy-status-get.
    Then:
     - Ensure that the output is correct.
    """
    from FortinetFortiwebVM import policy_status_get_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = policy_status_get_command(mock_client, {})
    assert result.outputs_prefix == "FortiwebVM.SystemPolicy"


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "System/Status/Status",
            "system_status/v1_system_status.json",
        ),
        (
            ClientV2.API_VER,
            "system/status.systemstatus",
            "system_status/v2_system_status.json",
        ),
    ),
)
def test_system_status_get_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
    """
    Scenario: Get system status.
    When:
     - fortiwebvm-system-status-get.
    Then:
     - Ensure that the output is correct.
    """
    from FortinetFortiwebVM import system_status_get_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = system_status_get_command(mock_client, {})
    assert result.outputs_prefix == "FortiwebVM.SystemStatus"


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Server/ServerPool",
            "policy_dependencies/v1_server_pool.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/server-pool",
            "policy_dependencies/v2_server_pool.json",
        ),
    ),
)
def test_server_pool_list_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
    """
    Scenario: List the server pools.
    When:
     - fortiwebvm-server-pool-list.
    Then:
     - Ensure that the output is correct.
    """
    from FortinetFortiwebVM import server_pool_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = server_pool_list_command(mock_client, {})
    assert result.outputs_prefix == "FortiwebVM.ServerPool"


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Service/HttpServiceList",
            "policy_dependencies/v1_http_service_list.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/service.predefined",
            "policy_dependencies/v2_http_service_list.json",
        ),
    ),
)
def test_http_service_list_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
    """
    Scenario: List the HTTP services.
    When:
     - fortiwebvm-http-service-list-get.
    Then:
     - Ensure that the output is correct.
    """
    from FortinetFortiwebVM import http_service_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = http_service_list_command(mock_client, {})
    assert result.outputs_prefix == "FortiwebVM.HttpServiceList"


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "Policy/WebProtectionProfile/InlineProtectionProfile",
            "policy_dependencies/v1_inline_protection_profile.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/web-protection-profile.inline-protection",
            "policy_dependencies/v2_inline_protection_profile.json",
        ),
    ),
)
def test_inline_protection_profile_list_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
    """
    Scenario: List the Inline protection profiles.
    When:
     - fortiwebvm-inline-protection-profile-list   .
    Then:
     - Ensure that the output is correct.
    """
    from FortinetFortiwebVM import inline_protection_profile_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = inline_protection_profile_list_command(mock_client, {})
    assert result.outputs_prefix == "FortiwebVM.InlineProtectionProfile"


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Server/VirtualServer",
            "policy_dependencies/v1_virtual_server.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/vserver",
            "policy_dependencies/v2_virtual_server.json",
        ),
    ),
)
def test_virtual_server_list_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
    """
    Scenario: List the virtual servers.
    When:
     - fortiwebvm-virtual-server-list.
    Then:
     - Ensure that the output is correct.
    """
    from FortinetFortiwebVM import virtual_server_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = virtual_server_list_command(mock_client, {})
    assert result.outputs_prefix == "FortiwebVM.VirtualServer"


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Server/HTTPContentRoutingPolicy",
            "policy_dependencies/v1_http_content_routing_policy.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/http-content-routing-policy",
            "policy_dependencies/v2_http_content_routing_policy.json",
        ),
    ),
)
def test_http_content_routing_policy_list_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
    """
    Scenario: List the HTTP content routing policies..
    When:
     - fortiwebvm-http-content-routing-member-list.
    Then:
     - Ensure that the output is correct.
    """
    from FortinetFortiwebVM import http_content_routing_policy_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = http_content_routing_policy_list_command(mock_client, {})
    assert result.outputs_prefix == "FortiwebVM.HttpContentRoutingPolicy"


@pytest.mark.parametrize(
    (
        "version",
        "endpoint",
        "args",
        "jsonpath",
        "expected_value",
        "status_code",
        "assert_flag",
    ),
    (
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy",
            {
                "name": "check",
                "deployment_mode": "HTTP Content Routing",
                "server_pool": "server1",
                "virtual_server": "virtual1",
                "http_service": "HTTP",
            },
            "server_policy/v1_create_success.json",
            "check",
            HTTPStatus.OK,
            False,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy",
            {
                "name": "check",
                "deployment_mode": "HTTP Content Routing",
                "server_pool": "server1",
                "virtual_server": "virtual1",
                "http_service": "HTTP",
            },
            "server_policy/v2_create_success.json",
            "check",
            HTTPStatus.OK,
            False,
        ),
    ),
)
def test_server_policy_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    expected_value: str,
    status_code: HTTPStatus,
    assert_flag: bool,
):
    """
    Scenario: Create a new server policy.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-server-policy-create called.
    Then:
     - Ensure that server policy created.
    """
    from FortinetFortiwebVM import server_policy_create_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response)
    result = server_policy_create_command(mock_client, args)
    output = (
        f'{OutputTitle.SERVER_POLICY.value} {args["name"]} {OutputTitle.CREATED.value}'
    )
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy",
            {
                "name": "check",
                "deployment_mode": "HTTP Content Routing",
                "server_pool": "server1",
                "virtual_server": "virtual1",
                "http_service": "HTTP",
            },
            "server_policy/v1_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
        ),
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy",
            {
                "name": "check",
                "deployment_mode": "HTTP Content Routing",
                "server_pool": "server1",
                "virtual_server": "virtual1",
                "http_service": "HTTP",
            },
            "server_policy/v1_wrong_parameters.json",
            ErrorMessage.ARGUMENTS.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy",
            {
                "name": "check",
                "deployment_mode": "HTTP Content Routing",
                "server_pool": "server1",
                "virtual_server": "virtual1",
                "http_service": "HTTP",
            },
            "server_policy/v2_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy",
            {
                "name": "check",
                "deployment_mode": "HTTP Content Routing",
                "server_pool": "server1",
                "virtual_server": "virtual1",
                "http_service": "HTTP",
            },
            "server_policy/v2_wrong_parameters.json",
            ErrorMessage.ARGUMENTS.value,
        ),
    ),
)
def test_fail_server_policy_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create a new server policy.
    Given:
     - User has provided wrong parameters.
     - User has provided exist name.
    When:
     - fortiwebvm-server-policy-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import server_policy_create_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )

    with pytest.raises(DemistoException) as error_info:
        server_policy_create_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy",
            {
                "name": "check",
                "deployment_mode": "HTTP Content Routing",
                "server_pool": "server1",
                "virtual_server": "virtual1",
            },
            "server_policy/v1_create_success.json",
            ErrorMessage.PROTOCOL.value,
        ),
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy",
            {
                "name": "check",
                "deployment_mode": "wrong",
                "server_pool": "server1",
                "virtual_server": "virtual1",
                "http_service": "HTTP",
            },
            "server_policy/v1_exist.json",
            ErrorMessage.DEPLOYMENT_MODE.value,
        ),
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy",
            {
                "name": "check",
                "deployment_mode": "Single Server/Server Balance",
                "virtual_server": "virtual1",
                "http_service": "HTTP",
            },
            "server_policy/v1_exist.json",
            ErrorMessage.SERVER_POOL.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy",
            {
                "name": "check",
                "deployment_mode": "HTTP Content Routing",
                "server_pool": "server1",
                "virtual_server": "virtual1",
                "http_service": "HTTP",
                "scripting": "wrong",
            },
            "server_policy/v2_exist.json",
            ErrorMessage.SCRIPTING.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy",
            {
                "name": "check",
                "deployment_mode": "HTTP Content Routing",
                "server_pool": "server1",
                "virtual_server": "virtual1",
                "http_service": "HTTP",
                "client_real_ip": "wrong",
            },
            "server_policy/v2_exist.json",
            ErrorMessage.CLIENT_REAL_IP.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy",
            {
                "name": "check",
                "deployment_mode": "HTTP Content Routing",
                "server_pool": "server1",
                "virtual_server": "virtual1",
                "http_service": "HTTP",
                "match_once": "wrong",
            },
            "server_policy/v2_exist.json",
            ErrorMessage.MATCH_ONCE.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy",
            {
                "name": "check",
                "deployment_mode": "HTTP Content Routing",
                "server_pool": "server1",
                "virtual_server": "virtual1",
                "http_service": "HTTP",
                "monitor_mode": "wrong",
            },
            "server_policy/v2_exist.json",
            ErrorMessage.MONITOR_MODE.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy",
            {
                "name": "check",
                "deployment_mode": "HTTP Content Routing",
                "server_pool": "server1",
                "virtual_server": "virtual1",
                "http_service": "HTTP",
                "scripting": "enable",
            },
            "server_policy/v2_exist.json",
            ErrorMessage.SCRIPTING_LIST.value,
        ),
    ),
)
def test_input_fail_server_policy_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create a new server policy.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-server-policy-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import server_policy_create_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )

    with pytest.raises(ValueError) as error_info:
        server_policy_create_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "expected_value"),
    (
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy/123456789",
            {
                "name": "123456789",
                "deployment_mode": "HTTP Content Routing",
                "server_pool": "server1",
                "virtual_server": "virtual1",
                "http_service": "HTTP",
            },
            "server_policy/v1_create_success.json",
            "123456789",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy?mkey=123456789",
            {
                "name": "123456789",
                "deployment_mode": "HTTP Content Routing",
                "server_pool": "server1",
                "virtual_server": "virtual1",
                "http_service": "HTTP",
            },
            "server_policy/v2_create_success.json",
            "123456789",
        ),
    ),
)
def test_server_policy_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    expected_value: str,
):
    """
    Scenario: Update a new server policy.
    Given:
     - User has provided correct parameters.
     - User has provided exist name.
    When:
     - fortiwebvm-server-policy-update called.
    Then:
     - Ensure that server policy updated.
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import server_policy_update_command

    get_endpoint = (
        "Policy/ServerPolicy/ServerPolicy"
        if version == ClientV1.API_VER
        else "cmdb/server-policy/policy"
    )
    get_jsonpath = (
        "server_policy/v1_list_success.json"
        if version == ClientV1.API_VER
        else "server_policy/v2_list_success.json"
    )
    url = urljoin(mock_client.base_url, get_endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response)

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response)
    result = server_policy_update_command(mock_client, args)
    output = (
        f'{OutputTitle.SERVER_POLICY.value} {args["name"]} {OutputTitle.UPDATED.value}'
    )
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy/123456789",
            {
                "name": "123456789",
                "deployment_mode": "HTTP Content Routing",
                "server_pool": "server1",
                "virtual_server": "virtual1",
                "http_service": "HTTP",
            },
            "server_policy/v1_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy?mkey=123456789",
            {
                "name": "123456789",
                "deployment_mode": "HTTP Content Routing",
                "server_pool": "server1",
                "virtual_server": "virtual1",
                "http_service": "HTTP",
            },
            "server_policy/v2_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_api_fail_server_policy_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Update a new server policy.
    Given:
     - User has provided exist name.
    When:
     - fortiwebvm-server-policy-update called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import server_policy_update_command

    get_endpoint = (
        "Policy/ServerPolicy/ServerPolicy"
        if version == ClientV1.API_VER
        else "cmdb/server-policy/policy"
    )
    get_jsonpath = (
        "server_policy/v1_list_success.json"
        if version == ClientV1.API_VER
        else "server_policy/v2_list_success.json"
    )
    url = urljoin(mock_client.base_url, get_endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response, status_code=HTTPStatus.OK)

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )

    with pytest.raises(DemistoException) as error_info:
        server_policy_update_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy/check",
            "server_policy/v1_delete_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy?mkey=check",
            "server_policy/v2_delete_success.json",
        ),
    ),
)
def test_server_policy_delete_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
    """
    Scenario: Delete a server policy.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-server-policy-delete called.
    Then:
     - Ensure that server policy deleted.
    """
    from FortinetFortiwebVM import server_policy_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(url=url, json=json_response)
    args = {"name": "check"}

    result = server_policy_delete_command(mock_client, args)
    output = (
        f'{OutputTitle.SERVER_POLICY.value} {args["name"]} {OutputTitle.DELETED.value}'
    )
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy/check",
            "server_policy/v1_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy?mkey=check",
            "server_policy/v2_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_fail_server_policy_delete_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Delete a server policy.
    Given:
     - User has provided not exist name.
    When:
     - fortiwebvm-server-policy-delete called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import server_policy_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    args = {"name": "check"}

    with pytest.raises(DemistoException) as error_info:
        server_policy_delete_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath", "expected"),
    (
        (
            ClientV1.API_VER,
            "Policy/ServerPolicy/ServerPolicy",
            "server_policy/v1_list_success.json",
            2,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/policy",
            "server_policy/v2_list_success.json",
            2,
        ),
    ),
)
def test_server_policy_list_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    jsonpath: str,
    expected,
):
    """
    Scenario: List server policies.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-server-policy-list called.
    Then:
     - Ensure that server policy listed.
    """
    from FortinetFortiwebVM import server_policy_list_command

    args = {"page": "1", "page_size": 2}
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = server_policy_list_command(mock_client, args)
    if isinstance(result.outputs, list):
        assert len(result.outputs) == expected
    assert result.outputs_prefix == "FortiwebVM.ServerPolicy"


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList",
            {
                "request_url": "/123",
                "request_type": "Simple String",
                "status": "disable",
            },
            "custom_whitelist/v1_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group",
            {
                "request_url": "/123",
                "request_type": "Simple String",
                "status": "disable",
            },
            "custom_whitelist/v2_url_create_success.json",
        ),
    ),
)
def test_custom_whitelist_url_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Create a custom whitelist url member.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-custom-whitelist-url-create called.
    Then:
     - Ensure that custom whitelist url member created.
    """
    from FortinetFortiwebVM import custom_whitelist_url_create_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    url = urljoin(mock_client.base_url, endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response, status_code=HTTPStatus.OK)

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response)
    result = custom_whitelist_url_create_command(mock_client, args)
    assert result.outputs_prefix == "FortiwebVM.CustomGlobalWhitelist"


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList",
            {
                "request_url": "/123",
                "request_type": "Simple String",
            },
            "custom_whitelist/v1_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group",
            {
                "request_url": "/123",
                "request_type": "Simple String",
            },
            "custom_whitelist/v2_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
        ),
    ),
)
def test_api_fail_custom_whitelist_url_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create a custom whitelist url member.
    Given:
     - User has provided exist name.
    When:
     - fortiwebvm-custom-whitelist-url-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import custom_whitelist_url_create_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    url = urljoin(mock_client.base_url, endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response, status_code=HTTPStatus.OK)

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )

    with pytest.raises(DemistoException) as error_info:
        custom_whitelist_url_create_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList",
            {
                "request_url": "123",
                "request_type": "Simple String",
            },
            "custom_whitelist/v1_exist.json",
            ErrorMessage.REQUEST_URL.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group",
            {
                "request_url": "123",
                "request_type": "Simple String",
            },
            "custom_whitelist/v2_exist.json",
            ErrorMessage.REQUEST_URL.value,
        ),
    ),
)
def test_input_fail_custom_whitelist_url_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create a custom whitelist url member.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-custom-whitelist-url-create called.
    Then:
     - Ensure that custom whitelist url member created.
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import custom_whitelist_url_create_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    url = urljoin(mock_client.base_url, endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response, status_code=HTTPStatus.OK)

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )

    with pytest.raises(ValueError) as error_info:
        custom_whitelist_url_create_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList",
            {"name": "ron", "request_type": "Simple String", "status": "disable"},
            "custom_whitelist/v1_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group",
            {"name": "ron", "request_type": "Simple String", "status": "disable"},
            "custom_whitelist/v2_parameter_create_success.json",
        ),
    ),
)
def test_custom_whitelist_parameter_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Create a custom whitelist parameter member.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-custom-whitelist-parameter-create called.
    Then:
     - Ensure that custom whitelist parameter member created.
    """
    from FortinetFortiwebVM import custom_whitelist_parameter_create_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    url = urljoin(mock_client.base_url, endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response)

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response)
    result = custom_whitelist_parameter_create_command(mock_client, args)
    assert result.outputs_prefix == "FortiwebVM.CustomGlobalWhitelist"


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList",
            {"name": "ron", "request_type": "Simple String", "status": "disable"},
            "custom_whitelist/v1_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
        ),
    ),
)
def test_api_fail_custom_whitelist_parameter_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create a custom whitelist parameter member.
    Given:
     - User has provided exist name.
    When:
     - fortiwebvm-custom-whitelist-parameter-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import custom_whitelist_parameter_create_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    url = urljoin(mock_client.base_url, endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response, status_code=HTTPStatus.OK)

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(DemistoException) as error_info:
        custom_whitelist_parameter_create_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group",
            {
                "name": "ron",
                "request_type": "Simple String",
                "request_url_status": "enable",
                "status": "disable",
            },
            "custom_whitelist/v2_exist.json",
            ErrorMessage.REQUEST_URL_INSERT.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group",
            {
                "name": "ron",
                "request_type": "Simple String",
                "request_url_status": "enable",
                "request_url": "/asds",
                "domain_status": "enable",
                "status": "disable",
            },
            "custom_whitelist/v2_exist.json",
            ErrorMessage.DOMAIN_INSERT.value,
        ),
    ),
)
def test_input_fail_custom_whitelist_parameter_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create a custom whitelist parameter member.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-custom-whitelist-parameter-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import custom_whitelist_parameter_create_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    url = urljoin(mock_client.base_url, endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response, status_code=HTTPStatus.OK)

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(ValueError) as error_info:
        custom_whitelist_parameter_create_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList",
            {"name": "ron", "status": "disable"},
            "custom_whitelist/v1_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group",
            {"name": "ron", "status": "disable"},
            "custom_whitelist/v2_cookie_create_success.json",
        ),
    ),
)
def test_custom_whitelist_cookie_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Create a custom whitelist cookie member.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-custom-whitelist-cookie-create called.
    Then:
     - Ensure that custom whitelist cookie member created.
    """
    from FortinetFortiwebVM import custom_whitelist_cookie_create_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    url = urljoin(mock_client.base_url, endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response)

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response)
    result = custom_whitelist_cookie_create_command(mock_client, args)
    assert result.outputs_prefix == "FortiwebVM.CustomGlobalWhitelist"


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList",
            {"name": "ron", "domain": "do1", "path": "/abc"},
            "custom_whitelist/v1_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group",
            {"name": "ron", "domain": "do1", "path": "/abc"},
            "custom_whitelist/v2_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
        ),
    ),
)
def test_api_fail_custom_whitelist_cookie_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create a custom whitelist cookie member.
    Given:
     - User has provided exist name.
    When:
     - fortiwebvm-custom-whitelist-cookie-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import custom_whitelist_cookie_create_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    url = urljoin(mock_client.base_url, endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response, status_code=HTTPStatus.OK)

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )

    with pytest.raises(DemistoException) as error_info:
        custom_whitelist_cookie_create_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group",
            {"name": "ron", "status": "disable", "header_name_type": "Simple String"},
            "custom_whitelist/v2_parameter_create_success.json",
        ),
    ),
)
def test_custom_whitelist_header_field_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Create a custom whitelist header field member.
    Given:
     - User has provided correct parameters.
     - User has provided exist name.
    When:
     - fortiwebvm-custom-whitelist-header-field-create called.
    Then:
     - Ensure that custom whitelist header field member created.
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import custom_whitelist_header_field_create_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    url = urljoin(mock_client.base_url, endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response)

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response)
    result = custom_whitelist_header_field_create_command(mock_client, args)
    assert result.outputs_prefix == "FortiwebVM.CustomGlobalWhitelist"


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group",
            {"name": "ron", "status": "disable", "header_name_type": "Simple String"},
            "custom_whitelist/v2_exist.json",
            ErrorMessage.ALREADY_EXIST.value,
        ),
    ),
)
def test_api_fail_custom_whitelist_header_field_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create a custom whitelist header field member.
    Given:
     - User has provided exist name.
    When:
     - fortiwebvm-custom-whitelist-header-field-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import custom_whitelist_header_field_create_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    url = urljoin(mock_client.base_url, endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response)

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(DemistoException) as error_info:
        custom_whitelist_header_field_create_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList",
            {"name": "ron", "status": "disable", "header_name_type": "Simple String"},
            "custom_whitelist/v1_wrong_parameters.json",
            ErrorMessage.V1_NOT_SUPPORTED.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group",
            {
                "name": "ron",
                "status": "disable",
                "header_name_type": "Simple String",
                "value_status": "enable",
            },
            "custom_whitelist/v2_wrong_parameters.json",
            ErrorMessage.VALUE_INSERT.value,
        ),
    ),
)
def test_input_fail_custom_whitelist_header_field_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create a custom whitelist header field member.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-custom-whitelist-header-field-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import custom_whitelist_header_field_create_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    url = urljoin(mock_client.base_url, endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response)

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(ValueError) as error_info:
        custom_whitelist_header_field_create_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList/3",
            {
                "id": "3",
                "request_url": "/123",
                "request_type": "Simple String",
                "status": "disable",
            },
            "custom_whitelist/v1_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group?mkey=1",
            {
                "id": "1",
                "request_url": "/123",
                "request_type": "Simple String",
                "status": "disable",
            },
            "custom_whitelist/v2_url_update_success.json",
        ),
    ),
)
def test_custom_whitelist_url_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Create a custom whitelist url member.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-custom-whitelist-url-update called.
    Then:
     - Ensure that custom whitelist url member updated.
    """
    from FortinetFortiwebVM import custom_whitelist_url_update_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    get_endpoint = (
        "ServerObjects/Global/CustomGlobalWhiteList"
        if version == ClientV1.API_VER
        else "cmdb/server-policy/pattern.custom-global-white-list-group"
    )
    url = urljoin(mock_client.base_url, get_endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response, status_code=HTTPStatus.OK)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response)
    result = custom_whitelist_url_update_command(mock_client, args)
    output = f'{OutputTitle.CUSTOM_WHITELIST_URL.value} {args["id"]} {OutputTitle.UPDATED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList/3",
            {
                "id": "3",
                "request_url": "/123",
                "request_type": "Simple String",
                "status": "disable",
            },
            "custom_whitelist/v1_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group?mkey=77",
            {
                "id": "77",
                "request_url": "/123",
                "request_type": "Simple String",
                "status": "disable",
            },
            "custom_whitelist/v2_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_api_fail_custom_whitelist_url_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create a custom whitelist url member.
    Given:
     - User has provided not exist name.
    When:
     - fortiwebvm-custom-whitelist-url-update called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import custom_whitelist_url_update_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    get_endpoint = (
        "ServerObjects/Global/CustomGlobalWhiteList"
        if version == ClientV1.API_VER
        else "cmdb/server-policy/pattern.custom-global-white-list-group"
    )
    url = urljoin(mock_client.base_url, get_endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response, status_code=HTTPStatus.OK)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(DemistoException) as error_info:
        custom_whitelist_url_update_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList/6",
            {
                "id": "6",
                "request_url": "/123",
                "request_type": "Simple String",
                "status": "disable",
            },
            "custom_whitelist/v1_not_exist.json",
            "You can't update Parameter member with URL update command.",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group?mkey=6",
            {
                "id": "2",
                "request_url": "/123",
                "request_type": "Simple String",
                "status": "disable",
            },
            "custom_whitelist/v2_not_exist.json",
            "You can't update Parameter member with URL update command.",
        ),
    ),
)
def test_input_fail_custom_whitelist_url_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create a custom whitelist url member.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-custom-whitelist-url-update called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import custom_whitelist_url_update_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    get_endpoint = (
        "ServerObjects/Global/CustomGlobalWhiteList"
        if version == ClientV1.API_VER
        else "cmdb/server-policy/pattern.custom-global-white-list-group"
    )
    url = urljoin(mock_client.base_url, get_endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response, status_code=HTTPStatus.OK)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(ValueError) as error_info:
        custom_whitelist_url_update_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    (
        "version",
        "endpoint",
        "args",
        "jsonpath",
    ),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList/6",
            {
                "id": "6",
                "name": "sdfs",
            },
            "custom_whitelist/v1_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group?mkey=2",
            {
                "id": "2",
                "name": "sdfs",
            },
            "custom_whitelist/v2_parameter_update_success.json",
        ),
    ),
)
def test_custom_whitelist_parameter_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Update a custom whitelist parameter member.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-custom-whitelist-parameter-update called.
    Then:
     - Ensure that custom whitelist parameter member updated.
    """
    from FortinetFortiwebVM import custom_whitelist_parameter_update_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    get_endpoint = (
        "ServerObjects/Global/CustomGlobalWhiteList"
        if version == ClientV1.API_VER
        else "cmdb/server-policy/pattern.custom-global-white-list-group"
    )
    url = urljoin(mock_client.base_url, get_endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response)
    result = custom_whitelist_parameter_update_command(mock_client, args)
    output = f'{OutputTitle.CUSTOM_WHITELIST_PARAMETER.value} {args["id"]} {OutputTitle.UPDATED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList/6",
            {
                "id": "6",
                "name": "sdfs",
            },
            "custom_whitelist/v1_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group?mkey=2",
            {
                "id": "2",
                "name": "sdfs",
            },
            "custom_whitelist/v2_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_fail_custom_whitelist_parameter_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Update a custom whitelist parameter member.
    Given:
     - User has provided not exist name.
    When:
     - fortiwebvm-custom-whitelist-parameter-update called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import custom_whitelist_parameter_update_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    get_endpoint = (
        "ServerObjects/Global/CustomGlobalWhiteList"
        if version == ClientV1.API_VER
        else "cmdb/server-policy/pattern.custom-global-white-list-group"
    )
    url = urljoin(mock_client.base_url, get_endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(DemistoException) as error_info:
        custom_whitelist_parameter_update_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList/3",
            {
                "id": "3",
                "name": "sdfs",
            },
            "custom_whitelist/v1_not_exist.json",
            "You can't update URL member with Parameter update command.",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group?mkey=1",
            {
                "id": "1",
                "name": "sdfs",
            },
            "custom_whitelist/v2_not_exist.json",
            "You can't update URL member with Parameter update command.",
        ),
    ),
)
def test_input_fail_custom_whitelist_parameter_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Update a custom whitelist parameter member.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-custom-whitelist-parameter-update called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import custom_whitelist_parameter_update_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    get_endpoint = (
        "ServerObjects/Global/CustomGlobalWhiteList"
        if version == ClientV1.API_VER
        else "cmdb/server-policy/pattern.custom-global-white-list-group"
    )
    url = urljoin(mock_client.base_url, get_endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(ValueError) as error_info:
        custom_whitelist_parameter_update_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList/7",
            {
                "id": "7",
                "name": "sdfs",
            },
            "custom_whitelist/v1_success.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group?mkey=3",
            {
                "id": "3",
                "name": "sdfs",
            },
            "custom_whitelist/v2_cookie_update_success.json",
        ),
    ),
)
def test_custom_whitelist_cookie_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Create a custom whitelist cookie member.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-custom-whitelist-cookie-update called.
    Then:
     - Ensure that custom whitelist cookie member updated.
    """
    from FortinetFortiwebVM import custom_whitelist_cookie_update_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    get_endpoint = (
        "ServerObjects/Global/CustomGlobalWhiteList"
        if version == ClientV1.API_VER
        else "cmdb/server-policy/pattern.custom-global-white-list-group"
    )
    url = urljoin(mock_client.base_url, get_endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response, status_code=HTTPStatus.OK)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response)
    result = custom_whitelist_cookie_update_command(mock_client, args)
    output = f'{OutputTitle.CUSTOM_WHITELIST_COOKIE.value} {args["id"]} {OutputTitle.UPDATED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList/7",
            {
                "id": "7",
                "name": "sdfs",
            },
            "custom_whitelist/v1_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group?mkey=3",
            {
                "id": "3",
                "name": "sdfs",
            },
            "custom_whitelist/v2_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_api_fail_custom_whitelist_cookie_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create a custom whitelist cookie member.
    Given:
     - User has provided not exist name.
    When:
     - fortiwebvm-custom-whitelist-cookie-update called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import custom_whitelist_cookie_update_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    get_endpoint = (
        "ServerObjects/Global/CustomGlobalWhiteList"
        if version == ClientV1.API_VER
        else "cmdb/server-policy/pattern.custom-global-white-list-group"
    )
    url = urljoin(mock_client.base_url, get_endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )

    with pytest.raises(DemistoException) as error_info:
        custom_whitelist_cookie_update_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList/3",
            {
                "id": "3",
                "name": "sdfs",
            },
            "custom_whitelist/v1_not_exist.json",
            "You can't update URL member with Cookie update command.",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group?mkey=2",
            {
                "id": "2",
                "name": "sdfs",
            },
            "custom_whitelist/v2_not_exist.json",
            "You can't update Parameter member with Cookie update command.",
        ),
    ),
)
def test_input_fail_custom_whitelist_cookie_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Create a custom whitelist cookie member.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-custom-whitelist-cookie-update called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import custom_whitelist_cookie_update_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    get_endpoint = (
        "ServerObjects/Global/CustomGlobalWhiteList"
        if version == ClientV1.API_VER
        else "cmdb/server-policy/pattern.custom-global-white-list-group"
    )
    url = urljoin(mock_client.base_url, get_endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )

    with pytest.raises(ValueError) as error_info:
        custom_whitelist_cookie_update_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group?mkey=4",
            {
                "id": "4",
                "name": "sdfs",
            },
            "custom_whitelist/v2_header_field_update_success.json",
        ),
    ),
)
def test_custom_whitelist_header_field_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Update a custom whitelist header-field member.
    Given:
     - User has provided correct header_fields.
    When:
     - fortiwebvm-custom-whitelist-header-field-update called.
    Then:
     - Ensure that custom whitelist header field member updated.
    """
    from FortinetFortiwebVM import custom_whitelist_header_field_update_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    get_endpoint = (
        "ServerObjects/Global/CustomGlobalWhiteList"
        if version == ClientV1.API_VER
        else "cmdb/server-policy/pattern.custom-global-white-list-group"
    )
    url = urljoin(mock_client.base_url, get_endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response)
    result = custom_whitelist_header_field_update_command(mock_client, args)
    output = f'{OutputTitle.CUSTOM_WHITELIST_HEADER_FIELD.value} {args["id"]} {OutputTitle.UPDATED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group?mkey=4",
            {
                "id": "4",
                "name": "sdfs",
            },
            "custom_whitelist/v2_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_fail_custom_whitelist_header_field_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Update a custom whitelist header-field member.
    Given:
     - User has provided not exist name.
    When:
     - fortiwebvm-custom-whitelist-header-field-update called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import custom_whitelist_header_field_update_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    get_endpoint = (
        "ServerObjects/Global/CustomGlobalWhiteList"
        if version == ClientV1.API_VER
        else "cmdb/server-policy/pattern.custom-global-white-list-group"
    )
    url = urljoin(mock_client.base_url, get_endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response, status_code=HTTPStatus.OK)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )

    with pytest.raises(DemistoException) as error_info:
        custom_whitelist_header_field_update_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList/7",
            {
                "id": "7",
                "name": "sdfs",
            },
            "custom_whitelist/v1_success.json",
            ErrorMessage.V1_NOT_SUPPORTED.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group?mkey=4",
            {
                "id": "4",
                "name": "sdfs",
                "value_status": "enable",
            },
            "custom_whitelist/v2_header_field_update_success.json",
            "Please insert value.",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group?mkey=2",
            {
                "id": "2",
                "name": "sdfs",
            },
            "custom_whitelist/v2_not_exist.json",
            "You can't update Parameter member with Header Field update command.",
        ),
    ),
)
def test_input_fail_custom_whitelist_header_field_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Update a custom whitelist header-field member.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-custom-whitelist-header-field-update called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import custom_whitelist_header_field_update_command

    get_jsonpath = (
        "custom_whitelist/v1_list.json"
        if version == ClientV1.API_VER
        else "custom_whitelist/v2_list.json"
    )
    get_endpoint = (
        "ServerObjects/Global/CustomGlobalWhiteList"
        if version == ClientV1.API_VER
        else "cmdb/server-policy/pattern.custom-global-white-list-group"
    )
    url = urljoin(mock_client.base_url, get_endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response, status_code=HTTPStatus.OK)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )

    with pytest.raises(ValueError) as error_info:
        custom_whitelist_header_field_update_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList/1",
            "custom_whitelist/v1_delete.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group?mkey=1",
            "custom_whitelist/v2_delete.json",
        ),
    ),
)
def test_custom_whitelist_delete_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
    """
    Scenario: Delete a custom whitelist member.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-server-policy-delete called.
    Then:
     - Ensure that server policy deleted.
    """
    from FortinetFortiwebVM import custom_whitelist_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(url=url, json=json_response)
    args = {"id": "1"}

    result = custom_whitelist_delete_command(mock_client, args)
    output = f'{OutputTitle.CUSTOM_WHITELIST_MEMBER.value} {args["id"]} {OutputTitle.DELETED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList/1",
            "custom_whitelist/v1_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group?mkey=1",
            "custom_whitelist/v2_not_exist.json",
            ErrorMessage.NOT_EXIST.value,
        ),
    ),
)
def test_fail_custom_whitelist_delete_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    jsonpath: str,
    error_msg: str,
):
    """
    Scenario: Delete a server policy.
    Given:
     - User has provided not exist name.
    When:
     - fortiwebvm-server-policy-delete called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import custom_whitelist_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(
        url=url,
        json=json_response,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    args = {"id": "1"}

    with pytest.raises(DemistoException) as error_info:
        custom_whitelist_delete_command(mock_client, args)
    assert error_msg in str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath", "expected"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomGlobalWhiteList",
            "custom_whitelist/v1_list.json",
            2,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/pattern.custom-global-white-list-group",
            "custom_whitelist/v2_list.json",
            2,
        ),
    ),
)
def test_custom_whitelist_list_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    jsonpath: str,
    expected,
):
    """
    Scenario: List custom whitelist members.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-server-policy-list called.
    Then:
     - Ensure that Custom WhiteList Members listed.
    """
    from FortinetFortiwebVM import custom_whitelist_list_command

    args = {"page": "1", "page_size": 2}
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = custom_whitelist_list_command(mock_client, args)
    if isinstance(result.outputs, list):
        assert len(result.outputs) == expected
    assert result.outputs_prefix == "FortiwebVM.CustomGlobalWhitelist"


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/GeoIPExceptionsList",
            "geo_dependencies/v1_geo_exceptions.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/geo-ip-except",
            "geo_dependencies/v2_geo_exceptions.json",
        ),
    ),
)
def test_geo_exception_list_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
    """
    Scenario: List the Geo IP Exceptions.
    When:
     - fortiwebvm-geo-exception-list.
    Then:
     - Ensure that the output is correct.
    """
    from FortinetFortiwebVM import geo_exception_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = geo_exception_list_command(mock_client, {})
    assert result.outputs_prefix == "FortiwebVM.GeoExceptionGroup"


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "LogReport/LogPolicy/TriggerList",
            "geo_dependencies/v1_trigger_policy.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/log/trigger-policy",
            "geo_dependencies/v2_trigger_policy.json",
        ),
    ),
)
def test_trigger_policy_list_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
    """
    Scenario: List the Trigger Policies.
    When:
     - fortiwebvm-trigger-policy-list.
    Then:
     - Ensure that the output is correct.
    """
    from FortinetFortiwebVM import trigger_policy_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = trigger_policy_list_command(mock_client, {})
    assert result.outputs_prefix == "FortiwebVM.TriggerPolicy"


@pytest.mark.parametrize(
    (
        "version",
        "endpoint",
        "args",
        "jsonpath",
        "expected_value",
        "status_code",
        "assert_flag",
    ),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomPredefinedGlobalWhiteList",
            {
                "id": "200001",
                "status": "enable",
            },
            "custom_predifined/v1_update_success.json",
            "200001",
            HTTPStatus.OK,
            False,
        ),
        (
            ClientV2.API_VER,
            "policy/serverobjects.global.predefinedglobalwhitelist",
            {
                "id": "200001",
                "status": "enable",
            },
            "custom_predifined/v2_update_success.json",
            "200001",
            HTTPStatus.OK,
            False,
        ),
    ),
)
def test_custom_predifined_whitelist_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    expected_value: str,
    status_code: HTTPStatus,
    assert_flag: bool,
):
    """
    Scenario: Update a custom predifined whitelist member.
    Given:
     - User has provided correct data.
     - User has provided exist name.
    When:
     - fortiwebvm-custom-predefined-whitelist-update called.
    Then:
     - Ensure that custom whitelist predifined member updated.
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import custom_predifined_whitelist_update_command

    get_jsonpath = (
        "custom_predifined/v1_list_success.json"
        if version == ClientV1.API_VER
        else "custom_predifined/v2_list_success.json"
    )
    url = urljoin(mock_client.base_url, endpoint)
    get_response = load_mock_response(get_jsonpath)
    requests_mock.get(url=url, json=get_response, status_code=HTTPStatus.OK)
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response, status_code=status_code)
    result = custom_predifined_whitelist_update_command(mock_client, args)
    output = f'{OutputTitle.CUSTOM_PREDIFINED.value} {args["id"]} {OutputTitle.UPDATED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Global/CustomPredefinedGlobalWhiteList",
            "custom_predifined/v1_list_success.json",
        ),
        (
            ClientV2.API_VER,
            "policy/serverobjects.global.predefinedglobalwhitelist",
            "custom_predifined/v2_list_success.json",
        ),
    ),
)
def test_custom_predifined_whitelist_list_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
    """
    Scenario: List the custom predifined whitelist members.
    When:
     - fortiwebvm-custom-predefined-whitelist-update called.
    Then:
     - Ensure that the output is correct.
    """
    from FortinetFortiwebVM import custom_predifined_whitelist_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = custom_predifined_whitelist_list_command(mock_client, {})
    assert result.outputs_prefix == "FortiwebVM.CustomPredefinedGlobalWhitelist"


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "System/Certificates/InterCAGroupList",
            "policy_dependencies/v1_certificate_intermediate_group.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/system/certificate.intermediate-certificate-group",
            "policy_dependencies/v2_certificate_intermediate_group.json",
        ),
    ),
)
def test_certificate_intermediate_group_list_command(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str
):
    """
    Scenario: List the Certificate intermediate groups.
    When:
     - fortiwebvm-certificate-intermediate-group-list.
    Then:
     - Ensure that the output is correct.
    """
    from FortinetFortiwebVM import certificate_intermediate_group_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = certificate_intermediate_group_list_command(mock_client, {})
    assert result.outputs_prefix == "FortiwebVM.CertificateIntermediateGroup"


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/URLAccessRule",
            {"name": "check", "action": "Alert & Deny", "host_status": "disable", "severity": "High"},
            "v1_create_update_group.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/url-access.url-access-rule",
            {"name": "check", "action": "Alert & Deny", "host_status": "disable", "severity": "High"},
            "url_access_rule_group/v2_create.json",
        ),
    ),
)
def test_url_access_rule_group_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Create an URL access rule group.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-url-access-rule-group-create called.
    Then:
     - Ensure that URL access rule group created.
    """
    from FortinetFortiwebVM import url_access_rule_group_create_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = url_access_rule_group_create_command(mock_client, args)
    output = f'{OutputTitle.URL_ACCESS_RULE_GROUP.value} {args["name"]} {OutputTitle.CREATED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/URLAccessRule",
            {"name": "check", "action": "Alert & Deny", "host_status": "enable"},
            ErrorMessage.INSERT_VALUE.value.format('host'),
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/url-access.url-access-rule",
            {"name": "check", "action": "Alert & Deny", "host_status": "enable"},
            ErrorMessage.INSERT_VALUE.value.format('host'),
        ),
    ),
)
def test_input_fail_url_access_rule_group_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    error_msg: str,
):
    """
    Scenario: Create an URL access rule group.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-protected-hostname-group-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import url_access_rule_group_create_command

    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(ValueError) as error_info:
        url_access_rule_group_create_command(mock_client, args)
    assert error_msg == str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/URLAccessRule/check",
            {"name": "check", "action": "Alert & Deny", "host_status": "disable"},
            "v1_create_update_group.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/url-access.url-access-rule?mkey=check",
            {"name": "check", "action": "Alert & Deny", "host_status": "disable"},
            "url_access_rule_group/v2_update.json",
        ),
    ),
)
def test_url_access_rule_group_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Update an URL access rule group.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-url-access-rule-group-update called.
    Then:
     - Ensure that URL access rule group updated.
    """
    from FortinetFortiwebVM import url_access_rule_group_update_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = url_access_rule_group_update_command(mock_client, args)
    output = f'{OutputTitle.URL_ACCESS_RULE_GROUP.value} {args["name"]} {OutputTitle.UPDATED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/URLAccessRule/check",
            {"name": "check"},
            "v1_delete.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/url-access.url-access-rule?mkey=check",
            {"name": "check"},
            "v2_delete.json",
        ),
    ),
)
def test_url_access_rule_group_delete_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Delete an URL access rule group.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-url-access-rule-group-delete called.
    Then:
     - Ensure that URL access rule group deleted.
    """
    from FortinetFortiwebVM import url_access_rule_group_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = url_access_rule_group_delete_command(mock_client, args)
    output = f'{OutputTitle.URL_ACCESS_RULE_GROUP.value} {args["name"]} {OutputTitle.DELETED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "expected"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/URLAccessRule",
            {"page": "1", "page_size": 3},
            "url_access_rule_group/v1_list.json",
            1,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/url-access.url-access-rule",
            {"page": "1", "page_size": 3},
            "url_access_rule_group/v2_list.json",
            1,
        ),
    ),
)
def test_url_access_rule_group_list_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    expected,
):
    """
    Scenario: List URL access rule groups.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-protected-hostname-group-list called.
    Then:
     - Ensure that protected hostname listed.
    """
    from FortinetFortiwebVM import url_access_rule_group_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = url_access_rule_group_list_command(mock_client, args)
    if isinstance(result.outputs, list):
        assert len(result.outputs) == expected
    assert result.outputs_prefix == "FortiwebVM.URLAccessRuleGroup"
    assert isinstance(result.outputs, list)
    assert result.outputs[0]['count'] == 0
    assert result.outputs[0]['host'] == 'test'


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "expected_value"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/URLAccessRule/test/URLAccessRuleNewURLAccessCondition",
            {"group_name": "test", "url_type": "Simple String", "url_pattern": "test",
             "meet_this_condition_if": "Object matches the URL Pattern", "source_address": "disable"},
            "url_access_rule_condition/v1_create.json",
            "2",
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/url-access.url-access-rule/match-condition?mkey=test",
            {
                "group_name": "test",
                "url_type": "Simple String",
                "url_pattern": "test", "meet_this_condition_if": "Object matches the URL Pattern",
                "source_address": "disable",
            },
            "url_access_rule_condition/v2_create.json",
            "1",
        ),
    ),
)
def test_url_access_rule_condition_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    expected_value: str,
):
    """
    Scenario: Create an URL access rule condition.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-url-access-rule-condition-create called.
    Then:
     - Ensure that URL access rule condition created.
    """
    from FortinetFortiwebVM import url_access_rule_condition_create_command

    json_response = load_mock_response(jsonpath)
    json_response_get = load_mock_response(
        "url_access_rule_condition/v1_list.json"
    )
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response)
    requests_mock.get(url=url, json=json_response_get, status_code=200)
    result = url_access_rule_condition_create_command(mock_client, args)
    assert result.outputs_prefix == "FortiwebVM.URLAccessRuleGroup"
    assert isinstance(result.outputs, dict)
    assert result.outputs["id"] == "test"
    assert result.outputs["Condition"]["id"] == expected_value


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/URLAccessRule/check/URLAccessRuleNewURLAccessCondition",
            {"group_name": "check", "url_type": "Simple String", "source_address": "enable", "url_pattern": "test"},
            ErrorMessage.INSERT_VALUE.value.format('source_address_type'),
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/url-access.url-access-rule/match-condition?mkey=check",
            {"group_name": "check", "url_type": "Simple String", "source_address": "enable", "url_pattern": "test"},
            ErrorMessage.INSERT_VALUE.value.format('source_address_type'),
        ),
        (
            ClientV1.API_VER,
            "WebProtection/Access/URLAccessRule/check/URLAccessRuleNewURLAccessCondition",
            {"group_name": "check", "url_type": "Simple String", "source_address": "enable", "url_pattern": "test",
             "source_address_type": "IP"},
            ErrorMessage.INSERT_VALUE.value.format('ip_range'),
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/url-access.url-access-rule/match-condition?mkey=check",
            {"group_name": "check", "url_type": "Simple String", "source_address": "enable", "url_pattern": "test",
             "source_address_type": "IP"},
            ErrorMessage.INSERT_VALUE.value.format('ip_range'),
        ),
        (
            ClientV1.API_VER,
            "WebProtection/Access/URLAccessRule/check/URLAccessRuleNewURLAccessCondition",
            {"group_name": "check", "url_type": "Simple String", "source_address": "enable", "url_pattern": "test",
             "source_address_type": ArgumentValues.SOURCE_ADDRESS_IP_RESOLVED.value},
            ErrorMessage.INSERT_VALUE.value.format('ip'),
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/url-access.url-access-rule/match-condition?mkey=check",
            {"group_name": "check", "url_type": "Simple String", "source_address": "enable", "url_pattern": "test",
             "source_address_type": ArgumentValues.SOURCE_ADDRESS_IP_RESOLVED.value},
            ErrorMessage.INSERT_VALUE.value.format('ip'),
        ),
        (
            ClientV1.API_VER,
            "WebProtection/Access/URLAccessRule/check/URLAccessRuleNewURLAccessCondition",
            {"group_name": "check", "url_type": "Simple String", "source_address": "enable", "url_pattern": "test",
             "source_address_type": ArgumentValues.SOURCE_ADDRESS_IP_RESOLVED.value, "ip": "0.0.0.0"},
            ErrorMessage.INSERT_VALUE.value.format('ip_type'),
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/url-access.url-access-rule/match-condition?mkey=check",
            {"group_name": "check", "url_type": "Simple String", "source_address": "enable", "url_pattern": "test",
             "source_address_type": ArgumentValues.SOURCE_ADDRESS_IP_RESOLVED.value, "ip": "0.0.0.0"},
            ErrorMessage.INSERT_VALUE.value.format('ip_type'),
        ),
        (
            ClientV1.API_VER,
            "WebProtection/Access/URLAccessRule/check/URLAccessRuleNewURLAccessCondition",
            {"group_name": "check", "url_type": "Simple String", "source_address": "enable", "url_pattern": "test",
             "source_address_type": ArgumentValues.SOURCE_ADDRESS_SOURCE_DOMAIN.value},
            ErrorMessage.INSERT_VALUE.value.format('source_domain'),
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/url-access.url-access-rule/match-condition?mkey=check",
            {"group_name": "check", "url_type": "Simple String", "source_address": "enable", "url_pattern": "test",
             "source_address_type": ArgumentValues.SOURCE_ADDRESS_SOURCE_DOMAIN.value},
            ErrorMessage.INSERT_VALUE.value.format('source_domain'),
        ),
        (
            ClientV1.API_VER,
            "WebProtection/Access/URLAccessRule/check/URLAccessRuleNewURLAccessCondition",
            {"group_name": "check", "url_type": "Simple String", "source_address": "enable", "url_pattern": "test",
             "source_address_type": ArgumentValues.SOURCE_ADDRESS_SOURCE_DOMAIN.value, "source_domain": "0.0.0.0"},
            ErrorMessage.INSERT_VALUE.value.format('source_domain_type'),
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/url-access.url-access-rule/match-condition?mkey=check",
            {"group_name": "check", "url_type": "Simple String", "source_address": "enable", "url_pattern": "test",
             "source_address_type": ArgumentValues.SOURCE_ADDRESS_SOURCE_DOMAIN.value, "source_domain": "0.0.0.0"},
            ErrorMessage.INSERT_VALUE.value.format('source_domain_type'),
        ),
    ),
)
def test_input_fail_url_access_rule_condition_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    error_msg: str,
):
    """
    Scenario: Create an URL access rule condition.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-url-access-rule-condition-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import url_access_rule_condition_create_command

    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(ValueError) as error_info:
        url_access_rule_condition_create_command(mock_client, args)
    assert error_msg == str(error_info.value)


@pytest.mark.parametrize(
    (
        "version",
        "put_endpoint",
        "get_endpoint",
        "args",
        "put_jsonpath",
        "get_jsonpath",
    ),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/URLAccessRule/test/URLAccessRuleNewURLAccessCondition/1",
            "WebProtection/Access/URLAccessRule/test/URLAccessRuleNewURLAccessCondition",
            {"group_name": "test", "condition_id": "1", "url_type": "Simple String", "url_pattern": "test",
             "meet_this_condition_if": "Object matches the URL Pattern", "source_address": "disable"},
            "url_access_rule_condition/v1_create.json",
            "url_access_rule_condition/v1_list.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/url-access.url-access-rule/match-condition?mkey=test&sub_mkey=1",
            "cmdb/waf/url-access.url-access-rule/match-condition?mkey=test",
            {
                "group_name": "test", "condition_id": "1",
                "url_type": "Simple String",
                "url_pattern": "test", "meet_this_condition_if": "Object matches the URL Pattern",
                "source_address": "disable",
            },
            "url_access_rule_condition/v2_create.json",
            "url_access_rule_condition/v2_get.json",
        ),
    ),
)
def test_url_access_rule_condition_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    put_endpoint: str,
    get_endpoint: str,
    args: Dict[str, Any],
    put_jsonpath: str,
    get_jsonpath: str,
):
    """
    Scenario: Update an URL access rule condition.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-protected-hostname-member-create called.
    Then:
     - Ensure that URL access rule condition updated.
    """
    from FortinetFortiwebVM import url_access_rule_condition_update_command

    json_response = load_mock_response(put_jsonpath)
    json_response_get = load_mock_response(get_jsonpath)
    put_url = urljoin(mock_client.base_url, put_endpoint)
    get_url = urljoin(mock_client.base_url, get_endpoint)
    requests_mock.put(url=put_url, json=json_response)
    requests_mock.get(url=get_url, json=json_response_get, status_code=200)
    result = url_access_rule_condition_update_command(mock_client, args)
    output = f'{OutputTitle.URL_ACCESS_RULE_CONDITION.value} {args["condition_id"]} {OutputTitle.UPDATED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "expected_value"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/URLAccessRule/test/URLAccessRuleNewURLAccessCondition/1",
            {"group_name": "test", "condition_id": "1"},
            "v1_delete.json",
            "2",
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/url-access.url-access-rule/match-condition?mkey=test&sub_mkey=1",
            {
                "group_name": "test",
                "condition_id": "1",
            },
            "v2_delete.json",
            "1",
        ),
    ),
)
def test_url_access_rule_condition_delete_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    expected_value: str,
):
    """
    Scenario: Delete an URL access rule condition
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-url-access-rule-condition-delete called.
    Then:
     - Ensure that URL access rule condition deleted.
    """
    from FortinetFortiwebVM import url_access_rule_condition_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(url=url, json=json_response)
    result = url_access_rule_condition_delete_command(mock_client, args)
    output = f'{OutputTitle.URL_ACCESS_RULE_CONDITION.value} {args["condition_id"]} {OutputTitle.DELETED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "expected"),
    (
        (
            ClientV1.API_VER,
            "WebProtection/Access/URLAccessRule/test/URLAccessRuleNewURLAccessCondition",
            {"group_name": "test", "page": "1", "page_size": 3},
            "url_access_rule_condition/v1_list.json",
            2,
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/url-access.url-access-rule/match-condition?mkey=test",
            {"group_name": "test", "page": "1", "page_size": 3},
            "url_access_rule_condition/v2_list.json",
            3,
        ),
    ),
)
def test_url_access_rule_condition_list_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    expected,
):
    """
    Scenario: List URL access rule conditions.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-url-access-rule-condition-list called.
    Then:
     - Ensure that URL access rule conditions listed.
    """
    from FortinetFortiwebVM import url_access_rule_condition_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = url_access_rule_condition_list_command(mock_client, args)
    assert isinstance(result.outputs, dict)
    assert result.outputs_prefix == "FortiwebVM.URLAccessRuleGroup"
    assert result.outputs.get('Condition')
    assert isinstance(result.outputs.get('Condition'), list)
    assert len(result.outputs['Condition']) == expected


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath", "outputs_prefix", "command_name"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Server/Persistence",
            "server_pool_dependencies/v1_persistence_policy.json",
            "FortiwebVM.PersistencePolicy",
            "fortiwebvm-persistence-policy-list",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/persistence-policy",
            "server_pool_dependencies/v2_persistence_policy.json",
            "FortiwebVM.PersistencePolicy",
            "fortiwebvm-persistence-policy-list",
        ),
        (
            ClientV1.API_VER,
            "ServerObjects/ServerHealthCheck/ServerHealthCheckList",
            "server_pool_dependencies/v1_server_health_check.json",
            "FortiwebVM.ServerHealthCheck",
            "fortiwebvm-server-health-check-list",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/health",
            "server_pool_dependencies/v2_server_health_check.json",
            "FortiwebVM.ServerHealthCheck",
            "fortiwebvm-server-health-check-list",
        ),
        (
            ClientV1.API_VER,
            "System/Certificates/Local",
            "server_pool_dependencies/v1_local_certificate.json",
            "FortiwebVM.LocalCertificate",
            "fortiwebvm-local-certificate-list",
        ),
        (
            ClientV2.API_VER,
            "system/certificate.local",
            "server_pool_dependencies/v2_local_certificate.json",
            "FortiwebVM.LocalCertificate",
            "fortiwebvm-local-certificate-list",
        ),
        (
            ClientV2.API_VER,
            "cmdb/system/certificate.multi-local",
            "server_pool_dependencies/v2_multi_certificate.json",
            "FortiwebVM.MultiCertificate",
            "fortiwebvm-multi-certificate-list",
        ),
        (
            ClientV2.API_VER,
            "cmdb/system/certificate.sni",
            "server_pool_dependencies/v2_sni_certificate.json",
            "FortiwebVM.SNICertificate",
            "fortiwebvm-sni-certificate-list",
        ),
        (
            ClientV2.API_VER,
            "cmdb/system/vip",
            "server_pool_dependencies/v2_sni_certificate.json",
            "FortiwebVM.VirtualIP",
            "fortiwebvm-virtual-ip-list",
        ),
        (
            ClientV1.API_VER,
            "System/Network/Interface",
            "server_pool_dependencies/v1_network_interface.json",
            "FortiwebVM.NetworkInterface",
            "fortiwebvm-network-interface-list",
        ),
        (
            ClientV2.API_VER,
            "system/network.interface",
            "server_pool_dependencies/v2_network_interface.json",
            "FortiwebVM.NetworkInterface",
            "fortiwebvm-network-interface-list",
        ),
        (
            ClientV2.API_VER,
            "cmdb/system/certificate.letsencrypt",
            "server_pool_dependencies/v2_letsencrypt.json",
            "FortiwebVM.Letsencrypt",
            "fortiwebvm-letsencrypt-certificate-list",
        ),
        (
            ClientV2.API_VER,
            "cmdb/system/sdn-connector",
            "server_pool_dependencies/v2_sdn_connector.json",
            "FortiwebVM.SDNCollector",
            "fortiwebvm-sdn-connector-list",
        ),
    ),
)
def test_dependencies_commands(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str,
    outputs_prefix: str, command_name: str
):
    """
    Scenario: List the dependencies commands bojects.
    When:
     - fortiwebvm-persistence-policy-list
     - fortiwebvm-server-health-check-list
     - fortiwebvm-local-certificate-list
     - fortiwebvm-multi-certificate-list
     - fortiwebvm-sni-certificate-list
     - fortiwebvm-virtual-ip-list
     - fortiwebvm-network-interface-list
     - fortiwebvm-sdn-connector-list

    Then:
     - Ensure that the output is correct.
    """
    from FortinetFortiwebVM import persistence_list_command
    from FortinetFortiwebVM import server_health_check_list_command
    from FortinetFortiwebVM import local_certificate_list_command
    from FortinetFortiwebVM import multi_certificate_list_command
    from FortinetFortiwebVM import sni_certificate_list_command
    from FortinetFortiwebVM import network_inteface_list_command
    from FortinetFortiwebVM import virtual_ip_list_command
    from FortinetFortiwebVM import letsencrypt_certificate_list_command
    from FortinetFortiwebVM import sdn_connector_list_command
    commands: dict[str, Callable] = {
        "fortiwebvm-persistence-policy-list": persistence_list_command,
        "fortiwebvm-server-health-check-list": server_health_check_list_command,
        "fortiwebvm-local-certificate-list": local_certificate_list_command,
        "fortiwebvm-multi-certificate-list": multi_certificate_list_command,
        "fortiwebvm-sni-certificate-list": sni_certificate_list_command,
        "fortiwebvm-virtual-ip-list": virtual_ip_list_command,
        "fortiwebvm-network-interface-list": network_inteface_list_command,
        "fortiwebvm-letsencrypt-certificate-list": letsencrypt_certificate_list_command,
        "fortiwebvm-sdn-connector-list": sdn_connector_list_command,
    }
    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = commands[command_name](mock_client, {})
    assert result.outputs_prefix == outputs_prefix
    assert isinstance(result.outputs, list)
    assert isinstance(result.outputs[0], dict)
    assert 'id' in result.outputs[0]


@pytest.mark.parametrize(
    ("version", "endpoint", "jsonpath", "outputs_prefix", "command_name"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Server/Persistence",
            "server_pool_dependencies/v1_persistence_policy.json",
            "FortiwebVM.PersistencePolicy",
            "fortiwebvm-multi-certificate-list",
        ),
        (
            ClientV1.API_VER,
            "ServerObjects/Server/Persistence",
            "server_pool_dependencies/v1_persistence_policy.json",
            "FortiwebVM.PersistencePolicy",
            "fortiwebvm-sni-certificate-list",
        ),
        (
            ClientV1.API_VER,
            "ServerObjects/Server/Persistence",
            "server_pool_dependencies/v1_persistence_policy.json",
            "FortiwebVM.PersistencePolicy",
            "fortiwebvm-sni-certificate-list",
        ),
    ),
)
def test_not_implemented_commands(
    requests_mock, mock_client: Client, version: str, endpoint: str, jsonpath: str,
    outputs_prefix: str, command_name: str
):
    """
    Scenario: Test not implemented commands.
    When:
     - fortiwebvm-multi-certificate-list
     - fortiwebvm-sni-certificate-list
     - fortiwebvm-letsencrypt-certificate-list
     - fortiwebvm-sdn-connector-list
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import multi_certificate_list_command
    from FortinetFortiwebVM import sni_certificate_list_command
    from FortinetFortiwebVM import letsencrypt_certificate_list_command
    from FortinetFortiwebVM import sdn_connector_list_command
    commands: dict[str, Callable] = {
        "fortiwebvm-multi-certificate-list": multi_certificate_list_command,
        "fortiwebvm-sni-certificate-list": sni_certificate_list_command,
        "fortiwebvm-letsencrypt-certificate-list": letsencrypt_certificate_list_command,
        "fortiwebvm-sdn-connector-list": sdn_connector_list_command,
    }
    with pytest.raises(NotImplementedError) as error_info:
        commands[command_name](mock_client, {})
    assert str(error_info.value) == ErrorMessage.V1_NOT_SUPPORTED.value


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Server/VirtualServer",
            {"name": "check", "action": "Alert & Deny", "status": "disable",
             "use_interface_ip": "enable", "interface": "port1"},
            "v1_create_update_group.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/vserver",
            {"name": "check", "action": "Alert & Deny", "status": "disable",
             "use_interface_ip": "enable", "interface": "port1"},
            "virtual_server_group/v2_create.json",
        ),
    ),
)
def test_virtual_server_group_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Create a virtual server group.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-virtual-server-group-create called.
    Then:
     - Ensure that virtual server group created.
    """
    from FortinetFortiwebVM import virtual_server_group_create_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = virtual_server_group_create_command(mock_client, args)
    output = f'{OutputTitle.VIRTUAL_SERVER_GROUP.value} {args["name"]} {OutputTitle.CREATED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "error_msg"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Server/VirtualServer",
            {"name": "check", "status": "disable", "use_interface_ip": "enable"},
            ErrorMessage.INSERT_VALUE.value.format('interface'),
        ),
        (
            ClientV1.API_VER,
            "ServerObjects/Server/VirtualServer",
            {"name": "check", "status": "disable", "use_interface_ip": "disable", "interface": "port1"},
            ErrorMessage.INSERT_VALUE.value.format("ipv4_address or ipv6_address")

        ),
    ),
)
def test_input_fail_virtual_server_group_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: dict[str, Any],
    error_msg: str,
):
    """
    Scenario: Create a virtual server group.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-virtual-server-group-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import virtual_server_group_create_command

    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(ValueError) as error_info:
        virtual_server_group_create_command(mock_client, args)
    assert error_msg == str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Server/VirtualServer/check",
            {"name": "check", "action": "Alert & Deny", "status": "disable",
             "use_interface_ip": "enable", "interface": "port1"},
            "v1_create_update_group.json",
        ),
    ),
)
def test_virtual_server_group_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Update a virtual server group.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-virtual-server-group-update called.
    Then:
     - Ensure that virtual server group updated.
    """
    from FortinetFortiwebVM import virtual_server_group_update_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = virtual_server_group_update_command(mock_client, args)
    output = f'{OutputTitle.VIRTUAL_SERVER_GROUP.value} {args["name"]} {OutputTitle.UPDATED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Server/VirtualServer/check",
            {"name": "check"},
            "v1_delete.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/vserver?mkey=check",
            {"name": "check"},
            "v2_delete.json",
        ),
    ),
)
def test_virtual_server_group_delete_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Delete a virtual server group.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-virtual-server-group-delete called.
    Then:
     - Ensure that virtual server group deleted.
    """
    from FortinetFortiwebVM import virtual_server_group_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = virtual_server_group_delete_command(mock_client, args)
    output = f'{OutputTitle.VIRTUAL_SERVER_GROUP.value} {args["name"]} {OutputTitle.DELETED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "expected"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Server/VirtualServer",
            {"page": "1", "page_size": 3},
            "url_access_rule_group/v1_list.json",
            1,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/vserver",
            {"page": "1", "page_size": 3},
            "url_access_rule_group/v2_list.json",
            1,
        ),
    ),
)
def test_virtual_server_group_list_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: dict[str, Any],
    jsonpath: str,
    expected,
):
    """
    Scenario: List virtual server groups.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-virtual-server-group-list called.
    Then:
     - Ensure that virtual server groups listed.
    """
    from FortinetFortiwebVM import virtual_server_group_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = virtual_server_group_list_command(mock_client, args)
    assert isinstance(result.outputs, list)
    assert len(result.outputs) == expected
    assert result.outputs_prefix == "FortiwebVM.VirtualServerGroup"


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "expected_value"),
    (
        (
            ClientV2.API_VER,
            "cmdb/server-policy/vserver/vip-list?mkey=check",
            {"group_name": "check", "status": "disable", "use_interface_ip": "enable", "interface": "port1"},
            "virtual_server_item/v2_create_update.json",
            "3",
        ),
    ),
)
def test_virtual_server_item_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: dict[str, Any],
    jsonpath: str,
    expected_value: str,
):
    """
    Scenario: Create a virtual server item.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-virtual-server-item-create called.
    Then:
     - Ensure that virtual server item created.
    """
    from FortinetFortiwebVM import virtual_server_item_create_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response)
    result = virtual_server_item_create_command(mock_client, args)
    assert result.outputs_prefix == "FortiwebVM.VirtualServerGroup"
    assert isinstance(result.outputs, dict)
    assert result.outputs["Item"]["id"] == expected_value


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "error_msg"),
    (
        (
            ClientV2.API_VER,
            "cmdb/waf/url-access.url-access-rule/match-condition?mkey=check",
            {"group_name": "check", "status": "disable", "use_interface_ip": "enable"},
            ErrorMessage.INSERT_VALUE.value.format('interface'),
        ),
        (
            ClientV2.API_VER,
            "cmdb/waf/url-access.url-access-rule/match-condition?mkey=check",
            {"group_name": "check", "status": "disable", "use_interface_ip": "disable"},
            ErrorMessage.INSERT_VALUE.value.format('virtual_ip'),
        ),
    ),
)
def test_input_fail_virtual_server_item_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: dict[str, Any],
    error_msg: str,
):
    """
    Scenario: Create a virtual server item.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-virtual-server-item-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import virtual_server_item_create_command

    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(
        url=url,
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        headers={"Content-Type": JSON_MIME_TYPE},
    )
    with pytest.raises(ValueError) as error_info:
        virtual_server_item_create_command(mock_client, args)
    assert error_msg == str(error_info.value)


@pytest.mark.parametrize(
    (
        "version",
        "put_endpoint",
        "args",
        "put_jsonpath",
    ),
    (
        (
            ClientV2.API_VER,
            "cmdb/server-policy/vserver/vip-list?mkey=test&sub_mkey=1",
            {
                "group_name": "test", "item_id": "1",
                "url_type": "Simple String",
                "url_pattern": "test", "meet_this_condition_if": "Object matches the URL Pattern",
                "source_address": "disable",
            },
            "virtual_server_item/v2_create_update.json",
        ),
    ),
)
def test_virtual_server_item_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    put_endpoint: str,
    args: dict[str, Any],
    put_jsonpath: str,
):
    """
    Scenario: Update a virtual server item.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-virtual-server-item-update called.
    Then:
     - Ensure that virtual server item updated.
    """
    from FortinetFortiwebVM import virtual_server_item_update_command

    json_response = load_mock_response(put_jsonpath)
    put_url = urljoin(mock_client.base_url, put_endpoint)
    requests_mock.put(url=put_url, json=json_response)
    result = virtual_server_item_update_command(mock_client, args)
    output = f'{OutputTitle.VIRTUAL_SERVER_ITEM.value} {args["item_id"]} {OutputTitle.UPDATED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "expected_value"),
    (
        (
            ClientV2.API_VER,
            "cmdb/server-policy/vserver/vip-list?mkey=test&sub_mkey=1",
            {
                "group_name": "test",
                "item_id": "1",
            },
            "v2_delete.json",
            "1",
        ),
    ),
)
def test_virtual_server_item_delete_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: dict[str, Any],
    jsonpath: str,
    expected_value: str,
):
    """
    Scenario: Delete a virtual server item
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-virtual-server-item-delte called.
    Then:
     - Ensure that virtual server item deleted.
    """
    from FortinetFortiwebVM import virtual_server_item_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(url=url, json=json_response)
    result = virtual_server_item_delete_command(mock_client, args)
    output = f'{OutputTitle.VIRTUAL_SERVER_ITEM.value} {args["item_id"]} {OutputTitle.DELETED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "expected"),
    (
        (
            ClientV2.API_VER,
            "cmdb/server-policy/vserver/vip-list?mkey=test",
            {"group_name": "test", "page": "1", "page_size": 3},
            "virtual_server_item/v2_list.json",
            3,
        ),
    ),
)
def test_virtual_server_item_list_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: dict[str, Any],
    jsonpath: str,
    expected,
):
    """
    Scenario: List virtual server items.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-virtual-server-item-list called.
    Then:
     - Ensure that virtual server items listed.
    """
    from FortinetFortiwebVM import virtual_server_item_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = virtual_server_item_list_command(mock_client, args)
    if isinstance(result.outputs, list):
        assert len(result.outputs) == expected
    assert result.outputs_prefix == "FortiwebVM.VirtualServerGroup"


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Server/ServerPool",
            {"name": "test", "server_balance": "Server Balance"},
            "v1_create_update_group.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/server-pool",
            {"name": "test", "server_balance": "Server Balance"},
            "server_pool/v2_create_update.json",
        ),
    ),
)
def test_server_pool_group_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Create a virtual server group.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-virtual-server-group-create called.
    Then:
     - Ensure that virtual server group created.
    """
    from FortinetFortiwebVM import server_pool_group_create_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.post(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = server_pool_group_create_command(mock_client, args)
    output = f'{OutputTitle.SERVER_POOL_GROUP.value} {args["name"]} {OutputTitle.CREATED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "args", "error_msg"),
    (
        (
            ClientV2.API_VER,
            {"name": "check", "health_check": "test", "type": "True Transparent Proxy"},
            ErrorMessage.INSERT_VALUE.value.format('health_check_source_ip')
        ),
        (
            ClientV2.API_VER,
            {"name": "check", "health_check": "test", "type": "True Transparent Proxy",
             "health_check_source_ip": "test"},
            ErrorMessage.INSERT_VALUE.value.format('health_check_source_ip_v6')
        ),
    ),
)
def test_input_fail_server_pool_group_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    args: Dict[str, Any],
    error_msg: str,
):
    """
    Scenario: Create a server pool group.
    Given:
     - User has provided wrong parameters.
    When:
     - fortiwebvm-server-pool-group-create called.
    Then:
     - Ensure relevant error raised.
    """
    from FortinetFortiwebVM import server_pool_group_create_command

    url = urljoin(mock_client.base_url, "ServerObjects/Server/ServerPool")
    requests_mock.post(
        url=url,
    )
    with pytest.raises(ValueError) as error_info:
        server_pool_group_create_command(mock_client, args)
    assert error_msg == str(error_info.value)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Server/ServerPool/check",
            {"name": "check", "type": "Reverse Proxy", "server_balance": "Server Balance", "lb_algo": "Round Robin"},
            "v1_create_update_group.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/server-pool?mkey=check",
            {"name": "check", "type": "Reverse Proxy", "server_balance": "Server Balance", "lb_algo": "Round Robin"},
            "server_pool/v2_create_update.json",
        ),
    ),
)
def test_server_pool_group_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Update a server pool group.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-server-pool-group-update called.
    Then:
     - Ensure that server pool group updated.
    """
    from FortinetFortiwebVM import server_pool_group_update_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.put(url=url, json=json_response, status_code=HTTPStatus.OK)
    args |= {"comments": "test", "health_check": "test", "persistence": "test"}
    result = server_pool_group_update_command(mock_client, args)
    output = f'{OutputTitle.SERVER_POOL_GROUP.value} {args["name"]} {OutputTitle.UPDATED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Server/ServerPool/check",
            {"name": "check"},
            "v1_delete.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/server-pool?mkey=check",
            {"name": "check"},
            "v2_delete.json",
        ),
    ),
)
def test_server_pool_group_delete_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Delete a server pool group.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-server-pool-group-delete called.
    Then:
     - Ensure that server pool group deleted.
    """
    from FortinetFortiwebVM import server_pool_group_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = server_pool_group_delete_command(mock_client, args)
    output = f'{OutputTitle.SERVER_POOL_GROUP.value} {args["name"]} {OutputTitle.DELETED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "expected"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Server/ServerPool",
            {"page": "1", "page_size": 3},
            "server_pool/v1_list.json",
            3,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/server-pool",
            {"page": "1", "page_size": 3},
            "server_pool/v2_list.json",
            1,
        ),
    ),
)
def test_server_pool_group_list_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    expected,
):
    """
    Scenario: List server pool groups.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-server-pool-group-list called.
    Then:
     - Ensure that server pool groups listed.
    """
    from FortinetFortiwebVM import server_pool_group_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = server_pool_group_list_command(mock_client, args)
    assert isinstance(result.outputs, list)
    assert len(result.outputs) == expected
    assert result.outputs_prefix == "FortiwebVM.ServerPoolGroup"


@pytest.mark.parametrize(
    ("version", "post_endpoint", "group_get_endpoint", "args", "post_json_path",
     "group_get_json_path", "expected_value", "group_type"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Server/ServerPool/test/EditServerPoolRule",
            "ServerObjects/Server/ServerPool",
            {"group_name": "test", "ip": "test", "server_type": "IP"},
            "v1_create_update_group.json",
            "server_pool/v1_list.json",
            "1",
            ArgumentValues.REVERSE_PROXY.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/server-pool/pserver-list?mkey=test",
            "cmdb/server-policy/server-pool?mkey=test",
            {
                "group_name": "test",
                "ip": "test"
            },
            "server_pool_rule/v2_create.json",
            "server_pool/v2_get_rp.json",
            "1",
            ArgumentValues.REVERSE_PROXY.value,
        ),
    ),
)
def test_server_pool_rule_create_command(
    requests_mock,
    mock_client: Client,
    version: str,
    post_endpoint: str,
    group_get_endpoint: str,
    args: Dict[str, Any],
    post_json_path: str,
    group_get_json_path: str,
    expected_value: str,
    group_type: str,
):
    """
    Scenario: Create an URL access rule condition.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-server-pool-reverse-proxy-rule-create called.
     - fortiwebvm-server-pool-offline-protection-rule-create called.
     - fortiwebvm-server-pool-true-transparent-proxy-rule-create called.
     - fortiwebvm-server-pool-transparent-inspection-rule-create called.
     - fortiwebvm-server-pool-wccp-rule-create called.
     - fortiwebvm-server-pool-ftp-rule-create called.
     - fortiwebvm-server-pool-adfs-rule-create called.
    Then:
     - Ensure that URL access rule condition created.
    """
    from FortinetFortiwebVM import server_pool_rule_create_command

    json_response = load_mock_response(post_json_path)
    json_response_get = load_mock_response(
        "server_pool_rule/v1_list.json"
    )
    group_get_response = load_mock_response(group_get_json_path)
    post_url = urljoin(mock_client.base_url, post_endpoint)
    get_url = urljoin(mock_client.base_url, group_get_endpoint)
    requests_mock.post(url=post_url, json=json_response)
    requests_mock.get(url=post_url, json=json_response_get, status_code=200)
    requests_mock.get(url=get_url, json=group_get_response, status_code=200)
    result = server_pool_rule_create_command(mock_client, args, group_type=group_type)
    assert result.outputs_prefix == "FortiwebVM.ServerPoolGroup"
    assert isinstance(result.outputs, dict)
    assert result.outputs['Rule']["id"] == expected_value


@pytest.mark.parametrize(
    ("version", "post_endpoint", "group_get_endpoint", "args", "post_json_path",
     "group_get_json_path", "expected_value", "group_type"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Server/ServerPool/test/EditServerPoolRule/1",
            "ServerObjects/Server/ServerPool",
            {"group_name": "test", "rule_id": "1", "ip": "1.1.1.1", "server_type": "IP"},
            "v1_create_update_group.json",
            "server_pool/v1_list.json",
            "1",
            ArgumentValues.REVERSE_PROXY.value,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/server-pool/pserver-list?mkey=test&sub_mkey=1",
            "cmdb/server-policy/server-pool?mkey=test",
            {
                "group_name": "test",
                "rule_id": "1",
                "ip": "1.1.1.1"
            },
            "server_pool_rule/v2_create.json",
            "server_pool/v2_get_rp.json",
            "1",
            ArgumentValues.REVERSE_PROXY.value,
        ),
    ),
)
def test_server_pool_rule_update_command(
    requests_mock,
    mock_client: Client,
    version: str,
    post_endpoint: str,
    group_get_endpoint: str,
    args: Dict[str, Any],
    post_json_path: str,
    group_get_json_path: str,
    expected_value: str,
    group_type: str,
):
    """
    Scenario: Update an URL access rule group.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-server-pool-reverse-proxy-rule-update called.
     - fortiwebvm-server-pool-offline-protection-rule-update called.
     - fortiwebvm-server-pool-true-transparent-proxy-rule-update called.
     - fortiwebvm-server-pool-transparent-inspection-rule-update called.
     - fortiwebvm-server-pool-wccp-rule-update called.
     - fortiwebvm-server-pool-ftp-rule-update called.
     - fortiwebvm-server-pool-adfs-rule-update called.
    Then:
     - Ensure that URL access rule group updated.
    """
    from FortinetFortiwebVM import server_pool_rule_update_command
    group_get_response = load_mock_response(group_get_json_path)
    get_url = urljoin(mock_client.base_url, group_get_endpoint)
    requests_mock.get(url=get_url, json=group_get_response, status_code=200)

    json_response = load_mock_response(post_json_path)
    post_url = urljoin(mock_client.base_url, post_endpoint)
    requests_mock.put(url=post_url, json=json_response, status_code=HTTPStatus.OK)
    result = server_pool_rule_update_command(mock_client, args, group_type=group_type)
    output = f'{OutputTitle.SERVER_POOL_RULE.value} {args["rule_id"]} {OutputTitle.UPDATED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Server/ServerPool/check/EditServerPoolRule/1",
            {"group_name": "check", "rule_id": "1"},
            "v1_delete.json",
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/server-pool/pserver-list?mkey=check&sub_mkey=1",
            {"group_name": "check", "rule_id": "1"},
            "v2_delete.json",
        ),
    ),
)
def test_server_pool_rule_delete_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
):
    """
    Scenario: Delete a server pool rule.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-server-pool-rule-delete called.
    Then:
     - Ensure that server pool rule deleted.
    """
    from FortinetFortiwebVM import server_pool_rule_delete_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.delete(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = server_pool_rule_delete_command(mock_client, args)
    output = f'{OutputTitle.SERVER_POOL_RULE.value} {args["rule_id"]} {OutputTitle.DELETED.value}'
    assert output == str(result.readable_output)


@pytest.mark.parametrize(
    ("version", "endpoint", "args", "jsonpath", "expected"),
    (
        (
            ClientV1.API_VER,
            "ServerObjects/Server/ServerPool/test/EditServerPoolRule",
            {"group_name": "test", "page": "1", "page_size": 3},
            "server_pool_rule/v1_list.json",
            1,
        ),
        (
            ClientV2.API_VER,
            "cmdb/server-policy/server-pool/pserver-list?mkey=test",
            {"group_name": "test", "page": "1", "page_size": 3},
            "server_pool_rule/v2_list.json",
            1,
        ),
    ),
)
def test_server_pool_rule_list_command(
    requests_mock,
    mock_client: Client,
    version: str,
    endpoint: str,
    args: Dict[str, Any],
    jsonpath: str,
    expected,
):
    """
    Scenario: List server pool rules.
    Given:
     - User has provided correct parameters.
    When:
     - fortiwebvm-server-pool-rule-list called.
    Then:
     - Ensure that server pool rules listed.
    """
    from FortinetFortiwebVM import server_pool_rule_list_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(mock_client.base_url, endpoint)
    requests_mock.get(url=url, json=json_response)
    result = server_pool_rule_list_command(mock_client, args)
    assert isinstance(result.outputs, dict)
    assert isinstance(result.outputs['Rule'], list)
    assert len(result.outputs['Rule']) == expected
    assert result.outputs_prefix == "FortiwebVM.ServerPoolGroup"
    assert result.outputs['Rule'][0]['ip'] == 'test'
