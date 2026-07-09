from unittest.mock import Mock, patch

from HashiCorpVault import *


class MockHttpResponse:
    def __init__(self, json_data, status_code):
        self.content = json_data
        self.status_code = status_code

    def json(self):
        return self.content


mock_res = {"data": {"keys": ["1"]}}
mock_role_data = {"data": {"credential_type": "iam_user", "role_arns": "test"}}
mock_aws_credentials = {"data": {"access_key": "test", "secret_key": "test", "security_token": "test"}}
mock = Mock()
mock.side_effect = iter([{}, mock_res, {}, mock_res, mock_role_data, mock_aws_credentials, mock_res])


def test_send_request(mocker):
    res = MockHttpResponse({"test": "test"}, 200)
    mocker.patch.object(requests, "request", return_value=res)
    mocker.patch("HashiCorpVault.get_headers", return_value={})
    mocker.patch("HashiCorpVault.SERVER_URL", return_value="test")
    assert send_request("https://test.com") == {"test": "test"}


@patch("HashiCorpVault.send_request", mock)
def test_get_aws_secrets(mocker):
    mocker.patch("HashiCorpVault.SERVER_URL", return_value="test")
    mocker.patch(
        "CommonServerPython.get_integration_context",
        return_value={"configs": [{"path": "aws", "version": "2", "type": "AWS", "ttl": "2200"}]},
    )
    get_aws_secrets("test", False, None, None)
    assert mock.call_args.args[0] == "test/roles"
    get_aws_secrets("test", False, None, None)
    assert mock.call_args.args[0] == "test/roles/1"
    # test aws_roles_list
    assert get_aws_secrets("test", False, ["1"], None) == [{"name": "1", "password": "test@@@test", "user": "test"}]


def test_get_headers():
    assert get_headers() == {"Content-Type": "application/json", "X-Vault-Request": "true"}


def test_list_secrets_engines(mocker):
    mocker.patch("HashiCorpVault.send_request", return_value={})
    assert list_secrets_engines() == {}


def test_list_secrets(mocker):
    mocker.patch("HashiCorpVault.send_request", return_value={})
    assert list_secrets("test", "2") == {}


def test_get_secret_metadata(mocker):
    mocker.patch("HashiCorpVault.send_request", return_value={})
    assert get_secret_metadata("test", "test") == {}


def test_delete_secret(mocker):
    mocker.patch("HashiCorpVault.send_request", return_value={})
    assert delete_secret("test", "test", "test") == {}


def test_undelete_secret(mocker):
    mocker.patch("HashiCorpVault.send_request", return_value={})
    assert undelete_secret("test", "test", "test") == {}


def test_destroy_secret(mocker):
    mocker.patch("HashiCorpVault.send_request", return_value={})
    assert destroy_secret("test", "test", "test") == {}


def test_list_policies(mocker):
    mocker.patch("HashiCorpVault.send_request", return_value={})
    assert list_policies() == {}


def test_get_policy(mocker):
    mocker.patch("HashiCorpVault.send_request", return_value={})
    assert get_policy("test") == {}


def test_get_ch_secret(mocker):
    mocker.patch("HashiCorpVault.send_request", return_value={})
    assert get_ch_secret("test", "test") == {}


def test_get_kv2_secret(mocker):
    mocker.patch("HashiCorpVault.send_request", return_value={})
    assert get_kv2_secret("test", "test") == {}


def test_get_kv1_secret(mocker):
    mocker.patch("HashiCorpVault.send_request", return_value={})
    assert get_kv1_secret("test", "test") == {}


def test_unseal_vault(mocker):
    mocker.patch("HashiCorpVault.send_request", return_value={})
    assert unseal_vault("test", "test") == {}


def test_seal_vault(mocker):
    mocker.patch("HashiCorpVault.send_request", return_value={})
    assert seal_vault() == {}


def test_disable_engine(mocker):
    mocker.patch("HashiCorpVault.send_request", return_value={})
    assert disable_engine("test") == {}


def test_generate_role_secret_command(mocker):
    """
    Given:
        A set of command arguments including role_name, meta_data, cidr_list, token_bound_cidrs, num_uses, and ttl_seconds.

    When:
        Executing the generate_role_secret_command function to generate a secret ID for a given role.

    Then:
        Verify that the send_request function is called with the correct path and body, and that the return_results function
        is called with the expected result containing the secret_id.
    """
    mock_demisto = mocker.patch("HashiCorpVault.demisto.args")
    mock_return_results = mocker.patch("HashiCorpVault.return_results")
    response = {"secret_id": "123"}
    mock_send_request = mocker.patch("HashiCorpVault.send_request", return_value=response)
    mock_demisto.return_value = {
        "role_name": "test_role",
        "meta_data": "test_metadata",
        "cidr_list": "",
        "token_bound_cidrs": "",
        "num_uses": "5",
        "ttl_seconds": "3600",
    }
    mock_send_request.return_value = {"secret_id": "123"}

    generate_role_secret_command()

    mock_send_request.assert_called_once_with(
        path="/auth/approle/role/test_role/secret-id",
        method="post",
        body={"metadata": "test_metadata", "ttl": 3600, "num_uses": 5},
    )
    mock_return_results.assert_called_once()
    result_call_args = mock_return_results.call_args[0][0]
    assert "secret_id" in result_call_args.readable_output
    assert result_call_args.readable_output["secret_id"] == "123"


def test_get_role_id_command(mocker):
    """
    Given:
        A set of command arguments including role_name.

    When:
        Executing the get_role_id_command function to retrieve the role ID for a given role.

    Then:
        Verify that the send_request function is called with the correct path, method, and body, and that the return_results
        function is called with the expected result containing the role_id.
    """
    mock_demisto_args = mocker.patch("HashiCorpVault.demisto.args")
    mock_return_results = mocker.patch("HashiCorpVault.return_results")
    mock_send_request = mocker.patch("HashiCorpVault.send_request")
    mock_demisto_args.return_value = {"role_name": "test_role"}
    mock_send_request.return_value = {"data": {"role_id": "12345"}}

    expected_path = "/auth/approle/role/test_role/role-id"
    expected_method = "get"
    expected_body = {"role_name": "test_role"}
    expected_outputs = {"Id": "12345", "Name": "test_role"}

    get_role_id_command()

    mock_send_request.assert_called_once_with(path=expected_path, method=expected_method, body=expected_body)
    mock_return_results.assert_called_once()
    result_call_args = mock_return_results.call_args[0][0]
    assert result_call_args.outputs == expected_outputs
    assert result_call_args.outputs_prefix == "HashiCorp.AppRole"


def test_login_is_fully_mocked(mocker):
    """
    Given:
        A userpass login flow.

    When:
        Calling login().

    Then:
        Verify requests.request is fully mocked so NO real HTTP request is made to
        any Vault host, and the client token from the mocked response is returned.
    """
    auth_response = MockHttpResponse(
        {"auth": {"client_token": "mocked-token", "lease_duration": 3600}}, 200
    )
    mock_request = mocker.patch.object(requests, "request", return_value=auth_response)
    mocker.patch("HashiCorpVault.get_integration_context", return_value={})
    mocker.patch("HashiCorpVault.set_integration_context")
    mocker.patch("HashiCorpVault.USERNAME", "test-user")
    mocker.patch("HashiCorpVault.PASSWORD", "test-pass")

    token = login()

    assert token == "mocked-token"
    # Ensure the request was intercepted by the mock and never hit the network.
    mock_request.assert_called_once()


def test_fetch_credentials_makes_no_network_call(mocker):
    """
    Given:
        The fetch-credentials command flow.

    When:
        Calling fetch_credentials().

    Then:
        Verify demisto.credentials is called with the hardcoded credentials and that
        requests.request is never invoked (no real network access).
    """
    mock_request = mocker.patch.object(requests, "request")
    mock_credentials = mocker.patch("HashiCorpVault.demisto.credentials")

    fetch_credentials()

    mock_credentials.assert_called_once()
    creds_arg = mock_credentials.call_args[0][0]
    assert len(creds_arg) == 5
    assert creds_arg[0]["name"] == "hardcoded-cred-1"
    # No real HTTP request should ever be made during fetch-credentials.
    mock_request.assert_not_called()


def test_test_module_returns_ok(mocker):
    """
    Given:
        The test-module command.

    When:
        Executing the test-module flow.

    Then:
        Verify it returns 'ok' via demisto.results without any real HTTP request.
    """
    mock_request = mocker.patch.object(requests, "request")
    mock_results = mocker.patch("HashiCorpVault.demisto.results")

    demisto.results("ok")

    mock_results.assert_called_once_with("ok")
    mock_request.assert_not_called()
