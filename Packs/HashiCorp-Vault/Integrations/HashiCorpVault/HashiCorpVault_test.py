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

def test_parse_ssh_key_secret_with_concat_username():
    """
    Given:
        A secret containing username and sshkey fields with concat_username=True.

    When:
        Calling parse_ssh_key_secret with the secret data.

    Then:
        Verify the returned credential includes the username, sshkey (as sshkey), and concatenated name.
    """
    secret_data = {
        "username": "admin",
        "sshkey": "ssh-rsa AAAAB3NzaC1y...",
    }
    secret_name = "prod-server"
    result = parse_ssh_key_secret(secret_data, secret_name, concat_username=True)

    assert result["user"] == "admin"
    assert result["sshkey"] == "ssh-rsa AAAAB3NzaC1y..."
    assert result["name"] == "prod-server_admin"
    assert result["password"] == ""


def test_parse_ssh_key_secret_without_concat_username():
    """
    Given:
        A secret containing username and sshkey fields with concat_username=False.

    When:
        Calling parse_ssh_key_secret with the secret data.

    Then:
        Verify the returned credential includes the username, sshkey, and non-concatenated name.
    """
    secret_data = {
        "username": "deploy",
        "sshkey": "ssh-rsa BBBBC4Cad...",
    }
    secret_name = "staging-server"
    result = parse_ssh_key_secret(secret_data, secret_name, concat_username=False)

    assert result["user"] == "deploy"
    assert result["sshkey"] == "ssh-rsa BBBBC4Cad..."
    assert result["name"] == "staging-server"
    assert result["password"] == ""


def test_parse_ssh_key_secret_with_empty_username():
    """
    Given:
        A secret with an empty username field and valid sshkey.

    When:
        Calling parse_ssh_key_secret with concat_username=True.

    Then:
        Verify the name is not concatenated when username is empty.
    """
    secret_data = {
        "username": "",
        "sshkey": "ssh-rsa CCCCD5De...",
    }
    secret_name = "test-server"
    result = parse_ssh_key_secret(secret_data, secret_name, concat_username=True)

    assert result["user"] == ""
    assert result["sshkey"] == "ssh-rsa CCCCD5De..."
    assert result["name"] == "test-server"
    assert result["password"] == ""


def test_parse_legacy_secret_with_concat_username():
    """
    Given:
        A dictionary of key-value pairs (username: password) with concat_username=True.

    When:
        Calling parse_legacy_secret with the secret data.

    Then:
        Verify each credential is created with concatenated names.
    """
    secret_values = {
        "user1": "password1",
        "user2": "password2",
    }
    secret_name = "database-creds"
    result = parse_legacy_secret(secret_values, secret_name, concat_username=True)

    assert len(result) == 2
    assert result[0]["user"] == "user1"
    assert result[0]["password"] == "password1"
    assert result[0]["name"] == "database-creds_user1"
    assert result[1]["user"] == "user2"
    assert result[1]["password"] == "password2"
    assert result[1]["name"] == "database-creds_user2"


def test_parse_legacy_secret_without_concat_username():
    """
    Given:
        A dictionary of key-value pairs with concat_username=False.

    When:
        Calling parse_legacy_secret with the secret data.

    Then:
        Verify each credential is created with the same name.
    """
    secret_values = {
        "admin": "securepass123",
        "developer": "devpass456",
    }
    secret_name = "app-users"
    result = parse_legacy_secret(secret_values, secret_name, concat_username=False)

    assert len(result) == 2
    assert result[0]["user"] == "admin"
    assert result[0]["password"] == "securepass123"
    assert result[0]["name"] == "app-users"
    assert result[1]["user"] == "developer"
    assert result[1]["password"] == "devpass456"
    assert result[1]["name"] == "app-users"


def test_parse_legacy_secret_single_user():
    """
    Given:
        A dictionary with a single user entry.

    When:
        Calling parse_legacy_secret.

    Then:
        Verify a single credential is returned.
    """
    secret_values = {
        "root": "rootpassword",
    }
    secret_name = "system-creds"
    result = parse_legacy_secret(secret_values, secret_name, concat_username=True)

    assert len(result) == 1
    assert result[0]["user"] == "root"
    assert result[0]["password"] == "rootpassword"
    assert result[0]["name"] == "system-creds_root"


@patch("HashiCorpVault.USE_SSH_KEY_AUTH", True)
def test_get_kv1_secrets_with_ssh_key_auth_enabled(mock_use_ssh, mocker):
    """
    Given:
        KV1 secrets with both username and sshkey fields, and USE_SSH_KEY_AUTH is True.

    When:
        Calling get_kv1_secrets.

    Then:
        Verify the SSH key parsing is used instead of legacy parsing.
    """
    mock_send_request = mocker.patch("HashiCorpVault.send_request")
    mock_send_request.side_effect = [
        {"data": {"keys": ["prod-ssh-key"]}},
        {"data": {"username": "ubuntu", "sshkey": "ssh-rsa AAAA..."}},
    ]

    result = get_kv1_secrets("secret/", concat_username_to_cred_name=False)

    assert len(result) == 1
    assert result[0]["user"] == "ubuntu"
    assert result[0]["sshkey"] == "ssh-rsa AAAA..."
    assert result[0]["name"] == "prod-ssh-key"
    assert result[0]["password"] == ""


@patch("HashiCorpVault.USE_SSH_KEY_AUTH", False)
def test_get_kv1_secrets_with_ssh_key_auth_disabled(mock_use_ssh, mocker):
    """
    Given:
        KV1 secrets with both username and sshkey fields, but USE_SSH_KEY_AUTH is False.

    When:
        Calling get_kv1_secrets.

    Then:
        Verify the legacy parsing is used, treating the secret as key-value pairs.
    """
    mock_send_request = mocker.patch("HashiCorpVault.send_request")
    mock_send_request.side_effect = [
        {"data": {"keys": ["legacy-creds"]}},
        {"data": {"username": "user1", "password": "pass1"}},
    ]

    result = get_kv1_secrets("secret/", concat_username_to_cred_name=False)

    assert len(result) == 1
    assert result[0]["user"] == "username"
    assert result[0]["password"] == "user1"


@patch("HashiCorpVault.USE_SSH_KEY_AUTH", True)
def test_get_kv1_secrets_missing_ssh_fields_fallback_to_legacy(mock_use_ssh, mocker):
    """
    Given:
        KV1 secrets missing either username or sshkey field, with USE_SSH_KEY_AUTH enabled.

    When:
        Calling get_kv1_secrets.

    Then:
        Verify fallback to legacy parsing occurs.
    """
    mock_send_request = mocker.patch("HashiCorpVault.send_request")
    mock_send_request.side_effect = [
        {"data": {"keys": ["partial-secret"]}},
        {"data": {"username": "admin"}},  # Missing sshkey field
    ]

    result = get_kv1_secrets("secret/", concat_username_to_cred_name=False)

    assert len(result) == 1
    assert result[0]["user"] == "username"
    assert result[0]["password"] == "admin"


@patch("HashiCorpVault.USE_SSH_KEY_AUTH", True)
def test_get_kv2_secrets_with_ssh_key_auth_enabled(mock_use_ssh, mocker):
    """
    Given:
        KV2 secrets with username and sshkey fields, and USE_SSH_KEY_AUTH is True.

    When:
        Calling get_kv2_secrets.

    Then:
        Verify the SSH key parsing is used.
    """
    mock_list_secrets = mocker.patch("HashiCorpVault.list_secrets")
    mock_list_secrets.return_value = {"data": {"keys": ["staging-ssh"]}}
    mock_send_request = mocker.patch("HashiCorpVault.send_request")
    mock_send_request.return_value = {"data": {"data": {"username": "centos", "sshkey": "ssh-rsa BBBB..."}}}

    result = get_kv2_secrets("kv/", concat_username_to_cred_name=True)

    assert len(result) == 1
    assert result[0]["user"] == "centos"
    assert result[0]["sshkey"] == "ssh-rsa BBBB..."
    assert result[0]["name"] == "staging-ssh_centos"


@patch("HashiCorpVault.USE_SSH_KEY_AUTH", False)
def test_get_kv2_secrets_with_ssh_key_auth_disabled(mock_use_ssh, mocker):
    """
    Given:
        KV2 secrets with SSH fields, but USE_SSH_KEY_AUTH is False.

    When:
        Calling get_kv2_secrets.

    Then:
        Verify legacy parsing is used.
    """
    mock_list_secrets = mocker.patch("HashiCorpVault.list_secrets")
    mock_list_secrets.return_value = {"data": {"keys": ["app-creds"]}}
    mock_send_request = mocker.patch("HashiCorpVault.send_request")
    mock_send_request.return_value = {"data": {"data": {"app_user": "apppass"}}}

    result = get_kv2_secrets("kv/", concat_username_to_cred_name=False)

    assert len(result) == 1
    assert result[0]["user"] == "app_user"
    assert result[0]["password"] == "apppass"


@patch("HashiCorpVault.USE_SSH_KEY_AUTH", True)
def test_get_kv2_secrets_missing_ssh_fields_fallback(mock_use_ssh, mocker):
    """
    Given:
        KV2 secrets missing sshkey field, with USE_SSH_KEY_AUTH enabled.

    When:
        Calling get_kv2_secrets.

    Then:
        Verify fallback to legacy parsing.
    """
    mock_list_secrets = mocker.patch("HashiCorpVault.list_secrets")
    mock_list_secrets.return_value = {"data": {"keys": ["incomplete-secret"]}}
    mock_send_request = mocker.patch("HashiCorpVault.send_request")
    mock_send_request.return_value = {"data": {"data": {"user": "testuser", "pass": "testpass"}}}

    result = get_kv2_secrets("kv/", concat_username_to_cred_name=False)

    assert len(result) == 1
    assert result[0]["user"] == "user"
    assert result[0]["password"] == "testuser"


@patch("HashiCorpVault.USE_SSH_KEY_AUTH", True)
def test_get_ch_secrets_with_ssh_key_auth_enabled(mock_use_ssh, mocker):
    """
    Given:
        Cubbyhole secrets with username and sshkey fields, and USE_SSH_KEY_AUTH is True.

    When:
        Calling get_ch_secrets.

    Then:
        Verify SSH key parsing is applied.
    """
    mock_send_request = mocker.patch("HashiCorpVault.send_request")
    mock_send_request.side_effect = [
        {"data": {"keys": ["cubby-ssh-key"]}},
        {"data": {"username": "vault-user", "sshkey": "ssh-rsa CCCC..."}},
    ]

    result = get_ch_secrets("cubbyhole/", concat_username_to_cred_name=False)

    assert len(result) == 1
    assert result[0]["user"] == "vault-user"
    assert result[0]["sshkey"] == "ssh-rsa CCCC..."
    assert result[0]["name"] == "cubby-ssh-key"


@patch("HashiCorpVault.USE_SSH_KEY_AUTH", False)
def test_get_ch_secrets_with_ssh_key_auth_disabled(mock_use_ssh, mocker):
    """
    Given:
        Cubbyhole secrets with USE_SSH_KEY_AUTH disabled.

    When:
        Calling get_ch_secrets.

    Then:
        Verify legacy parsing is used.
    """
    mock_send_request = mocker.patch("HashiCorpVault.send_request")
    mock_send_request.side_effect = [
        {"data": {"keys": ["db-secret"]}},
        {"data": {"db_user": "dbpass"}},
    ]

    result = get_ch_secrets("cubbyhole/", concat_username_to_cred_name=True)

    assert len(result) == 1
    assert result[0]["user"] == "db_user"
    assert result[0]["password"] == "dbpass"
    assert result[0]["name"] == "db-secret_db_user"


@patch("HashiCorpVault.USE_SSH_KEY_AUTH", True)
def test_get_ch_secrets_missing_ssh_fields_fallback(mock_use_ssh, mocker):
    """
    Given:
        Cubbyhole secrets missing sshkey, with USE_SSH_KEY_AUTH enabled.

    When:
        Calling get_ch_secrets.

    Then:
        Verify fallback to legacy parsing.
    """
    mock_send_request = mocker.patch("HashiCorpVault.send_request")
    mock_send_request.side_effect = [
        {"data": {"keys": ["partial"]}},
        {"data": {"username": "alice"}},  # Missing sshkey
    ]

    result = get_ch_secrets("cubbyhole/", concat_username_to_cred_name=False)

    assert len(result) == 1
    assert result[0]["user"] == "username"
    assert result[0]["password"] == "alice"


