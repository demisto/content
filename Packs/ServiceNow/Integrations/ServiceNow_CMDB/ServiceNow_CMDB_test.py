import pytest
from ServiceNow_CMDB import (
    Client,
    add_relation_command,
    create_record_command,
    delete_relation_command,
    get_record_command,
    main,
    records_list_command,
    update_record_command,
)
from ServiceNowApiModule import ServiceNowClient
from test_data.response_constants import (
    ADD_RELATION_RESPONSE,
    CREATE_RECORD_RESPONSE,
    DELETE_RELATION_RESPONSE,
    GET_RECORD_RESPONSE,
    RECORDS_LIST_EMPTY_RESPONSE,
    RECORDS_LIST_RESPONSE_WITH_RECORDS,
    UPDATE_RECORD_RESPONSE,
)
from test_data.result_constants import (
    EXPECTED_ADD_RELATION,
    EXPECTED_CREATE_RECORD,
    EXPECTED_DELETE_RELATION,
    EXPECTED_GET_RECORD,
    EXPECTED_RECORDS_LIST_NO_RECORDS,
    EXPECTED_RECORDS_LIST_WITH_RECORDS,
    EXPECTED_UPDATE_RECORD,
)


@pytest.mark.parametrize(
    "response, expected_result",
    [
        (RECORDS_LIST_RESPONSE_WITH_RECORDS, EXPECTED_RECORDS_LIST_WITH_RECORDS),
        (RECORDS_LIST_EMPTY_RESPONSE, EXPECTED_RECORDS_LIST_NO_RECORDS),
    ],
)
def test_records_list_command(response, expected_result, mocker):
    """
    Given:
        - The records list command.
    When:
        - Mocking the response from the http request once to a response containing records, and once to a response with
        no records.
    Then:
        - Validate that in the first case when the response contains records, the context has both `Class` and `Records`
         keys. In the second case, when no records are in the response, validate the context has only the `Class` key.
    """
    client = Client()
    mocker.patch.object(ServiceNowClient, "http_request", return_value=response)
    result = records_list_command(client, args={"class": "test_class"})
    assert expected_result == result[1]


def test_get_record_command(mocker):
    """
    Given:
        - The get record by id command.
    When:
        - Mocking the response from the http request to a response containing several attributes, inbound and outbound
        relations of the record.
    Then:
        - Validate that the output context of the command contains all attributes and relations that were returned.
    """
    client = Client()
    mocker.patch.object(ServiceNowClient, "http_request", return_value=GET_RECORD_RESPONSE)
    result = get_record_command(client, args={"class": "test_class", "sys_id": "record_id"})
    assert result[1] == EXPECTED_GET_RECORD


def test_create_record_command(mocker):
    """
    Given:
        - The create record command.
    When:
        - Mocking the response from the http request to a response containing the attributes of the new record with no
        inbound or outbound relations.
    Then:
        - Validate that the context output contains the `Class`, `SysId` and `Attributes` keys according to the mocked
        response, and that the inbound and outbound relations lists are empty.
    """
    client = Client()
    mocker.patch.object(ServiceNowClient, "http_request", return_value=CREATE_RECORD_RESPONSE)
    result = create_record_command(client, args={"class": "test_class", "attributes": "name=Test Create Record"})
    assert result[1] == EXPECTED_CREATE_RECORD


def test_update_record_command(mocker):
    """
    Given:
        - The update record command.
    When:
        - Mocking the response from the http request to a response containing the attributes of the updated record.
    Then:
        - Validate that the context output was changed according to the new attributes.
    """
    client = Client()
    mocker.patch.object(ServiceNowClient, "http_request", return_value=UPDATE_RECORD_RESPONSE)
    result = update_record_command(
        client, args={"class": "test_class", "sys_id": "record_id", "attributes": "name=Test Create Record"}
    )
    assert result[1] == EXPECTED_UPDATE_RECORD


def test_add_relation_command(mocker):
    """
    Given:
        - The add relation command.
    When:
        - Mocking the response from the http request to a response containing the attributes and the relations of the
        record.
    Then:
        - Validate that the `InboundRelations` key in the context output contains the added relation.
    """
    client = Client()
    mocker.patch.object(ServiceNowClient, "http_request", return_value=ADD_RELATION_RESPONSE)
    result = add_relation_command(
        client,
        args={
            "class": "test_class",
            "sys_id": "record_id",
            "inbound_relations": "[{'type': 'relation_type', 'target':'target', 'sys_class_name':'class_name'}]",
        },
    )
    assert result[1] == EXPECTED_ADD_RELATION


def test_delete_relation_command(mocker):
    """
    Given:
        - The delete relation command.
    When:
        - Mocking the response from the http request to a response containing the attributes and the relations of the
        record.
    Then:
        - Validate that the `InboundRelations` key in the context output is empty.
    """
    client = Client()
    mocker.patch.object(ServiceNowClient, "http_request", return_value=DELETE_RELATION_RESPONSE)
    result = delete_relation_command(client, args={"class": "test_class", "sys_id": "record_id", "relation_sys_id": "rel_id"})
    assert result[1] == EXPECTED_DELETE_RELATION


def test_client_jwt_param_usage(mocker):
    """
    Given:
    - JWT params provided to the ServiceNow CMDB Client
    When:
    - Initializing the Client with jwt_params
    Then:
    - ServiceNowClient is instantiated with the same jwt_params
    - The jwt attribute is set on the inner ServiceNowClient
    """
    jwt_params = {
        "private_key": "-----BEGIN PRIVATE KEY-----test-----END PRIVATE KEY-----",
        "kid": "test_kid",
        "sub": "test_sub",
        "aud": "test_aud",
        "iss": "test_iss",
    }
    mocker.patch("ServiceNowApiModule.jwt.encode", return_value="jwt_token_stub")
    client = Client(
        username="user",
        password="pw",
        use_oauth=True,
        client_id="client_id",
        client_secret="client_secret",
        url="https://example.com",
        verify=True,
        proxy=False,
        jwt_params=jwt_params,
    )
    assert hasattr(client.snow_client, "jwt")
    assert client.snow_client.jwt == "jwt_token_stub"


def test_client_empty_jwt_param_usage(mocker):
    """
    Given:
    - no JWT params provided to the ServiceNow CMDB Client
    When:
    - Initializing the Client
    Then:
    - ServiceNowClient is instantiated with the same jwt_params
    - The jwt attribute is set to None on the inner ServiceNowClient
    """
    jwt_params = {}
    client = Client(
        username="user",
        password="pw",
        use_oauth=True,
        client_id="client_id",
        client_secret="client_secret",
        url="https://example.com",
        verify=True,
        proxy=False,
        jwt_params=jwt_params,
    )
    assert hasattr(client.snow_client, "jwt")
    assert client.snow_client.jwt is None


class TestCredentialFlowEndToEnd:
    """End-to-end tests for the new basic_credentials / oauth_credentials flow in main()."""

    BASE_PARAMS = {
        "url": "https://test.service-now.com",
        "insecure": False,
        "proxy": False,
        "use_oauth": False,
        "use_jwt": False,
    }

    def test_basic_auth_with_basic_credentials(self, mocker):
        """
        Given:
            - basic_credentials param provides username and password.
            - OAuth is not enabled.
        When:
            - main() is called with the 'test-module' command.
        Then:
            - The Client is created with the username/password from basic_credentials.
            - test-module succeeds.
        """
        params = {
            **self.BASE_PARAMS,
            "basic_credentials": {"identifier": "basic_user", "password": "basic_pass"},
            "oauth_credentials": {"identifier": "oauth_id", "password": "oauth_secret"},
        }
        mocker.patch("ServiceNow_CMDB.demisto.params", return_value=params)
        mocker.patch("ServiceNow_CMDB.demisto.command", return_value="test-module")
        return_results_mock = mocker.patch("ServiceNow_CMDB.return_results")
        mocker.patch.object(ServiceNowClient, "http_request", return_value={"result": []})

        client_init_spy = mocker.patch("ServiceNow_CMDB.Client", wraps=Client)
        main()

        # Verify Client was called with basic_credentials values
        call_kwargs = client_init_spy.call_args[1]
        assert call_kwargs["username"] == "basic_user"
        assert call_kwargs["password"] == "basic_pass"
        assert call_kwargs["use_oauth"] is False
        return_results_mock.assert_called_once_with("ok")

    def test_basic_auth_legacy_fallback(self, mocker):
        """
        Given:
            - basic_credentials param is empty (no username/password).
            - oauth_credentials param has identifier and password.
            - OAuth is not enabled.
        When:
            - main() is called with the 'test-module' command.
        Then:
            - The Client falls back to using oauth_credentials for username/password (legacy behavior).
            - test-module succeeds.
        """
        params = {
            **self.BASE_PARAMS,
            "basic_credentials": {},
            "oauth_credentials": {"identifier": "legacy_user", "password": "legacy_pass"},
        }
        mocker.patch("ServiceNow_CMDB.demisto.params", return_value=params)
        mocker.patch("ServiceNow_CMDB.demisto.command", return_value="test-module")
        mocker.patch("ServiceNow_CMDB.demisto.debug")
        return_results_mock = mocker.patch("ServiceNow_CMDB.return_results")
        mocker.patch.object(ServiceNowClient, "http_request", return_value={"result": []})

        client_init_spy = mocker.patch("ServiceNow_CMDB.Client", wraps=Client)
        main()

        # Verify Client was called with legacy fallback values from oauth_credentials
        call_kwargs = client_init_spy.call_args[1]
        assert call_kwargs["username"] == "legacy_user"
        assert call_kwargs["password"] == "legacy_pass"
        assert call_kwargs["use_oauth"] is False
        return_results_mock.assert_called_once_with("ok")

    def test_oauth_uses_oauth_credentials_for_client_id_secret(self, mocker):
        """
        Given:
            - use_oauth is True.
            - oauth_credentials provides client_id (identifier) and client_secret (password).
            - basic_credentials provides username and password.
        When:
            - main() is called with the 'test-module' command.
        Then:
            - The Client is created with client_id/client_secret from oauth_credentials.
            - use_oauth is True.
        """
        params = {
            **self.BASE_PARAMS,
            "use_oauth": True,
            "basic_credentials": {"identifier": "basic_user", "password": "basic_pass"},
            "oauth_credentials": {"identifier": "my_client_id", "password": "my_client_secret"},
        }
        mocker.patch("ServiceNow_CMDB.demisto.params", return_value=params)
        mocker.patch("ServiceNow_CMDB.demisto.command", return_value="test-module")
        # return_error must stop execution (like the real one does via sys.exit),
        # otherwise test_module continues to records_list which triggers auto-login HTTP calls.
        mocker.patch("ServiceNow_CMDB.return_error", side_effect=SystemExit("return_error called"))

        client_init_spy = mocker.patch("ServiceNow_CMDB.Client", wraps=Client)
        with pytest.raises(SystemExit):
            main()

        # Verify Client was called with OAuth params
        call_kwargs = client_init_spy.call_args[1]
        assert call_kwargs["client_id"] == "my_client_id"
        assert call_kwargs["client_secret"] == "my_client_secret"
        assert call_kwargs["use_oauth"] is True
        assert call_kwargs["username"] == "basic_user"
        assert call_kwargs["password"] == "basic_pass"

    def test_jwt_auth_flow(self, mocker):
        """
        Given:
            - use_jwt is True, use_oauth is False.
            - oauth_credentials provides client_id and client_secret.
            - JWT params (private_key, kid, sub) are provided.
        When:
            - main() is called with the 'test-module' command.
        Then:
            - use_oauth is set to True (JWT implies OAuth).
            - jwt_params are passed to the Client.
            - The Client is created with the correct JWT configuration.
        """
        params = {
            **self.BASE_PARAMS,
            "use_jwt": True,
            "basic_credentials": {"identifier": "basic_user", "password": "basic_pass"},
            "oauth_credentials": {"identifier": "jwt_client_id", "password": "jwt_client_secret"},
            "private_key": {"password": "-----BEGIN PRIVATE KEY-----test-----END PRIVATE KEY-----"},
            "kid": "test_kid",
            "sub": "test_sub",
        }
        mocker.patch("ServiceNow_CMDB.demisto.params", return_value=params)
        mocker.patch("ServiceNow_CMDB.demisto.command", return_value="test-module")
        mocker.patch("ServiceNow_CMDB.return_results")
        mocker.patch("ServiceNowApiModule.jwt.encode", return_value="jwt_token_stub")
        mocker.patch.object(ServiceNowClient, "http_request", return_value={"result": []})

        client_init_spy = mocker.patch("ServiceNow_CMDB.Client", wraps=Client)
        main()

        call_kwargs = client_init_spy.call_args[1]
        assert call_kwargs["use_oauth"] is True
        assert call_kwargs["client_id"] == "jwt_client_id"
        assert call_kwargs["client_secret"] == "jwt_client_secret"
        jwt_params = call_kwargs["jwt_params"]
        assert jwt_params["private_key"] == "-----BEGIN PRIVATE KEY-----test-----END PRIVATE KEY-----"
        assert jwt_params["kid"] == "test_kid"
        assert jwt_params["sub"] == "test_sub"
        assert jwt_params["aud"] == "jwt_client_id"

    def test_jwt_and_oauth_both_enabled_raises_error(self, mocker):
        """
        Given:
            - Both use_jwt and use_oauth are True.
        When:
            - main() is called.
        Then:
            - A ValueError is raised indicating only one auth method should be chosen.
        """
        params = {
            **self.BASE_PARAMS,
            "use_jwt": True,
            "use_oauth": True,
            "basic_credentials": {},
            "oauth_credentials": {"identifier": "id", "password": "secret"},
        }
        mocker.patch("ServiceNow_CMDB.demisto.params", return_value=params)
        mocker.patch("ServiceNow_CMDB.demisto.command", return_value="test-module")
        return_error_mock = mocker.patch("ServiceNow_CMDB.return_error")

        main()

        # The first call to return_error is for the auth method error;
        # a second call may occur because 'client' is not defined after the ValueError
        assert return_error_mock.call_count >= 1
        assert "authentication method" in return_error_mock.call_args_list[0][0][0]

    def test_basic_auth_partial_credentials_triggers_fallback(self, mocker):
        """
        Given:
            - basic_credentials has username but no password.
            - oauth_credentials has identifier and password.
            - OAuth is not enabled.
        When:
            - main() is called with the 'test-module' command.
        Then:
            - The Client falls back to oauth_credentials for both username and password.
        """
        params = {
            **self.BASE_PARAMS,
            "basic_credentials": {"identifier": "partial_user", "password": ""},
            "oauth_credentials": {"identifier": "fallback_user", "password": "fallback_pass"},
        }
        mocker.patch("ServiceNow_CMDB.demisto.params", return_value=params)
        mocker.patch("ServiceNow_CMDB.demisto.command", return_value="test-module")
        mocker.patch("ServiceNow_CMDB.demisto.debug")
        mocker.patch("ServiceNow_CMDB.return_results")
        mocker.patch.object(ServiceNowClient, "http_request", return_value={"result": []})

        client_init_spy = mocker.patch("ServiceNow_CMDB.Client", wraps=Client)
        main()

        call_kwargs = client_init_spy.call_args[1]
        assert call_kwargs["username"] == "fallback_user"
        assert call_kwargs["password"] == "fallback_pass"

    def test_no_credentials_at_all(self, mocker):
        """
        Given:
            - Both basic_credentials and oauth_credentials are empty.
            - OAuth is not enabled.
        When:
            - main() is called with the 'test-module' command.
        Then:
            - The Client is created with empty string username/password (from empty oauth_credentials fallback).
        """
        params = {
            **self.BASE_PARAMS,
            "basic_credentials": {},
            "oauth_credentials": {},
        }
        mocker.patch("ServiceNow_CMDB.demisto.params", return_value=params)
        mocker.patch("ServiceNow_CMDB.demisto.command", return_value="test-module")
        mocker.patch("ServiceNow_CMDB.demisto.debug")
        mocker.patch("ServiceNow_CMDB.return_results")
        mocker.patch.object(ServiceNowClient, "http_request", return_value={"result": []})

        client_init_spy = mocker.patch("ServiceNow_CMDB.Client", wraps=Client)
        main()

        call_kwargs = client_init_spy.call_args[1]
        # Falls back to oauth_credentials which are also empty, .get() returns "" by default
        assert call_kwargs["username"] == ""
        assert call_kwargs["password"] == ""

    def test_oauth_login_command_with_new_credentials(self, mocker):
        """
        Given:
            - use_oauth is True.
            - oauth_credentials provides client_id and client_secret.
            - basic_credentials provides username and password.
        When:
            - main() is called with the 'servicenow-cmdb-oauth-login' command.
        Then:
            - The login command is executed with the correct client configuration.
        """
        params = {
            **self.BASE_PARAMS,
            "use_oauth": True,
            "basic_credentials": {"identifier": "basic_user", "password": "basic_pass"},
            "oauth_credentials": {"identifier": "my_client_id", "password": "my_client_secret"},
        }
        mocker.patch("ServiceNow_CMDB.demisto.params", return_value=params)
        mocker.patch("ServiceNow_CMDB.demisto.command", return_value="servicenow-cmdb-oauth-login")
        mocker.patch("ServiceNow_CMDB.demisto.args", return_value={"username": "login_user", "password": "login_pass"})
        mocker.patch.object(ServiceNowClient, "login")
        return_outputs_mock = mocker.patch("ServiceNow_CMDB.return_outputs")

        client_init_spy = mocker.patch("ServiceNow_CMDB.Client", wraps=Client)
        main()

        call_kwargs = client_init_spy.call_args[1]
        assert call_kwargs["client_id"] == "my_client_id"
        assert call_kwargs["client_secret"] == "my_client_secret"
        assert call_kwargs["use_oauth"] is True
        return_outputs_mock.assert_called_once()
