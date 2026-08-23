import json
import os

import pytest
from AzureResourceGraph import AzureResourceGraphClient, list_operations_command, pagination, query_resources_command

client = AzureResourceGraphClient(
    base_url="url",
    tenant_id="tenant",
    auth_id="auth_id",
    enc_key="enc_key",
    app_name="APP_NAME",
    verify="verify",
    proxy="proxy",
    self_deployed="self_deployed",
    ok_codes=(1, 2),
    server="server",
    certificate_thumbprint="",
    private_key="",
)


""" HELPER FUNCTIONS """


def util_load_json(path):
    full_path = os.path.join(os.path.dirname(__file__), path)
    with open(file=full_path, encoding="utf-8") as f:
        return json.loads(f.read())


def get_azure_access_token_mock() -> dict:
    """
    Mock Azure access token object.

    Returns:
        dict: Azure access token mock.
    """
    return {
        "access_token": "my-access-token",
        "expires_in": 3595,
        "refresh_token": "my-refresh-token",
    }


"""TESTS"""


@pytest.mark.parametrize(
    "function_name, data_file_name, args, additional_args",
    [
        ("list_operations", "test_list_operations_output", None, None),
        (
            "query_resources",
            "test_resources_query_output",
            {"query": "dummy"},
            {"paging_options": "dummy", "subscriptions": "dummy", "management_groups": "dummy"},
        ),
    ],
)
def test_client_api_calls(mocker, function_name, data_file_name, args, additional_args):
    data = util_load_json(f"test_data/{data_file_name}.json")
    mock_http_request = mocker.patch.object(client.ms_client, "http_request")
    mock_http_request.return_value = data
    if args and not additional_args:
        result = getattr(client, function_name)(args)
    elif args and additional_args:
        result = getattr(client, function_name)(args, **additional_args)
    else:
        result = getattr(client, function_name)()
    assert result == data


@pytest.mark.parametrize(
    "limit, page_size, page_number, expected_number_of_operations, expected_first_name",
    [
        (1, None, None, 1, "Microsoft.ResourceGraph/operations/read"),
        (3, 2, 2, 2, "Microsoft.ResourceGraph/resourcesHistory/read"),
    ],
)
def test_successful_list_operations_command(
    mocker, limit, page_size, page_number, expected_number_of_operations, expected_first_name
):
    operations_data = util_load_json("test_data/test_list_operations_output.json")
    mocker.patch.object(client, "list_operations", return_value=operations_data)
    args: dict = {"limit": limit, "page": page_number, "page_size": page_size}
    command_results = list_operations_command(client, args)
    assert command_results.outputs[0]["Name"] == expected_first_name
    assert len(command_results.outputs) == expected_number_of_operations


@pytest.mark.parametrize(
    "limit, page_size, page_number, expected_error_message",
    [
        (None, None, 2, 'Please enter a value for "page_size" when using "page".'),
        (None, 2, None, 'Please enter a value for "page" when using "page_size".'),
    ],
)
def test_failure_list_operations_command(mocker, limit, page_size, page_number, expected_error_message):
    try:
        operations_data = util_load_json("test_data/test_list_operations_output.json")
        mocker.patch.object(client, "list_operations", return_value=operations_data)
        args: dict = {"limit": limit, "page": page_number, "page_size": page_size}
        list_operations_command(client, args)
    except Exception as e:
        assert e.message == expected_error_message


@pytest.mark.parametrize(
    "query, data_file_name, expected_output",
    [("Resources | project id, name, type, location, tags | limit 3", "test_resources_query_output", "test-ssh-nsg")],
)
def test_query_resources_command_output(mocker, query, data_file_name, expected_output):
    query_data = util_load_json(f"test_data/{data_file_name}.json")
    args: dict = {"query": query, "limit": 1}
    mocker.patch.object(client, "query_resources", return_value=query_data)
    command_results = query_resources_command(client, args=args)
    assert command_results.outputs[0]["name"] == expected_output


@pytest.mark.parametrize(
    "query, data_file_name, extra_args, expected_length, expected_name",
    [
        (
            "Resources | project id, name, type, location, tags",
            "test_resources_query_paging_output",
            {"page": 1, "page_size": 3},
            3,
            "test-ssh-nsg-2",
        )
    ],
)
def test_query_resources_command_paging(mocker, query, data_file_name, extra_args, expected_length, expected_name):
    query_data = util_load_json(f"test_data/{data_file_name}.json")
    args: dict = {"query": query}
    args.update(extra_args)
    mocker.patch.object(client, "query_resources", return_value=query_data)
    command_results = query_resources_command(client, args=args)
    assert len(command_results.outputs) == expected_length
    assert command_results.outputs[0]["name"] == expected_name


def test_pagination_helper():
    fake_response = list(range(1, 101))
    results = pagination(fake_response, page_size=3, page_number=5)
    assert len(results) == 3


def test_test_module_command(mocker) -> None:
    """
    Scenario: run test module when managed identities client id provided.
    Given:
     - User has provided managed identities client oid.
    When:
     - test-module called.
    Then:
     - Ensure the output are as expected
    """
    import AzureResourceGraph
    import demistomock as demisto
    from AzureResourceGraph import MicrosoftClient, main

    params = {
        "auth_id": "test_client_id",
        "use_managed_identities": "True",
        "cred_token": {"password": "test"},
        "client_credentials": True,
        "host": "https://management.azure.com",
        "tenant_id": "1abc234d-12a3-12a3-12a3-1234abcde123",
        "cred_auth_id": {"password": "test_api"},
        "unsecure": False,
        "proxy": False,
        "private_key": "test-key",
        "self_deployed": True,
        "enc_key": "test",
    }

    # operations_data = util_load_json('./test_data/test_list_operations_output.json')
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(MicrosoftClient, "http_request", return_value=get_azure_access_token_mock())
    mocker.patch.object(AzureResourceGraph, "return_results")

    main()

    assert "ok" in AzureResourceGraph.return_results.call_args[0][0]


class TestGovAccountToggle:
    """Tests for the Gov Account checkbox feature."""

    GOV_SCOPE = "https://management.usgovcloudapi.net/.default"
    GOV_SERVER = "https://management.usgovcloudapi.net"
    GOV_BASE_URL = "https://management.usgovcloudapi.net/providers/Microsoft.ResourceGraph"
    NORMAL_SCOPE = "https://management.azure.com/.default"
    NORMAL_SERVER = "https://management.azure.com"
    NORMAL_BASE_URL = "https://management.azure.com/providers/Microsoft.ResourceGraph"

    def test_client_with_gov_account_enabled(self, mocker):
        """
        Given:
            - is_gov=True is passed to AzureResourceGraphClient.
        When:
            - The client is initialized.
        Then:
            - MicrosoftClient is created with the gov scope, AZURE_US_GCC_HIGH_CLOUD azure_cloud,
              and the gov base_url.
            - The client server is set to the gov management URL.
        """
        from AzureResourceGraph import AZURE_US_GCC_HIGH_CLOUD, AzureResourceGraphClient, MicrosoftClient

        mock_ms_client = mocker.patch.object(MicrosoftClient, "__init__", return_value=None)

        gov_client = AzureResourceGraphClient(
            base_url=self.NORMAL_BASE_URL,
            tenant_id="tenant",
            auth_id="auth_id",
            enc_key="enc_key",
            app_name="APP_NAME",
            verify=False,
            proxy=False,
            self_deployed=True,
            ok_codes=(200,),
            server=self.NORMAL_SERVER,
            certificate_thumbprint="",
            private_key="",
            is_gov=True,
        )

        call_kwargs = mock_ms_client.call_args[1]
        assert call_kwargs["scope"] == self.GOV_SCOPE
        assert call_kwargs["azure_cloud"] == AZURE_US_GCC_HIGH_CLOUD
        assert call_kwargs["base_url"] == self.GOV_BASE_URL
        assert gov_client.server == self.GOV_SERVER

    def test_client_with_gov_account_disabled(self, mocker):
        """
        Given:
            - is_gov=False (default) is passed to AzureResourceGraphClient.
        When:
            - The client is initialized.
        Then:
            - MicrosoftClient is created with the standard scope, no azure_cloud parameter,
              and the standard base_url.
            - The client server is set to the standard management URL.
        """
        from AzureResourceGraph import AzureResourceGraphClient, MicrosoftClient

        mock_ms_client = mocker.patch.object(MicrosoftClient, "__init__", return_value=None)

        normal_client = AzureResourceGraphClient(
            base_url=self.NORMAL_BASE_URL,
            tenant_id="tenant",
            auth_id="auth_id",
            enc_key="enc_key",
            app_name="APP_NAME",
            verify=False,
            proxy=False,
            self_deployed=True,
            ok_codes=(200,),
            server=self.NORMAL_SERVER,
            certificate_thumbprint="",
            private_key="",
            is_gov=False,
        )

        call_kwargs = mock_ms_client.call_args[1]
        assert call_kwargs["scope"] == self.NORMAL_SCOPE
        assert "azure_cloud" not in call_kwargs
        assert call_kwargs["base_url"] == self.NORMAL_BASE_URL
        assert normal_client.server == self.NORMAL_SERVER

    def test_client_default_is_not_gov(self, mocker):
        """
        Given:
            - is_gov is not passed to AzureResourceGraphClient (uses default).
        When:
            - The client is initialized.
        Then:
            - MicrosoftClient is created with the standard scope (same as is_gov=False).
        """
        from AzureResourceGraph import AzureResourceGraphClient, MicrosoftClient

        mock_ms_client = mocker.patch.object(MicrosoftClient, "__init__", return_value=None)

        default_client = AzureResourceGraphClient(
            base_url=self.NORMAL_BASE_URL,
            tenant_id="tenant",
            auth_id="auth_id",
            enc_key="enc_key",
            app_name="APP_NAME",
            verify=False,
            proxy=False,
            self_deployed=True,
            ok_codes=(200,),
            server=self.NORMAL_SERVER,
            certificate_thumbprint="",
            private_key="",
        )

        call_kwargs = mock_ms_client.call_args[1]
        assert call_kwargs["scope"] == self.NORMAL_SCOPE
        assert "azure_cloud" not in call_kwargs
        assert call_kwargs["base_url"] == self.NORMAL_BASE_URL
        assert default_client.server == self.NORMAL_SERVER

    def test_main_passes_gov_account_param(self, mocker):
        """
        Given:
            - The gov_account parameter is set to True in demisto.params().
        When:
            - main() is called with test-module command.
        Then:
            - AzureResourceGraphClient is initialized with is_gov=True and the gov URLs are used.
        """
        import AzureResourceGraph
        import demistomock as demisto
        from AzureResourceGraph import AZURE_US_GCC_HIGH_CLOUD, MicrosoftClient, main

        params = {
            "auth_id": "test_client_id",
            "cred_token": {"password": "test"},
            "host": "https://management.azure.com",
            "tenant_id": "1abc234d-12a3-12a3-12a3-1234abcde123",
            "cred_auth_id": {"password": "test_api"},
            "unsecure": False,
            "proxy": False,
            "private_key": "test-key",
            "self_deployed": True,
            "enc_key": "test",
            "gov_account": True,
        }

        mocker.patch.object(demisto, "params", return_value=params)
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="test-module")
        mock_ms_init = mocker.patch.object(MicrosoftClient, "__init__", return_value=None)
        mocker.patch.object(MicrosoftClient, "http_request", return_value=get_azure_access_token_mock())
        mocker.patch.object(AzureResourceGraph, "return_results")

        main()

        ms_call_kwargs = mock_ms_init.call_args[1]
        assert ms_call_kwargs["scope"] == self.GOV_SCOPE
        assert ms_call_kwargs["azure_cloud"] == AZURE_US_GCC_HIGH_CLOUD
        assert ms_call_kwargs["base_url"] == self.GOV_BASE_URL
        assert "ok" in AzureResourceGraph.return_results.call_args[0][0]

    def test_main_without_gov_account_param(self, mocker):
        """
        Given:
            - The gov_account parameter is not set (defaults to False) in demisto.params().
        When:
            - main() is called with test-module command.
        Then:
            - AzureResourceGraphClient is initialized with is_gov=False and the standard URLs are used.
        """
        import AzureResourceGraph
        import demistomock as demisto
        from AzureResourceGraph import MicrosoftClient, main

        params = {
            "auth_id": "test_client_id",
            "cred_token": {"password": "test"},
            "host": "https://management.azure.com",
            "tenant_id": "1abc234d-12a3-12a3-12a3-1234abcde123",
            "cred_auth_id": {"password": "test_api"},
            "unsecure": False,
            "proxy": False,
            "private_key": "test-key",
            "self_deployed": True,
            "enc_key": "test",
        }

        mocker.patch.object(demisto, "params", return_value=params)
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch.object(demisto, "command", return_value="test-module")
        mock_ms_init = mocker.patch.object(MicrosoftClient, "__init__", return_value=None)
        mocker.patch.object(MicrosoftClient, "http_request", return_value=get_azure_access_token_mock())
        mocker.patch.object(AzureResourceGraph, "return_results")

        main()

        ms_call_kwargs = mock_ms_init.call_args[1]
        assert ms_call_kwargs["scope"] == self.NORMAL_SCOPE
        assert "azure_cloud" not in ms_call_kwargs
        assert ms_call_kwargs["base_url"] == self.NORMAL_BASE_URL
        assert "ok" in AzureResourceGraph.return_results.call_args[0][0]
