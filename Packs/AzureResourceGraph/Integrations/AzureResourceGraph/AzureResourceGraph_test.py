import json
import io
import pytest
from AzureResourceGraph import AzureResourceGraphClient, list_operations_command, query_resources_command


client = AzureResourceGraphClient(
    base_url="url", tenant_id="tenant", auth_id="auth_id", enc_key="enc_key", app_name="APP_NAME", verify="verify",
    proxy="proxy", self_deployed="self_deployed", ok_codes=(1, 2), server="server", subscription_id="subscription_id",
    certificate_thumbprint='', private_key='')


''' HELPER FUNCTIONS '''


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def get_azure_access_token_mock() -> dict:
    """
    Mock Azure access token object.

    Returns:
        dict: Azure access token mock.
    """
    return {
        'access_token': 'my-access-token',
        'expires_in': 3595,
        'refresh_token': 'my-refresh-token',
    }


'''TESTS'''


@pytest.mark.parametrize(
    "function_name, data_file_name, args", [
        ("list_operations", "test_list_operations_output", None),
        ("query_resources", "test_resources_query_output", {"query": "dummy"})
    ]
)
def test_client_api_calls(mocker, function_name, data_file_name, args):
    data = util_load_json(f"./test_data/{data_file_name}.json")
    mock_http_request = mocker.patch.object(client.ms_client, "http_request")
    mock_http_request.return_value = data
    if args:
        result = getattr(client, function_name)(args)
    else:
        result = getattr(client, function_name)()
    assert result == data


def test_list_operations_command(mocker):
    operations_data = util_load_json('./test_data/test_list_operations_output.json')
    mocker.patch.object(client, 'list_operations', return_value=operations_data)
    command_results = list_operations_command(client)
    assert command_results.outputs[0]["Name"] == "Microsoft.ResourceGraph/operations/read"


@pytest.mark.parametrize(
    'query, data_file_name, expected_output', [
        ("Resources | project id, name, type, location, tags | limit 3",
         "test_resources_query_output",
         "test-ssh-nsg")
    ]
)
def test_query_resources_command(mocker, query, data_file_name, expected_output):
    query_data = util_load_json(f"./test_data/{data_file_name}.json")
    args: dict = {"query": query}
    mocker.patch.object(client, 'query_resources', return_value=query_data)
    command_results = query_resources_command(client, args=args)
    assert command_results.outputs[0]["name"] == expected_output


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
    from AzureResourceGraph import main, MicrosoftClient
    import AzureResourceGraph
    import demistomock as demisto

    params = {
        "auth_id": "test_client_id",
        "use_managed_identities": "True",
        "cred_token": {"password": "test"},
        "client_credentials": True,
        'host': 'https://management.azure.com',
        'tenant_id': '1abc234d-12a3-12a3-12a3-1234abcde123',
        'cred_auth_id': {'password': 'test_api'},
        'unsecure': False,
        'proxy': False,
        'private_key': 'test-key',
        'self_deployed': True,
        'enc_key': 'test',
        'subscription_id': 'test'
    }

    # operations_data = util_load_json('./test_data/test_list_operations_output.json')
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(MicrosoftClient, 'http_request', return_value=get_azure_access_token_mock())
    mocker.patch.object(AzureResourceGraph, 'return_results')

    main()

    assert "ok" in AzureResourceGraph.return_results.call_args[0][0]
