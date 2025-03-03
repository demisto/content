import json
import os
import pytest

from AzureResourceGraph import AzureResourceGraphClient, list_operations_command, query_resources_command, pagination


client = AzureResourceGraphClient(base_url="url", tenant_id="tenant", auth_id="auth_id", enc_key="enc_key",
                                  app_name="APP_NAME", verify="verify", proxy="proxy", self_deployed="self_deployed",
                                  ok_codes=(1, 2), server="server", certificate_thumbprint='', private_key='')


''' HELPER FUNCTIONS '''


def util_load_json(path):
    full_path = os.path.join(os.path.dirname(__file__), path)
    with open(file=full_path, encoding='utf-8') as f:
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
    "function_name, data_file_name, args, additional_args", [
        ("list_operations", "test_list_operations_output", None, None),
        ("query_resources", "test_resources_query_output", {"query": "dummy"}, {"paging_options": "dummy",
                                                                                "subscriptions": "dummy",
                                                                                "management_groups": "dummy"})
    ]
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


@pytest.mark.parametrize("limit, page_size, page_number, expected_number_of_operations, expected_first_name",
                         [(1, None, None, 1, "Microsoft.ResourceGraph/operations/read"),
                          (3, 2, 2, 2, "Microsoft.ResourceGraph/resourcesHistory/read")])
def test_successful_list_operations_command(mocker, limit, page_size, page_number,
                                            expected_number_of_operations, expected_first_name):
    operations_data = util_load_json('test_data/test_list_operations_output.json')
    mocker.patch.object(client, 'list_operations', return_value=operations_data)
    args: dict = {"limit": limit, "page": page_number, "page_size": page_size}
    command_results = list_operations_command(client, args)
    assert command_results.outputs[0]["Name"] == expected_first_name
    assert len(command_results.outputs) == expected_number_of_operations


@pytest.mark.parametrize("limit, page_size, page_number, expected_error_message",
                         [(None, None, 2, "Please enter a value for \"page_size\" when using \"page\"."),
                          (None, 2, None, "Please enter a value for \"page\" when using \"page_size\".")])
def test_failure_list_operations_command(mocker, limit, page_size, page_number, expected_error_message):
    try:
        operations_data = util_load_json('test_data/test_list_operations_output.json')
        mocker.patch.object(client, 'list_operations', return_value=operations_data)
        args: dict = {"limit": limit, "page": page_number, "page_size": page_size}
        list_operations_command(client, args)
    except Exception as e:
        assert e.message == expected_error_message


@pytest.mark.parametrize(
    'query, data_file_name, expected_output', [
        ("Resources | project id, name, type, location, tags | limit 3",
         "test_resources_query_output",
         "test-ssh-nsg")
    ]
)
def test_query_resources_command_output(mocker, query, data_file_name, expected_output):
    query_data = util_load_json(f"test_data/{data_file_name}.json")
    args: dict = {"query": query, 'limit': 1}
    mocker.patch.object(client, 'query_resources', return_value=query_data)
    command_results = query_resources_command(client, args=args)
    assert command_results.outputs[0]["name"] == expected_output


@pytest.mark.parametrize(
    'query, data_file_name, extra_args, expected_length, expected_name', [
        ("Resources | project id, name, type, location, tags",
         "test_resources_query_paging_output",
         {'page': 1, 'page_size': 3},
         3,
         "test-ssh-nsg-2")
    ]
)
def test_query_resources_command_paging(mocker, query, data_file_name, extra_args, expected_length, expected_name):
    query_data = util_load_json(f"test_data/{data_file_name}.json")
    args: dict = {"query": query}
    args.update(extra_args)
    mocker.patch.object(client, 'query_resources', return_value=query_data)
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
    }

    # operations_data = util_load_json('./test_data/test_list_operations_output.json')
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(MicrosoftClient, 'http_request', return_value=get_azure_access_token_mock())
    mocker.patch.object(AzureResourceGraph, 'return_results')

    main()

    assert "ok" in AzureResourceGraph.return_results.call_args[0][0]
