import json

import pytest

"""MOCK PARAMETERS """
CLUSTER_URL = "https://help.kusto.windows.net"
APPLICATION_ID = "xxx-xxx-xxx"
QUERY_URL_SUFFIX = "/v1/rest/query"
MANAGEMENT_URL_SUFFIX = "/v1/rest/mgmt"
CLIENT_ACTIVITY_PREFIX = "XSOAR-DataExplorerIntegation"
CLIENT_ACTIVITY_ID = "XSOAR-DataExplorer1;xxxx-xxxxx-xxxxx-xxxx"
DATABASE_NAME = "Samples"
QUERY = "test_query"


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    with open(f"test_data/{file_name}", encoding="utf-8") as mock_file:
        return mock_file.read()


def mock_client(auth_type: str = "Device Code"):
    from AzureDataExplorer import DataExplorerClient

    return DataExplorerClient(CLUSTER_URL, APPLICATION_ID, CLIENT_ACTIVITY_PREFIX, False, False, auth_type)


def test_execute_search_query_command(requests_mock):
    """
    Scenario: execute search query against given database.
    Given:
     - User has provided valid credentials.
     - Database name provided.
     - KQL query provided.
    When:
     - azure-data-explorer-execute-search-query command called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
    - Validate outputs' fields.
    """
    from AzureDataExplorer import search_query_execute_command

    mock_response = json.loads(load_mock_response("execute_query.json"))
    url = f"{CLUSTER_URL}{QUERY_URL_SUFFIX}"
    requests_mock.post("https://login.microsoftonline.com/organizations/oauth2/v2.0/token", json={})
    requests_mock.post(url, json=mock_response)
    result = search_query_execute_command(mock_client(), {"database_name": DATABASE_NAME, "query": "StormEvents | take 3"})
    outputs = result.outputs
    assert len(outputs) == 4
    assert outputs["Database"] == DATABASE_NAME
    assert outputs["Query"] == "StormEvents | take 3"
    assert outputs["PrimaryResults"][0]["StartTime"] == "2007-09-29T08:11:00"
    assert outputs["PrimaryResults"][0]["EndLocation"] == "MELBOURNE BEACH"
    assert outputs["PrimaryResults"][0]["EndLat"] == 28.0393

    assert result.outputs_prefix == "AzureDataExplorer.SearchQueryResults"


@pytest.mark.parametrize(
    "test_input,outputs_size,expected_activity,query",
    [
        ({"database_name": DATABASE_NAME}, 2, "KPC.execute;43b2bbf0-1d81-4c6d-9312-3fb93ae84d50", "StormEvents | take 10"),
        (
            {"database_name": DATABASE_NAME, "page": 2, "page_size": 1},
            1,
            "KPC.execute;463b6d97-09ef-4d06-99f8-b4ee21fc6620",
            "StormEvents | take 20",
        ),
    ],
)
def test_list_search_queries_command(test_input, outputs_size, expected_activity, query, requests_mock):
    """
    Scenario: execute search query against given database.
    Given:
     - User has provided valid credentials.
     - Database name provided.
    When:
     - azure-data-explorer-list-search-queries command called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
    - Validate outputs' fields.
    """
    from AzureDataExplorer import search_queries_list_command

    mock_response = json.loads(load_mock_response("list_completed_queries.json"))
    url = f"{CLUSTER_URL}{MANAGEMENT_URL_SUFFIX}"
    requests_mock.post(url, json=mock_response)
    requests_mock.post("https://login.microsoftonline.com/organizations/oauth2/v2.0/token", json={})
    result = search_queries_list_command(mock_client(), test_input)
    outputs = result.outputs
    assert len(outputs) == outputs_size
    assert outputs[0]["ClientActivityId"] == expected_activity
    assert outputs[0]["Text"] == query
    assert result.outputs_prefix == "AzureDataExplorer.SearchQuery"


def test_list_search_running_queries_command(requests_mock):
    """
    Scenario: execute search query against given database.
    Given:
     - User has provided valid credentials.
     - Database name provided.
    When:
     - azure-data-explorer-list-running-search-query command called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Validate outputs' fields.
    """
    from AzureDataExplorer import running_search_queries_list_command

    mock_response = json.loads(load_mock_response("list_running_queries.json"))
    url = f"{CLUSTER_URL}{MANAGEMENT_URL_SUFFIX}"
    requests_mock.post(url, json=mock_response)
    requests_mock.post("https://login.microsoftonline.com/organizations/oauth2/v2.0/token", json={})
    result = running_search_queries_list_command(mock_client(), {"database_name": DATABASE_NAME, "page": 1, "limit": 1})
    outputs = result.outputs
    assert len(outputs) == 1
    assert outputs[0]["Text"] == "set notruncation;\r\nCovid19_Bing |limit 1000000000000"
    assert outputs[0]["ClientActivityId"] == "KustoWebV2;a9f21b87-bfab-4cec-953f-3f3ba9a5dded"
    assert result.outputs_prefix == "AzureDataExplorer.RunningSearchQuery"


@pytest.mark.parametrize(
    "response_mock_file,test_input,expected_reason",
    [
        ("cancel_query.json", {"database_name": DATABASE_NAME, "client_activity_id": CLIENT_ACTIVITY_ID}, "None"),
        (
            "cancel_query_reason.json",
            {
                "database_name": DATABASE_NAME,
                "client_activity_id": CLIENT_ACTIVITY_ID,
                "reason": "Query cancelled by the user's request",
            },
            "Query cancelled by the user's request",
        ),
    ],
)
def test_cancel_running_search_query_command(response_mock_file, test_input, expected_reason, requests_mock):
    """
    Scenario: execute search query against given database.
    Given:
     - User has provided valid credentials.
     - Database name provided.
    When:
     - azure-data-explorer-cancel-running-search-query command called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
    """
    from AzureDataExplorer import running_search_query_cancel_command

    mock_response = json.loads(load_mock_response(response_mock_file))
    url = f"{CLUSTER_URL}{MANAGEMENT_URL_SUFFIX}"
    requests_mock.post(url, json=mock_response)
    requests_mock.post("https://login.microsoftonline.com/organizations/oauth2/v2.0/token", json={})

    cancel_query_result = running_search_query_cancel_command(mock_client(), test_input)
    outputs = cancel_query_result.outputs
    assert len(outputs) == 1
    assert outputs[0]["ReasonPhrase"] == expected_reason
    assert cancel_query_result.outputs_prefix == "AzureDataExplorer.CanceledSearchQuery"


def test_retrieve_common_request_body():
    """
    Scenario: Retrieve the body argument for requests call.
    Given:
     - Database name provided.
     - A response returned from the API.
    When:
     - Before every request method in AzureDataExplorer client.
    Then:
     - Ensure that the retrieved body is as expected.
    """
    from AzureDataExplorer import retrieve_common_request_body

    body = retrieve_common_request_body(DATABASE_NAME, QUERY)
    assert body["db"] == DATABASE_NAME
    assert body["csl"] == QUERY


def test_convert_kusto_response_to_dict():
    """
    Scenario: Convert kusto Response Dataset to dict object.
    Given:
     - User has provided valid credentials.
     - Database name provided.
     - A response returned from the API.
    When:
     - Following a successful API call to Azure Data Explorer API.
    Then:
     - Ensure number of items is correct.
     - Ensure that time attributes in str format
    """
    from AzureDataExplorer import convert_kusto_response_to_dict
    from azure.kusto.data.response import KustoResponseDataSetV1

    mock_response = json.loads(load_mock_response("execute_query.json"))
    kusto_format_response = KustoResponseDataSetV1(mock_response)
    dict_kusto = convert_kusto_response_to_dict(kusto_format_response, page=1, limit=1)
    assert len(dict_kusto) == 1
    assert type(dict_kusto[0]["StartTime"]) is str
    assert type(dict_kusto[0]["EndTime"]) is str


def test_format_header_for_list_commands():
    """
    Scenario: Format the header of readable output in list commands.
    Given:
        - Base command header.
        - Number retrieved results.
        - Number of total pages.
        - The client entered page number.
        - The client entered limit number.
    When:
     - azure-data-explorer-running-search-query-list command called.
     - azure-data-explorer-search-query-list command called.
    Then:
     - Ensure the header is in the right format.
    """
    from AzureDataExplorer import format_header_for_list_commands

    readable_output_header = format_header_for_list_commands("List of Completed Search Queries", 1, 1, 1, 1)

    assert (
        readable_output_header == "List of Completed Search Queries \nShowing"
        " page 1 out of 1 total pages. Current page size: 1."
    )


def test_calculate_total_request_timeout():
    """
    Scenario: Calculates total request timeout in search query execution API call.
    Given:
        - Client's server timeout argument.
    When:
     - azure-data-explorer-search-query-execution command called.
    Then:
     - Ensure total request timeout calculated correctly.
    """
    from AzureDataExplorer import calculate_total_request_timeout

    total_request_timeout = calculate_total_request_timeout(5)
    assert total_request_timeout == 320


def test_validate_list_command_arguments():
    """
    Scenario: Validation list commands optional arguments.
    Given:
        - Number retrieved results.
        - Limit number.
    When:
     - azure-data-explorer-running-search-query-list command called.
     - azure-data-explorer-search-query-list command called.
    Then:
     - Ensure that exception is raised when page number and limit number are invalid.
    """

    from AzureDataExplorer import validate_list_command_arguments

    try:
        validate_list_command_arguments(1, 0, 1)
    except ValueError as v_error:
        assert str(v_error) == "Page and limit arguments must be integers greater than 0."


@pytest.mark.parametrize(
    "auth_type, expected_results",
    [
        ("Device Code", "Please enable the integration and run `!azure-data-explorer-auth-start`"),
        ("Authorization Code", "When using user auth flow configuration, "),
    ],
)
def test_test_module_command(mocker, auth_type, expected_results):
    """
    Given:
        - Case 1: Integration params with 'Device' as auth_type.
        - Case 2: Integration params with 'User Auth' as auth_type.
    When:
        - Calling test-module command.
    Then
        - Assert the right exception was thrown.
        - Case 1: Should throw an exception related to Device-code-flow config and return True.
        - Case 2: Should throw an exception related to User-Auth-flow config and return True.
    """
    from AzureDataExplorer import test_module

    client = mock_client(auth_type)
    with pytest.raises(Exception) as e:
        test_module(client)
    assert expected_results in str(e.value)


def test_generate_login_url(mocker):
    """
    Given:
        - Self-deployed are true and auth code are the auth flow
    When:
        - Calling function azure-data-explorer-generate-login-url
    Then:
        - Ensure the generated url are as expected.
    """
    # prepare
    import demistomock as demisto
    from AzureDataExplorer import main
    import AzureDataExplorer

    redirect_uri = "redirect_uri"
    tenant_id = "tenant_id"
    client_id = "client_id"
    cluster_url = "https://help.kusto.windows.net"
    mocked_params = {
        "redirect_uri": redirect_uri,
        "cluster_url": cluster_url,
        "self_deployed": "True",
        "tenant_id": tenant_id,
        "client_id": client_id,
        "authentication_type": "Authorization Code",
        "credentials": {"identifier": client_id, "password": "client_secret"},
    }
    mocker.patch.object(demisto, "params", return_value=mocked_params)
    mocker.patch.object(demisto, "command", return_value="azure-data-explorer-generate-login-url")
    mocker.patch.object(AzureDataExplorer, "return_results")

    # call
    main()

    # assert
    expected_url = (
        f"[login URL](https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?"
        "response_type=code"
        f"&scope=offline_access%20{cluster_url}/.default"
        f"&client_id={client_id}&redirect_uri={redirect_uri})"
    )
    res = AzureDataExplorer.return_results.call_args[0][0].readable_output
    assert expected_url in res
