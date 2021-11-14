from CommonServerPython import *

'''MOCK PARAMETERS '''
CLUSTER_URL = "https://help.kusto.windows.net"
APPLICATION_ID = "xxx-xxx-xxx"
QUERY_URL_SUFFIX = "/v1/rest/query"
MANAGEMENT_URL_SUFFIX = "/v1/rest/mgmt"
CLIENT_ACTIVITY_PREFIX = "XSOAR-DataExplorerIntegation"


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    with open(f'test_data/{file_name}', mode='r', encoding='utf-8') as mock_file:
        return mock_file.read()


def mock_client():
    from AzureDataExplorer import DataExplorerClient
    return DataExplorerClient(CLUSTER_URL, APPLICATION_ID, CLIENT_ACTIVITY_PREFIX, False, False)


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
    mock_response = json.loads(load_mock_response('execute_query.json'))
    url = f'{CLUSTER_URL}{QUERY_URL_SUFFIX}'
    requests_mock.post("https://login.microsoftonline.com/organizations/oauth2/v2.0/token", json={})
    requests_mock.post(url, json=mock_response)
    result = search_query_execute_command(mock_client(), {
        "database_name": "Samples",
        "query": "StormEvents | take 3"
    })
    outputs = result.outputs
    assert len(outputs) == 3
    assert outputs['PrimaryResults'][0]['StartTime'] == '2007-09-29T08:11:00'
    assert outputs['PrimaryResults'][0]['EndLocation'] == 'MELBOURNE BEACH'
    assert outputs['PrimaryResults'][0]['EndLat'] == 28.0393

    assert result.outputs_prefix == 'AzureDataExplorer.SearchQueryResults'


def test_list_search_queries_command(requests_mock):
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
    mock_response = json.loads(load_mock_response('list_completed_queries.json'))
    url = f'{CLUSTER_URL}{MANAGEMENT_URL_SUFFIX}'
    requests_mock.post(url, json=mock_response)
    requests_mock.post("https://login.microsoftonline.com/organizations/oauth2/v2.0/token", json={})
    result = search_queries_list_command(mock_client(), {
        "database_name": "Samples"
    })
    outputs = result.outputs
    assert len(outputs) == 2
    assert outputs[0]['ClientActivityId'] == 'KPC.execute;43b2bbf0-1d81-4c6d-9312-3fb93ae84d50'
    assert outputs[0]['Text'] == 'StormEvents | take 10'
    assert result.outputs_prefix == 'AzureDataExplorer.SearchQuery'


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
    mock_response = json.loads(load_mock_response('list_running_queries.json'))
    url = f'{CLUSTER_URL}{MANAGEMENT_URL_SUFFIX}'
    requests_mock.post(url, json=mock_response)
    requests_mock.post("https://login.microsoftonline.com/organizations/oauth2/v2.0/token", json={})
    result = running_search_queries_list_command(mock_client(), {
        "database_name": "Samples",
        "page": 1,
        "limit": 1
    })
    outputs = result.outputs
    assert len(outputs) == 1
    assert outputs[0]['Text'] == "set notruncation;\r\nCovid19_Bing |limit 1000000000000"
    assert outputs[0]['ClientActivityId'] == 'KustoWebV2;a9f21b87-bfab-4cec-953f-3f3ba9a5dded'
    assert result.outputs_prefix == 'AzureDataExplorer.RunningSearchQuery'


def test_cancel_running_search_query_command(requests_mock):
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
    from AzureDataExplorer import running_search_queries_list_command
    mock_response = json.loads(load_mock_response('cancel_query.json'))
    url = f'{CLUSTER_URL}{MANAGEMENT_URL_SUFFIX}'
    requests_mock.post(url, json=mock_response)
    requests_mock.post("https://login.microsoftonline.com/organizations/oauth2/v2.0/token", json={})

    result = running_search_queries_list_command(mock_client(), {
        "database_name": "Samples"
    })
    outputs = result.outputs
    assert len(outputs) == 1
    assert outputs[0]['RunningQueryCanceled'] is False
    assert outputs[0]['ReasonPhrase'] == "Query cancelled by the user's request"
    assert result.outputs_prefix == 'AzureDataExplorer.RunningSearchQuery'


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

    mock_response = json.loads(load_mock_response('execute_query.json'))
    kusto_format_response = KustoResponseDataSetV1(mock_response)
    dict_kusto = convert_kusto_response_to_dict(kusto_format_response, page=1, limit=1)
    assert len(dict_kusto) == 1
    assert type(dict_kusto[0]['StartTime']) == str
    assert type(dict_kusto[0]['EndTime']) == str
