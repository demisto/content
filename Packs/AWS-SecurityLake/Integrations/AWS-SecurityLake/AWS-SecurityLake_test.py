import pytest
import importlib
import json
from pathlib import Path

AWSSecurityLake = importlib.import_module("AWS-SecurityLake")


class MockClient:
    def __init__(self, *args, **kwargs):
        pass

    def start_query_execution(self, *args, **kwargs):
        pass

    def stop_query_execution(self, *args, **kwargs):
        pass

    def get_query_execution(self, *args, **kwargs):
        pass

    def get_query_results(self, *args, **kwargs):
        pass
    
    def list_data_catalogs(self, *args, **kwargs):
        pass
    
    def list_databases(self, *args, **kwargs):
        pass
    
    def list_table_metadata(self, *args, **kwargs):
        pass
    
    def list_data_lakes(self, *args, **kwargs):
        pass
    
    def get_data_lake_sources(self, *args, **kwargs):
        pass
    



def load_test_data(folder: str, file_name: str) -> dict | str:
    """
    A function for loading and returning data from test files within the "test_data" folder.

    Args:
        folder (str): Name of the parent folder of the file within `test_data`.
        file_name (str): Name of a json file to load data from.

    Returns:
        dict | str: The data loaded from the file. If the file is a JSON file, a dict is returned, otherwise a string.
    """
    with open(Path("test_data") / folder / file_name) as f:
        if file_name.endswith('.json'):
            return json.load(f)

        return f.read()


def test_execute_query_command(mocker):
    client = MockClient()
    start_query_execution_mock_data = load_test_data('raw_data_mock', 'start_query_execution.json')
    mocker.patch.object(client, 'start_query_execution', return_value=start_query_execution_mock_data)
    get_query_execution_mock_data = load_test_data('raw_data_mock', 'get_query_execution.json')
    mocker.patch.object(client, 'get_query_execution', return_value=get_query_execution_mock_data)
    get_query_results_mock_data = load_test_data('raw_data_mock', 'get_query_results.json')
    mocker.patch.object(client, 'get_query_results', return_value=get_query_results_mock_data)

    args = {
        'QueryString': "SELECT * FROM test_db.test_table",
        'OutputLocation': 's3://athena-queries-test',
    }

    result = AWSSecurityLake.execute_query_command(args, client)

    expected_context_execution_details = load_test_data('expected_context', 'get_query_execution_command.json')
    expected_context_results = load_test_data('expected_context', 'get_query_results_command.json')
    expected_context = {
        'Query': expected_context_execution_details,
        'QueryResults': expected_context_results
    }
    assert result.outputs == expected_context

    expected_hr = load_test_data('expected_hr', 'get_query_results_command.txt')
    assert result.readable_output == expected_hr


    """
    Given: argument to list catalogs
    When: running list_table_metadata_command
    Then: validate that the correct values are returned.
    """
    
    client = MockClient()
    mocker.patch.object(client, 'list_data_catalogs', return_value={
    'TableMetadataList': [
        {
            'Name': 'string',
            'CreateTime': datetime(2015, 1, 1),
            'LastAccessTime': datetime(2015, 1, 1),
            'TableType': 'string',
            'Columns': [
                {
                    'Name': 'string',
                    'Type': 'string',
                    'Comment': 'string'
                },
            ],
            'PartitionKeys': [
                {
                    'Name': 'string',
                    'Type': 'string',
                    'Comment': 'string'
                },
            ],
            'Parameters': {
                'string': 'string'
            }
        },
    ],
    'NextToken': 'string'
})
    
    result = AWSSecurityLake.list_table_metadata_command(client, {})
    assert result.outputs == {'Catalog': [{'CatalogName': 'test', 'Type': 'LAMBDA'}], 'CatalogNextToken': 'test'}
    assert result.outputs_prefix == 'AWS.SecurityLake'
    assert result.outputs_key_field == 'CatalogName'

COMMANDS=[(AWSSecurityLake.list_catalogs_command, 'list_catalogs_command.json', 'CatalogName', 'list_data_catalogs'),
          (AWSSecurityLake.list_databases_command, 'list_database_command.json', 'Name', 'list_databases'),
          (AWSSecurityLake.list_table_metadata_command, 'list_table_metadata_command.json', 'Name', 'list_table_metadata'),
          (AWSSecurityLake.list_sources_command, 'list_sources_command.json', 'account', 'get_data_lake_sources'),
          (AWSSecurityLake.list_data_lakes_command, 'list_data_lakes_command.json', 'dataLakeArn', 'list_data_lakes')]
@pytest.mark.parametrize("command, file_name, output_key_field, client_command", COMMANDS)
def test_general_command(mocker, command, file_name, output_key_field, client_command):
    """
    Given: argument to command
    When: running the relevant command
    Then: validate that the correct values are returned.
    """
    
    client = MockClient()
    response = load_test_data('raw_data_mock', file_name)
    outputs = load_test_data('expected_context', file_name)
    mocker.patch.object(client, client_command, return_value=response)
    
    result = command(client, {})
    assert result.outputs == outputs
    assert result.outputs_key_field == output_key_field





