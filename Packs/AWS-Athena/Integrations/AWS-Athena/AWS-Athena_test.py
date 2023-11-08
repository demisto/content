import importlib
import json
from pathlib import Path

AWS_Athena = importlib.import_module("AWS-Athena")


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


def load_test_data(folder: str, file_name: str) -> dict:
    """
    A function for loading and returning data from json files within the "test_data" folder.

    Args:
        folder (str): Name of the parent folder of the file within `test_data`.
        file_name (str): Name of a json file to load data from.

    Returns:
        dict: Dictionary data loaded from the json file.
    """
    with open(Path("test_data") / folder / f"{file_name}.json") as f:
        return json.load(f)


def test_start_query_command(mocker):
    client = MockClient()
    mock_data = load_test_data('raw_data_mock', 'start_query')
    mocker.patch.object(client, 'start_query_execution', return_value=mock_data)

    args = {'QueryString': "SELECT * FROM test_db.test_table WHERE eventDay BETWEEN "
                           "cast(date_format(current_timestamp - INTERVAL '7' day, '%Y%m%d%H') as varchar) and "
                           "cast(date_format(current_timestamp - INTERVAL '0' day, '%Y%m%d%H') as varchar) LIMIT 25",
            'OutputLocation': 's3://athena-queries-test',
            }
    result = AWS_Athena.start_query_execution_command(args, client)

    expected_context = load_test_data('expected_context', 'start_query_command')
    assert result.outputs == expected_context


def test_get_query_execution_command(mocker):
    client = MockClient()
    mock_data = load_test_data('raw_data_mock', 'get_query_execution')
    mocker.patch.object(client, 'get_query_execution', return_value=mock_data)

    args = {'QueryExecutionId': 'b3c194e7-6580-421c-81fa-4b409e1ba04f'}
    result = AWS_Athena.get_query_execution_command(args, client)

    expected_context = load_test_data('expected_context', 'get_query_execution_command')
    assert result.outputs == expected_context


def test_get_query_results_command(mocker):
    client = MockClient()
    mock_data = load_test_data('raw_data_mock', 'get_query_results')
    mocker.patch.object(client, 'get_query_results', return_value=mock_data)

    args = {'QueryExecutionId': 'b3c194e7-6580-421c-81fa-4b409e1ba04f'}
    result = AWS_Athena.get_query_results_command(args, client)

    expected_context = load_test_data('expected_context', 'get_query_results_command')
    assert result.outputs == expected_context
