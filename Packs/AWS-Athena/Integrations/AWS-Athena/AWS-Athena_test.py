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
        if file_name.endswith(".json"):
            return json.load(f)

        return f.read()


def test_execute_query_command(mocker):
    client = MockClient()
    start_query_execution_mock_data = load_test_data("raw_data_mock", "start_query_execution.json")
    mocker.patch.object(client, "start_query_execution", return_value=start_query_execution_mock_data)
    get_query_execution_mock_data = load_test_data("raw_data_mock", "get_query_execution.json")
    mocker.patch.object(client, "get_query_execution", return_value=get_query_execution_mock_data)
    get_query_results_mock_data = load_test_data("raw_data_mock", "get_query_results.json")
    mocker.patch.object(client, "get_query_results", return_value=get_query_results_mock_data)

    args = {
        "QueryString": "SELECT * FROM test_db.test_table",
        "OutputLocation": "s3://athena-queries-test",
    }

    result = AWS_Athena.execute_query_command(args, client)

    expected_context_execution_details = load_test_data("expected_context", "get_query_execution_command.json")
    expected_context_results = load_test_data("expected_context", "get_query_results_command.json")
    expected_context = {"Query": expected_context_execution_details, "QueryResults": expected_context_results}
    assert result.outputs == expected_context

    expected_hr = load_test_data("expected_hr", "get_query_results_command.txt")
    assert result.readable_output == expected_hr


def test_start_query_command(mocker):
    client = MockClient()
    mock_data = load_test_data("raw_data_mock", "start_query_execution.json")
    mocker.patch.object(client, "start_query_execution", return_value=mock_data)

    args = {
        "QueryString": "SELECT * FROM test_db.test_table",
        "OutputLocation": "s3://athena-queries-test",
    }

    result = AWS_Athena.start_query_command(args, client)

    expected_context = load_test_data("expected_context", "start_query_command.json")
    assert result.outputs == expected_context


def test_get_query_execution_command(mocker):
    client = MockClient()
    mock_data = load_test_data("raw_data_mock", "get_query_execution.json")
    mocker.patch.object(client, "get_query_execution", return_value=mock_data)

    args = {"QueryExecutionId": "b3c194e7-6580-421c-81fa-4b409e1ba04f"}
    result = AWS_Athena.get_query_execution_command(args, client)

    expected_context = load_test_data("expected_context", "get_query_execution_command.json")
    assert result.outputs == expected_context


def test_get_query_results_command(mocker):
    client = MockClient()
    mock_data = load_test_data("raw_data_mock", "get_query_results.json")
    mocker.patch.object(client, "get_query_results", return_value=mock_data)

    args = {"QueryExecutionId": "b3c194e7-6580-421c-81fa-4b409e1ba04f", "polling": "false"}
    result = AWS_Athena.get_query_results_command(args, client)

    expected_context = load_test_data("expected_context", "get_query_results_command.json")
    assert result.outputs == expected_context

    expected_hr = load_test_data("expected_hr", "get_query_results_command.txt")
    assert result.readable_output == expected_hr
