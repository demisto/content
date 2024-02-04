import pytest
import importlib
import json
from pathlib import Path

AWSSecurityLake = importlib.import_module("AWSSecurityLake")


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
        "query_string": "SELECT * FROM test_db.test_table",
        "output_location": "s3://athena-queries-test",
    }

    result = AWSSecurityLake.execute_query_command(args, "QueryResults", client)

    expected_context_execution_details = load_test_data("expected_context", "get_query_execution_command.json")
    expected_context_results = load_test_data("expected_context", "get_query_results_command.json")
    expected_context = {
        "AWS.SecurityLake.Query": expected_context_execution_details,
        "AWS.SecurityLake.QueryResults": expected_context_results,
    }
    assert result.outputs == expected_context

    expected_hr = load_test_data("expected_hr", "get_query_results_command.txt")
    assert result.readable_output == expected_hr


COMMANDS = [
    (AWSSecurityLake.list_catalogs_command, "list_catalogs_command.json", "list_data_catalogs"),
    (AWSSecurityLake.list_databases_command, "list_database_command.json", "list_databases"),
    (AWSSecurityLake.list_table_metadata_command, "list_table_metadata_command.json", "list_table_metadata"),
    (AWSSecurityLake.list_sources_command, "list_sources_command.json", "get_data_lake_sources"),
    (AWSSecurityLake.list_data_lakes_command, "list_data_lakes_command.json", "list_data_lakes"),
]


@pytest.mark.parametrize("command, file_name, client_command", COMMANDS)
def test_general_command(mocker, command, file_name, client_command):
    """
    Given: argument to command
    When: running the relevant command
    Then: validate that the correct values are returned.
    """

    client = MockClient()
    response = load_test_data("raw_data_mock", file_name)
    outputs = load_test_data("expected_context", file_name)
    mocker.patch.object(client, client_command, return_value=response)

    result = command(client, {})
    assert result.outputs == outputs


QUEYRY_COMMANDS = [
    (
        AWSSecurityLake.mfalogin_query_command,
        {"database": "test_db", "table": "test_table", "user_name": "1234"},
        "SELECT * FROM test_db.test_table WHERE CAST(actor.user.name AS VARCHAR) = '1234';",
        "MfaLoginQueryResults",
    ),
    (
        AWSSecurityLake.source_ip_query_command,
        {"database": "test_db", "table": "test_table", "ip_src": "1234"},
        "SELECT * FROM test_db.test_table WHERE CAST(src_endpoint.ip AS VARCHAR) = '1234';",
        "SourceIPQueryResults",
    ),
    (
        AWSSecurityLake.guardduty_activity_query_command,
        {"database": "test_db", "table": "test_table", "severity": "Critical"},
        "SELECT * FROM test_db.test_table WHERE severity = 'Critical';",
        "GuardDutyActivityQueryResults",
    ),
]


@pytest.mark.parametrize("command, args, query, query_results_context_key", QUEYRY_COMMANDS)
def test_query_creation_commands(mocker, command, args, query, query_results_context_key):
    """
    Given: Command arguments.
    When: Running query generating command.
    Then: Validate correct values are generated when calling the execute_query_command.
    """
    client = MockClient()
    execute_command = mocker.patch.object(AWSSecurityLake, "execute_query_command")

    command(client=client, args=args)

    assert execute_command.called is True
    assert execute_command.call_args.kwargs.get("args").get("query_string") == query
    assert execute_command.call_args.kwargs.get("query_results_context_key") == query_results_context_key
