from IsolateEndpoint import *
import pytest
from unittest.mock import patch

@pytest.mark.parametrize(
    "endpoint_data, expected_output",
    [
        (
            {
                "Hostname": "host123",
                "ID": "endpoint",
                "IPAddress": "8.8.1.1",
                "Brand": "brand",
                "Message": "Fail"
            },
            {
                "endpoint_id": "endpoint",
                "endpoint_hostname": "host123",
                "endpoint_ip": "8.8.1.1",
                "endpoint_brand": "brand",
                "endpoint_message": "Fail",
            }
        ),
    ]
)
def test_get_args_from_endpoint_data(endpoint_data, expected_output):
    """
    Given:
        Endpoint data where values are either dictionaries or lists of dictionaries.
    When:
        The get_args_from_endpoint_data function is called.
    Then:
        It extracts and returns the correct values in a structured dictionary.
    """
    result = get_args_from_endpoint_data(endpoint_data)
    assert result == expected_output


def test_structure_endpoints_data():
    """
    Given:
        Various formats of `get_endpoint_data_results`, including a dict, a list with multiple elements,
        and None values.
    When:
        The structure_endpoints_data function is called.
    Then:
        It returns a properly structured list with the expected values.
    """
    input_data = {"key": "value"}
    expected_output = [{"key": "value"}]
    assert structure_endpoints_data(input_data) == expected_output

    input_data = [None, {"key2": "value2"}]
    expected_output = [{"key2": "value2"}]
    assert structure_endpoints_data(input_data) == expected_output

    input_data = None
    expected_output = []
    assert structure_endpoints_data(input_data) == expected_output


@patch('IsolateEndpoint.create_message_to_context_and_hr')
def test_check_which_args_missing_in_output(mock_create_message):
    """
    Given:
        - Different cases where `zipped_args` contain endpoint details that may or may not be in `valid_args`.
    When:
        - The `check_which_args_missing_in_output` function is called.
    Then:
        - It should call `create_message_to_context_and_hr` when an endpoint is missing.
        - It should not call `create_message_to_context_and_hr` when an endpoint is found.
    """
    executed_args = [
        {'endpoint_id': '123', 'endpoint_ip': '192'},
        {'endpoint_id': '789', 'endpoint_ip': '193'}
    ]
    outputs = []
    zipped_args = [
        {'endpoint_id': '', 'endpoint_ip': '194'},
        {'endpoint_id': '555', 'endpoint_ip': '195'},
        {'endpoint_id': '123', 'endpoint_ip': ''},
        {'endpoint_id': '', 'endpoint_ip': '192'},
        {'endpoint_id': '', 'endpoint_ip': ''},
        {'endpoint_id': '', 'endpoint_ip': '192'},
        {'endpoint_id': '456', 'endpoint_ip': ''}
    ]
    check_missing_executed_args_in_output(
        zipped_args, executed_args, outputs
    )
    assert mock_create_message.call_count == 4


def test_map_zipped_args():
    """
    Given:
        Three lists of endpoint_ids, endpoint_ips, and endpoint_hostnames with varying lengths.
    When:
        The map_zipped_args function is called.
    Then:
        It correctly maps the elements into a list of dictionaries, filling missing values with empty strings.
    """
    endpoint_ids = ["123", "456"]
    endpoint_ips = ["192.168.1.1", "192.168.1.2"]
    expected_output = [
        {"endpoint_id": "123", "endpoint_ip": "192.168.1.1"},
        {"endpoint_id": "456", "endpoint_ip": "192.168.1.2"},
    ]
    assert map_zipped_args(endpoint_ids, endpoint_ips) == expected_output

    endpoint_ids = ["123"]
    endpoint_ips = ["192.168.1.1", "192.168.1.2"]
    expected_output = [
        {"endpoint_id": "123", "endpoint_ip": "192.168.1.1"},
        {"endpoint_id": "", "endpoint_ip": "192.168.1.2"},
    ]
    assert map_zipped_args(endpoint_ids, endpoint_ips) == expected_output


def test_map_args():
    """
    Given:
        - A Command object with `arg_mapping` defining how to map keys in `args`.
        - Optional hard-coded arguments that should be included in the output.
    When:
        - The `map_args` function is called.
    Then:
        - It correctly maps the values from `args` based on `arg_mapping`.
        - It includes hard-coded arguments in the output.
        - It returns an empty string for missing keys instead of raising an error.
    """
    base_command = Command(
        brand="test_brand",
        name="test_command",
        arg_mapping={}
    )

    base_command.arg_mapping = {"new_key1": "old_key1", "new_key2": "old_key2"}
    args = {"old_key1": "value1", "old_key2": "value2"}
    expected_output = {"new_key1": "value1", "new_key2": "value2"}
    assert map_args(base_command, args) == expected_output

    base_command.arg_mapping = {"new_key1": "old_key1", "new_key2": "missing_key"}
    args = {"old_key1": "value1"}
    expected_output = {"new_key1": "value1", "new_key2": ""}
    assert map_args(base_command, args) == expected_output

    base_command.arg_mapping = {}
    assert map_args(base_command, {}) == {}

    base_command.arg_mapping = {"new_key": "old_key"}
    assert map_args(base_command, {}) == {"new_key": ""}

    base_command.arg_mapping = {"new_key1": "old_key1"}
    base_command.hard_coded_args = {"fixed_key": "fixed_value"}
    args = {"old_key1": "value1"}
    expected_output = {"new_key1": "value1", "fixed_key": "fixed_value"}
    assert map_args(base_command, args) == expected_output


def test_are_there_missing_args():
    """
    Given:
        - A Command object with arg_mapping defining expected argument keys.
    When:
        - The function checks if all mapped arguments are missing.
    Then:
        - It correctly identifies when arguments are missing or present.
    """
    base_command = Command(
        brand="test_brand",
        name="test_command",
        arg_mapping={}
    )

    base_command.arg_mapping = {"new_key1": "old_key1", "new_key2": "old_key2"}
    args = {"old_key1": "value1", "old_key2": "value2"}
    assert are_there_missing_args(base_command, args) is False

    base_command.arg_mapping = {"new_key1": "old_key1", "new_key2": "missing_key"}
    args = {"old_key1": "value1"}
    assert are_there_missing_args(base_command, args) is False

    base_command.arg_mapping = {"new_key1": "old_key1", "new_key2": "old_key2"}
    assert are_there_missing_args(base_command, {}) is True

    base_command.arg_mapping = {}
    assert are_there_missing_args(base_command, {}) is False


def test_is_endpoint_isolatable():
    """
    Given:
        - Various endpoint data scenarios.
    When:
        - Checking if the endpoint can be isolated.
    Then:
        - Return the correct boolean value and message based on the conditions.
    """
    endpoint_data = {"IsIsolated": "No"}
    assert is_endpoint_already_isolated(endpoint_data, endpoint_args={}, endpoint_output={}) is False

    endpoint_data["IsIsolated"] = "Yes"
    assert is_endpoint_already_isolated(endpoint_data, endpoint_args={}, endpoint_output={}) is True


@patch('IsolateEndpoint.is_error')
@patch('IsolateEndpoint.get_error')
@patch('IsolateEndpoint.create_message_to_context_and_hr')
def test_handle_raw_response_results(mock_create_message, mock_get_error, mock_is_error):
    """
    Given:
        - Mocked raw response data and arguments.
    When:
        - Running the handle_raw_response_results function.
    Then:
        - Ensure the expected functions are called and errors are logged correctly for both error and success scenarios.
    """
    command = Command(brand="BrandA", name="TestCommand", arg_mapping={})
    raw_response = {'status': 'error'}
    args = {'arg1': 'value1'}
    outputs = {}
    verbose = False

    mock_is_error.return_value = True
    mock_get_error.return_value = 'Some error occurred'

    handle_raw_response_results(command, raw_response, args, outputs, verbose)

    mock_create_message.assert_called_once_with(
        args=args,
        result='Fail',
        message='Failed to execute command TestCommand. Error:Some error occurred',
        endpoint_output=outputs
    )


def test_initialize_commands():
    """
    Given:
        - The initialize_commands function is called to initialize a list of command objects.
    When:
        - Running the test_initialize_commands function to validate the list of command names.
    Then:
        - Ensure the actual command names match the expected set of command names and that no commands are missing or unexpected.
    """
    commands = initialize_commands()
    expected_command_names = {
        'core-isolate-endpoint',
        'cs-falcon-contain-host',
        'fireeye-hx-host-containment',
        'microsoft-atp-isolate-machine',
    }

    actual_command_names = {cmd.name for cmd in commands}

    assert actual_command_names == expected_command_names, f"Missing or unexpected commands: {actual_command_names}"


def test_run_commands_for_endpoint():
    """
    Given:
        - A list of command objects with specified brands and arguments.
        - A module manager with modules in different states (active and inactive).
        - A set of brands to run commands for, including valid and invalid brands.
        - Endpoint data and arguments related to a specific endpoint.
    When:
        - Running the test_run_commands_for_endpoint function with different arguments, including those that match the brand
         and others that don't.
    Then:
        - Ensure commands are only executed for matching brands (active modules).
        - Verify that results are properly added when conditions match, and that no results are added for inactive modules
         or mismatched arguments.
    """
    commands = [Command(brand="BrandA", name="command_name", arg_mapping={})]
    modules = {
        "module1": {"brand": "BrandA", "state": "active"},
        "module2": {"brand": "BrandB", "state": "inactive"},
    }
    brands_to_run = ["BrandA", "BrandC"]
    endpoint_output = {}
    results = []
    verbose = True

    args = {"endpoint_hostname": "host1", "endpoint_brand": "BrandB"}
    run_commands_for_endpoint(commands=commands, endpoint_args=args, endpoint_output=endpoint_output,
                              results=results, verbose=verbose)
    assert results == []

    args = {"endpoint_hostname": "host1", "endpoint_brand": "BrandA"}
    run_commands_for_endpoint(commands=commands, endpoint_args=args, endpoint_output=endpoint_output,
                              results=results, verbose=verbose)
    assert len(results) == 1
    assert "Result" in results[0].readable_output

    commands = [Command(brand="BrandB", name="command1", arg_mapping={})]
    run_commands_for_endpoint(commands=commands, endpoint_args=args, endpoint_output=endpoint_output,
                              results=results, verbose=verbose)
    assert len(results) == 1  # No new results added because module is inactive

    commands = [Command(brand="BrandA", name="command1", arg_mapping={"endpoint_id": "ida"})]
    run_commands_for_endpoint(commands=commands, endpoint_args=args, endpoint_output=endpoint_output,
                              results=results, verbose=verbose)
    assert len(results) == 1  # No new results added because not matching args


def test_search_and_add_endpoint_output():
    """
    Given:
        - A list of endpoint outputs with different endpoint names and results.
        - A new endpoint output that either matches an existing endpoint or is unique.
    When:
        - Adding a new endpoint output to the list.
    Then:
        - If the endpoint exists, its results should be updated by appending the new results.
        - If the endpoint does not exist, it should be added to the list.
    """

    outputs = [{"EndpointName": "endpoint_1", "Results": ["result_1"]}]

    # Adding a new endpoint that does not exist in the list
    endpoint_output = {"EndpointName": "endpoint_2", "Results": ["result_2"]}
    search_and_add_endpoint_output(outputs, endpoint_output)
    assert len(outputs) == 2

    # Updating an existing endpoint
    endpoint_output = {"EndpointName": "endpoint_1", "Results": ["result_3"]}
    search_and_add_endpoint_output(outputs, endpoint_output)
    assert len(outputs) == 2  # No new endpoint added
    assert outputs[0]["Results"] == ["result_1", "result_3"]  # Nested list issue

    # Ensuring no duplicate endpoints are added
    search_and_add_endpoint_output(outputs, endpoint_output)
    assert len(outputs) == 2  # No new endpoint added
