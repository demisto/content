from IsolateEndpoint import *
import pytest
from unittest.mock import patch


@pytest.mark.parametrize(
    "endpoint_data, expected_output",
    [
        (
            {"Hostname": "host123", "ID": "endpoint", "IPAddress": "8.8.1.1", "Brand": "brand", "Message": "Fail"},
            {
                "endpoint_id": "endpoint",
                "endpoint_hostname": "host123",
                "endpoint_ip": "8.8.1.1",
                "endpoint_brand": "brand",
                "endpoint_message": "Fail",
            },
        ),
    ],
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


@patch("IsolateEndpoint.create_message_to_context_and_hr")
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
    executed_args = [{"endpoint_id": "123", "endpoint_ip": "192"}, {"endpoint_id": "789", "endpoint_ip": "193"}]
    outputs = []
    zipped_args = [
        {"endpoint_id": "", "endpoint_ip": "194"},
        {"endpoint_id": "555", "endpoint_ip": "195"},
        {"endpoint_id": "123", "endpoint_ip": ""},
        {"endpoint_id": "", "endpoint_ip": "192"},
        {"endpoint_id": "", "endpoint_ip": ""},
        {"endpoint_id": "", "endpoint_ip": "192"},
        {"endpoint_id": "456", "endpoint_ip": ""},
    ]
    check_missing_executed_args_in_output(zipped_args, executed_args, outputs)
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
    base_command = Command(brand="test_brand", name="test_command", arg_mapping={})

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
    base_command = Command(brand="test_brand", name="test_command", arg_mapping={})

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


@patch("IsolateEndpoint.is_error")
@patch("IsolateEndpoint.get_error")
@patch("IsolateEndpoint.create_message_to_context_and_hr")
def test_handle_raw_response_results(mock_create_message, mock_get_error, mock_is_error):
    """
    Given:
        - Mocked raw response data and arguments.
    When:
        - Running the handle_raw_response_results function.
    Then:
        - Ensure the expected functions are called and messages are correct for both error and success scenarios.
    """
    command = Command(brand="BrandA", name="TestCommand", arg_mapping={})
    args = {"endpoint_id": "1234"}
    outputs = {}
    verbose = False

    mock_is_error.return_value = True
    mock_get_error.return_value = "Some error occurred"

    handle_raw_response_results(command, {"status": "error"}, args, outputs, verbose)

    expected_error_message = "Failed to isolate 1234 with command TestCommand.Error:Some error occurred"

    mock_create_message.assert_called_once_with(
        is_isolated=False,
        endpoint_args=args,
        result="Fail",
        message=expected_error_message,
        endpoint_output=outputs,
    )

    mock_create_message.reset_mock()

    mock_is_error.return_value = False
    outputs.clear()

    handle_raw_response_results(command, {"status": "ok"}, args, outputs, verbose)

    expected_success_message = "1234 was isolated successfully with command TestCommand."

    mock_create_message.assert_called_once_with(
        is_isolated=True,
        endpoint_args=args,
        result="Success",
        message=expected_success_message,
        endpoint_output=outputs,
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
        "core-isolate-endpoint",
        "cs-falcon-contain-host",
        "fireeye-hx-host-containment",
        "microsoft-atp-isolate-machine",
    }

    actual_command_names = {cmd.name for cmd in commands}

    assert actual_command_names == expected_command_names, f"Missing or unexpected commands: {actual_command_names}"


def test_find_command_by_brand():
    """
    Given:
        - A list of Command objects with different brand names.
    When:
        - Calling the find_command_by_brand function with the brand 'BrandB'.
    Then:
        - Ensure the function returns the Command object with brand 'BrandB'.
    """
    command_a = Command(brand="BrandA", name="command-a", arg_mapping={})
    command_b = Command(brand="BrandB", name="command-b", arg_mapping={})
    result = find_command_by_brand(commands=[command_a, command_b], brand="BrandB")
    assert result == command_b


@patch("IsolateEndpoint.create_message_to_context_and_hr")
def test_check_inputs_for_command_missing_args(mock_create_message):
    command = Command(brand="BrandA", name="command", arg_mapping={"arg1": "mapped_arg1"})
    args = {"mapped_arg1": ""}
    result = check_inputs_for_command(command, endpoint_output={}, args=args)
    assert result is False
    assert mock_create_message.called

    args = {"mapped_arg1": "val"}
    result = check_inputs_for_command(command, endpoint_output={}, args=args)
    assert result is True


def test_create_message_to_context_and_hr_success_case():
    endpoint_args = {"endpoint_id": "1234", "endpoint_brand": "SomeBrand"}
    endpoint_output = {}
    create_message_to_context_and_hr(
        is_isolated=True,
        endpoint_args=endpoint_args,
        result="Success",
        message="Test Message",
        endpoint_output=endpoint_output,
    )

    expected = {
        "Endpoint": "1234",
        "Result": "Success",
        "Source": "SomeBrand",
        "Message": "Test Message",
        "Isolated": "Yes",
    }
    assert endpoint_output == expected


@patch("IsolateEndpoint.demisto.executeCommand")
@patch("IsolateEndpoint.handle_raw_response_results")
def test_run_commands_for_endpoint_executes_command(mock_handle_response, mock_execute):
    command = Command(brand="TestBrand", name="test-command", arg_mapping={"arg1": "arg1"})
    mock_commands = [command]

    mock_execute.return_value = [{"Type": 1, "Contents": "Done"}]
    mock_handle_response.return_value = "CommandResult"

    endpoint_args = {"arg1": "value", "endpoint_brand": "TestBrand"}
    results = []

    run_commands_for_endpoint(mock_commands, endpoint_args, {}, results, verbose=False)

    mock_execute.assert_called_once()
    mock_handle_response.assert_called_once()
    assert "CommandResult" in results
