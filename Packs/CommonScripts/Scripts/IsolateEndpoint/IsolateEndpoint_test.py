from IsolateEndpoint import *
import pytest
from unittest.mock import patch


@pytest.fixture
def setup_for_test_module_manager():
    modules = {
        "module1": {"brand": "BrandA", "state": "active"},
        "module2": {"brand": "BrandB", "state": "inactive"},
    }
    brands_to_run = ["BrandA", "BrandC"]
    module_manager = ModuleManager(modules=modules, brands_to_run=brands_to_run)
    command = Command(brand="BrandA", name="TestCommand", arg_mapping={})
    return module_manager, command, modules, brands_to_run


class TestModuleManager:

    def test_is_brand_in_brands_to_run(self, setup_for_test_module_manager):
        """
        Given:
            A module manager and a command
        When:
            The command's brand is in brands_to_run
        Then:
            The is_brand_in_brands_to_run function should return True. Otherwise, False.
        """
        module_manager, command, _, _ = setup_for_test_module_manager

        assert module_manager.is_brand_in_brands_to_run(command) is True

        command.brand = "BrandB"
        assert module_manager.is_brand_in_brands_to_run(command) is False

        command.brand = "BrandC"
        assert module_manager.is_brand_in_brands_to_run(command) is True

        command.brand = "BrandD"
        assert module_manager.is_brand_in_brands_to_run(command) is False

    def test_is_brand_available(self, setup_for_test_module_manager):
        """
        Given:
            A ModuleManager instance with an enabled brand that is in the brands to run.

        When:
            is_brand_available is called with a Command for that brand.

        Then:
            The method should return True. Otherwise, False.
        """
        module_manager, command, _, _ = setup_for_test_module_manager

        assert module_manager.is_brand_available(command) is True

        command.brand = "BrandB"
        assert module_manager.is_brand_available(command) is False

        command.brand = "BrandC"
        assert module_manager.is_brand_available(command) is False

        command.brand = "BrandD"
        assert module_manager.is_brand_available(command) is False


@pytest.mark.parametrize(
    "endpoint_data, expected_output",
    [
        (
            {
                "Hostname": {"Value": "host123", "Source": "brand"},
                "ID": {"Value": "agent"},
                "IPAddress": {"Value": "8.8.1.1"},
            },
            {
                "agent_id": "agent",
                "agent_hostname": "host123",
                "agent_ip": "8.8.1.1",
                "agent_brand": "brand",
            }
        ),
        (
            {
                "Hostname": [{"Value": "host1", "Source": "brand1"}, {"Value": "host2", "Source": "brand2"}],
                "ID": [{"Value": "agent1"}, {"Value": "agent2"}],
                "IPAddress": [{"Value": "8.8.2.2"}, {"Value": "8.8.3.3"}],
            },
            {
                "agent_id": "agent1",
                "agent_hostname": "host1",
                "agent_ip": "8.8.2.2",
                "agent_brand": "brand1",
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
    assert result == expected_output, f"Failed for input: {endpoint_data}"


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
        - Different cases where `zipped_args` contain agent details that may or may not be in `valid_args`.
    When:
        - The `check_which_args_missing_in_output` function is called.
    Then:
        - It should call `create_message_to_context_and_hr` when an agent is missing.
        - It should not call `create_message_to_context_and_hr` when an agent is found.
    """
    valid_args = [
        {'agent_id': '123', 'agent_ip': '192', 'agent_hostname': 'host1'},
        {'agent_id': '789', 'agent_ip': '193', 'agent_hostname': 'host3'}
    ]
    outputs = []
    human_readable_outputs = []
    zipped_args = [
        {'agent_id': '', 'agent_ip': '194', 'agent_hostname': 'host4'},
        {'agent_id': '555', 'agent_ip': '195', 'agent_hostname': ''},
        {'agent_id': '123', 'agent_ip': '', 'agent_hostname': ''},
        {'agent_id': '', 'agent_ip': '192', 'agent_hostname': ''},
        {'agent_id': '', 'agent_ip': '', 'agent_hostname': 'host1'},
        {'agent_id': '', 'agent_ip': '192', 'agent_hostname': 'host1'},
        {'agent_id': '456', 'agent_ip': '', 'agent_hostname': 'host2'}
    ]
    check_which_args_missing_in_output(
        zipped_args, valid_args, outputs, human_readable_outputs
    )
    assert mock_create_message.call_count == 3


def test_map_zipped_args():
    """
    Given:
        Three lists of agent_ids, agent_ips, and agent_hostnames with varying lengths.
    When:
        The map_zipped_args function is called.
    Then:
        It correctly maps the elements into a list of dictionaries, filling missing values with empty strings.
    """
    agent_ids = ["123", "456"]
    agent_ips = ["192.168.1.1", "192.168.1.2"]
    agent_hostnames = ["host1", "host2"]
    expected_output = [
        {"agent_id": "123", "agent_hostname": "host1", "agent_ip": "192.168.1.1"},
        {"agent_id": "456", "agent_hostname": "host2", "agent_ip": "192.168.1.2"},
    ]
    assert map_zipped_args(agent_ids, agent_ips, agent_hostnames) == expected_output

    agent_ids = ["123"]
    agent_ips = ["192.168.1.1", "192.168.1.2"]
    agent_hostnames = ["host1"]
    expected_output = [
        {"agent_id": "123", "agent_hostname": "host1", "agent_ip": "192.168.1.1"},
        {"agent_id": "", "agent_hostname": "", "agent_ip": "192.168.1.2"},
    ]
    assert map_zipped_args(agent_ids, agent_ips, agent_hostnames) == expected_output


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
    endpoint_data = {
        "IsIsolated": {"Value": "No"},
        "Status": {"Value": "Online"}
    }

    assert is_endpoint_isolatable(endpoint_data, args={}, endpoint_output={}, human_readable_outputs=[]) is True

    endpoint_data["IsIsolated"]["Value"] = "Yes"
    assert is_endpoint_isolatable(endpoint_data, args={}, endpoint_output={}, human_readable_outputs=[]) is False

    endpoint_data["Status"]["Value"] = "Offline"
    assert is_endpoint_isolatable(endpoint_data, args={}, endpoint_output={}, human_readable_outputs=[]) is False


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
    human_readable_outputs = []
    verbose = False

    mock_is_error.return_value = True
    mock_get_error.return_value = 'Some error occurred'

    handle_raw_response_results(command, raw_response, args, outputs, human_readable_outputs, verbose)

    mock_create_message.assert_called_once_with(
        args=args,
        result='Fail',
        message='Failed to execute command TestCommand. Error:Some error occurred',
        endpoint_output=outputs,
        human_readable_outputs=human_readable_outputs,
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
        'xdr-endpoint-isolate',
        'cs-falcon-contain-host',
        'fireeye-hx-host-containment',
        'cb-edr-quarantine-device',
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
        - Endpoint data and arguments related to a specific agent.
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
    module_manager = ModuleManager(modules=modules, brands_to_run=brands_to_run)
    endpoint_data = {"id": "1234"}
    endpoint_output = {}
    human_readable_outputs = []
    results = []
    verbose = True

    args = {"agent_hostname": "host1", "agent_brand": "BrandB"}
    run_commands_for_endpoint(commands, args, module_manager, endpoint_data, endpoint_output, human_readable_outputs,
                              results, verbose)
    assert results == []

    args = {"agent_hostname": "host1", "agent_brand": "BrandA"}
    run_commands_for_endpoint(commands, args, module_manager, endpoint_data, endpoint_output, human_readable_outputs,
                              results, verbose)
    assert len(results) == 1
    assert "Result" in results[0].readable_output

    commands = [Command(brand="BrandB", name="command1", arg_mapping={})]
    run_commands_for_endpoint(commands, args, module_manager, endpoint_data, endpoint_output, human_readable_outputs,
                              results, verbose)
    assert len(results) == 1  # No new results added because module is inactive

    commands = [Command(brand="BrandA", name="command1", arg_mapping={"agent_id": "ida"})]
    run_commands_for_endpoint(commands, args, module_manager, endpoint_data, endpoint_output, human_readable_outputs,
                              results, verbose)
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
