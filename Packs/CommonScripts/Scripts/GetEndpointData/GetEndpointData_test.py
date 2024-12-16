import pytest
import demistomock as demisto
from CommonServerPython import CommandResults, EntryType
from GetEndpointData import *


@pytest.fixture
def setup_module_manager():
    modules = {
        "module1": {"brand": "BrandA", "state": "active"},
        "module2": {"brand": "BrandB", "state": "inactive"},
    }
    brands_to_run = ["BrandA", "BrandC"]
    module_manager = ModuleManager(modules=modules, brands_to_run=brands_to_run)
    command = Command(brand="BrandA", name="TestCommand", output_keys=[], args_mapping={}, output_mapping={})
    return module_manager, command, modules, brands_to_run

class TestModuleManager:

    def test_is_brand_in_brands_to_run(self, setup_module_manager):
        module_manager, command, _, _ = setup_module_manager

        assert module_manager.is_brand_in_brands_to_run(command) is True

        command.brand = "BrandB"
        assert module_manager.is_brand_in_brands_to_run(command) is False

        command.brand = "BrandC"
        assert module_manager.is_brand_in_brands_to_run(command) is True

        command.brand = "BrandD"
        assert module_manager.is_brand_in_brands_to_run(command) is False

    def test_is_brand_available(self, setup_module_manager):
        module_manager, command, _, _ = setup_module_manager

        assert module_manager.is_brand_available(command) is True

        command.brand = "BrandB"
        assert module_manager.is_brand_available(command) is False

        command.brand = "BrandC"
        assert module_manager.is_brand_available(command) is False

        command.brand = "BrandD"
        assert module_manager.is_brand_available(command) is False

@pytest.fixture
def setup(mocker):
    module_manager = mocker.Mock(spec=ModuleManager)
    command_runner = EndpointCommandRunner(module_manager=module_manager)
    command = Command(brand="TestBrand", name="test-command", output_keys=[], args_mapping={}, output_mapping={})
    return command_runner, module_manager, command

class TestEndpointCommandRunner:
    def test_is_command_runnable(self, setup):
        command_runner, module_manager, command = setup

        module_manager.is_brand_available.return_value = True

        args = {"arg1": "value1"}
        assert command_runner.is_command_runnable(command, args) is True

        module_manager.is_brand_available.return_value = False
        assert command_runner.is_command_runnable(command, args) is False

        module_manager.is_brand_available.return_value = True
        args = {}  # No args provided and command has no arg mapping
        assert command_runner.is_command_runnable(command, args) is True

        command.args_mapping = {'arg1': 'endpoint_arg1'}  # No args provided but command has arg mapping
        assert command_runner.is_command_runnable(command, args) is False

    def test_run_execute_command_with_list(self, mocker, setup):
        command_runner, _, command = setup

        mock_demisto_execute_command = mocker.patch.object(
            demisto,
            'executeCommand',
            return_value=[{"Type": 1, "Contents": "result"}]
        )
        result = command_runner.run_execute_command(command, {"arg1": "value1"})
        assert result == [{"Type": 1, "Contents": "result"}]
        mock_demisto_execute_command.assert_called_once_with("test-command", {"arg1": "value1"})

    def test_run_execute_command_with_dict(self, mocker, setup):
        command_runner, _, command = setup

        mock_demisto_execute_command = mocker.patch.object(
            demisto,
            'executeCommand',
            return_value={"Type": 1, "Contents": "result"}
        )
        result = command_runner.run_execute_command(command, {"arg1": "value1"})
        assert result == [{"Type": 1, "Contents": "result"}]
        mock_demisto_execute_command.assert_called_once_with("test-command", {"arg1": "value1"})

    def test_get_command_results(self, mocker, setup):
        command_runner, _,command = setup
        command_results = [
            {"EntryContext": {"key": "value"}, "HumanReadable": "Readable output", "Type": EntryType.NOTE},
            {"EntryContext": {}, "HumanReadable": "Another output", "Type": EntryType.NOTE},
            {"EntryContext": {}, "Contents": "Error output", "Type": EntryType.ERROR }  # An entry with error
        ]
        expected_context_outputs = [{"key": "value"}, {}]
        expected_human_readable = f"#### Result for !{command.name} \nReadable output\nAnother output"
        expected_error_outputs = [CommandResults(
                    readable_output=f"#### Error for !{command.name} \nError output",
                    entry_type=EntryType.ERROR,
                    mark_as_note=True,
                )]

        context_outputs, human_readable_command_results, error_outputs = command_runner.get_command_results("test-command", command_results, {})
        human_readable = human_readable_command_results[0].readable_output
        assert context_outputs == expected_context_outputs
        assert human_readable == expected_human_readable
        for expected_error_output, error_output in zip(expected_error_outputs, error_outputs):
            assert error_output.readable_output == expected_error_output.readable_output

    def test_run_command(self, mocker, setup):
        command_runner, module_manager, command = setup
        endpoint_args = {"arg1": "value1"}

        mock_prepare_args = mocker.patch('GetEndpointData.prepare_args', return_value={"arg1": "value1"})

        mock_run_execute_command = mocker.patch.object(
            command_runner,
            'run_execute_command',
            return_value=[{"Type": 1, "Contents": "result"}]
        )

        mock_get_commands_outputs = mocker.patch.object(
            command_runner,
            'get_command_results',
            return_value=(
                [{"key": "value"}],
                [{"readable_output": "Readable output"}],
                []
            )
        )

        hr, endpoints = command_runner.run_command(command, endpoint_args)
        assert hr == [{"readable_output": "Readable output"}]
        assert endpoints == []

        mock_get_commands_outputs.return_value = ([], [{"readable_output": "Readable output"}], ["Error output"])
        hr, endpoints = command_runner.run_command(command, endpoint_args)
        assert hr == ["Error output"]
        assert endpoints == []

        mock_prepare_args.assert_called_with(command, endpoint_args)
        mock_run_execute_command.assert_called()
        mock_get_commands_outputs.assert_called()

@pytest.fixture
def setup_command_runner(mocker):
    command_runner = mocker.Mock(spec=EndpointCommandRunner)
    return command_runner

def test_run_single_args_commands(mocker, setup_command_runner):
    command_runner = setup_command_runner

    # Mock inputs
    zipped_args = [
        ("agent1", "192.168.1.1", "hostname1"),
        ("agent2", "192.168.1.2", "hostname2")
    ]
    single_args_commands = [
        Command(brand="BrandA", name="command1", output_keys=[], args_mapping={}, output_mapping={}),
        Command(brand="BrandB", name="command2", output_keys=[], args_mapping={}, output_mapping={})
    ]
    verbose = True
    endpoint_outputs_list = []
    endpoints_not_found_list = []

    # Mock the run_command method
    command_runner.run_command.side_effect = [
        (["Readable output 1"], [{"key1": "value1"}]),  # First command for first agent
        (["Readable output 2"], []),  # Second command for first agent (not found)
        (["Readable output 3"], [{"key2": "value2"}]),  # First command for second agent
        (["Readable output 4"], []),  # Second command for second agent (not found)
    ]

    # Mock the merge_endpoint_outputs function
    # Returning the first element of every list to get a list of dictionaries
    mock_merge_endpoint_outputs = mocker.patch('GetEndpointData.merge_endpoint_outputs', side_effect=lambda x: x[0])

    # Call the function
    results = run_single_args_commands(
        zipped_args=zipped_args,
        single_args_commands=single_args_commands,
        command_runner=command_runner,
        verbose=verbose,
        endpoint_outputs_list=endpoint_outputs_list,
        endpoints_not_found_list=endpoints_not_found_list
    )

    # Assert results
    expected_endpoint_outputs_list = [{"key1": "value1"}, {"key2": "value2"}]
    expected_endpoints_not_found_list = [
        {'Key': 'agent1', 'Source': 'BrandB'},
        {'Key': 'agent2', 'Source': 'BrandB'}
    ]
    expected_command_results_list = ["Readable output 1", "Readable output 2", "Readable output 3", "Readable output 4"]

    assert results == (expected_endpoint_outputs_list, expected_endpoints_not_found_list, expected_command_results_list)
    assert endpoint_outputs_list == expected_endpoint_outputs_list
    assert endpoints_not_found_list == expected_endpoints_not_found_list

    # Verify run_command calls
    assert command_runner.run_command.call_count == 4

    # Verify merge_endpoint_outputs calls
    assert mock_merge_endpoint_outputs.call_count == 2

def test_run_list_args_commands(mocker, setup_command_runner):
    command_runner = setup_command_runner

    # Example data
    list_args_commands = [
        Command(brand="BrandA", name="command1", output_keys=[], args_mapping={}, output_mapping={}),
        Command(brand="BrandB", name="command2", output_keys=[], args_mapping={}, output_mapping={})
    ]
    agent_ids = ["id1", "id2"]
    agent_ips = ["192.168.1.1", "192.168.1.2"]
    agent_hostnames = ["host1", "host2"]
    zipped_args = zip(agent_ids, agent_ips, agent_hostnames)
    endpoint_outputs_list = []
    endpoints_not_found_list = []
    verbose = True

    # Mock command runner behavior
    command_runner.run_command.side_effect = [
        (["Output1"], {"result": "data1"}),  # First command returns data
        ([], None)  # Second command returns no data
    ]
    # Mock the merge_endpoint_outputs function
    mock_merge_endpoint_outputs = mocker.patch('GetEndpointData.merge_endpoint_outputs', return_value=[{"merged": "data"}])

    # Call the function
    result_outputs, result_not_found, result_readable = run_list_args_commands(
        list_args_commands,
        command_runner,
        agent_ids,
        agent_ips,
        agent_hostnames,
        zipped_args,
        endpoint_outputs_list,
        endpoints_not_found_list,
        verbose
    )

    # Assertions
    assert result_outputs == [{"merged": "data"}]
    assert result_not_found == [
        {"Key": "id1", "Source": "BrandB"},
        {"Key": "id2", "Source": "BrandB"}
    ]
    assert result_readable == ["Output1"]

    # Verify command_runner was called with correct arguments
    command_runner.run_command.assert_any_call(
        list_args_commands[0],
        {
            "agent_id": "id1,id2",
            "agent_ip": "192.168.1.1,192.168.1.2",
            "agent_hostname": "host1,host2"
        }
    )

    # Verify merge_endpoint_outputs was called correctly
    mock_merge_endpoint_outputs.assert_called_once_with([{"result": "data1"}])

def test_create_endpoint(mocker, setup_command_runner):
    # Example data
    command_output = {
        "key1": "value1",
        "key2": "value2"
    }
    output_mapping = {
        "key1": "mapped_key1"
    }
    source = "test_source"

    # Call the function
    result = create_endpoint(command_output, output_mapping, source)

    # Expected result
    expected = {
        "mapped_key1": {"Value": "value1", "Source": "test_source"},
        "key2": {"Value": "value2", "Source": "test_source"}
    }

    # Assertions
    assert result == expected

    # Test empty command_output
    assert create_endpoint({}, output_mapping, source) == {}

def test_prepare_args():

    command = Command(
        brand="BrandA",
        name="command1",
        output_keys=[],
        args_mapping={
            "cmd_arg1": "endpoint_arg1",
            "cmd_arg2": "endpoint_arg2"
        },
        output_mapping={}
    )

    # Example data
    endpoint_args = {
        "endpoint_arg1": "value1",
        "endpoint_arg2": "value2",
        "endpoint_arg3": "value3"  # Not in args_mapping
    }

    # Call the function
    result = prepare_args(command, endpoint_args)

    # Expected result
    expected = {
        "cmd_arg1": "value1",
        "cmd_arg2": "value2"
    }

    # Assertions
    assert result == expected

    # Test with missing or empty values
    endpoint_args = {
        "endpoint_arg1": "value1",
        "endpoint_arg2": "",  # Empty value
        "endpoint_arg3": None  # None value
    }

    # Call the function again
    result = prepare_args(command, endpoint_args)

    # Expected result
    expected = {
        "cmd_arg1": "value1"
    }

    # Assertions
    assert result == expected

def test_prepare_human_readable():
    # Example data
    command_name = "example-command"
    args = {
        "arg1": "value1",
        "arg2": "value2",
        "arg3": None  # None value should be ignored
    }
    human_readable = "This is a human-readable result."

    # Call the function
    result = prepare_human_readable(command_name, args, human_readable, is_error=False)

    # Expected result
    expected_command = "!example-command arg1=value1 arg2=value2"
    expected_output = f"#### Result for {expected_command}\n{human_readable}"

    # Assertions
    assert result.readable_output == expected_output
    assert result.entry_type is EntryType.NOTE
    assert result.mark_as_note is True

    # Test error case
    error_human_readable = "An error occurred."
    result = prepare_human_readable(command_name, args, error_human_readable, is_error=True)

    expected_output = f"#### Error for {expected_command}\n{error_human_readable}"

    # Assertions
    assert result.readable_output == expected_output
    assert result.entry_type == EntryType.ERROR
    assert result.mark_as_note is True

    # Test with no human_readable
    result = prepare_human_readable(command_name, args, "", is_error=False)

    # Assertions
    assert result is None

def test_get_output_key(mocker):

    # Example raw context with keys
    raw_context = {
        "key1": "value1",
        "key2(subkey)": "value2",
        "key3": "value3"
    }

    # Test case 1: Direct match
    output_key = "key1"
    result = get_output_key(output_key, raw_context)
    assert result == "key1", f"Expected 'key1', got {result}"

    # Test case 2: Matching with a nested key
    output_key = "key2"
    result = get_output_key(output_key, raw_context)
    assert result == "key2(subkey)", f"Expected 'key2(subkey)', got {result}"

    # Test case 3: No match found
    output_key = "key4"
    result = get_output_key(output_key, raw_context)
    assert result == "", f"Expected '', got {result}"

    # Test case 4: Empty raw context
    result = get_output_key("key1", {})
    assert result == "", f"Expected '', got {result}"


def test_get_outputs():
    raw_context = {
        "key1": "value1",
        "key2(subkey)": "value2",
        "key3": "value3"
    }

    # Test case 1: Direct match
    output_key = "key1"
    result = get_outputs(output_key, raw_context)
    assert result == "value1", f"Expected 'value1', got {result}"

    # Test case 2: Matching with a nested key
    output_key = "key2"
    result = get_outputs(output_key, raw_context)
    assert result == "value2", f"Expected 'value2', got {result}"

    # Test case 3: No match found
    output_key = "key4"
    result = get_outputs(output_key, raw_context)
    assert result == {}, f"Expected {{}}, got {result}"

    # Test case 4: Empty raw context
    result = get_outputs("key1", {})
    assert result == {}, f"Expected {{}}, got {result}"


@pytest.fixture
def setup_endpoints():
    return [
        {'Hostname': {'Value': 'host1'}, 'Port': {'Value': 8080}},
        {'Hostname': {'Value': 'host2'}, 'Port': {'Value': 9090}},
        {'Hostname': {'Value': 'host1'}, 'Protocol': {'Value': 'http'}},
    ]


def test_merge_no_conflicts(mocker, setup_endpoints):
    endpoints = [setup_endpoints[0], setup_endpoints[2]]
    expected_result = {
        'Hostname': [{'Value': 'host1'}, {'Value': 'host1'}],
        'Port': {'Value': 8080},
        'Protocol': {'Value': 'http'},
    }
    result = merge_endpoints(endpoints)
    assert result == expected_result


def test_merge_with_hostname_conflict(setup_endpoints, mocker):
    endpoints = setup_endpoints
    # Using pytest mocker fixture for mocking the logging functions
    mock_error = mocker.patch.object(demisto, 'error')

    result = merge_endpoints(endpoints)

    # Verify that the error is logged when hostname conflict occurs
    mock_error.assert_called_once_with(
        "Conflict detected for 'Hostname'. Conflicting dictionaries: {'Value': 'host1'}, {'Value': 'host2'}")

    # Check that the Hostname key is present in the result
    assert 'Hostname' in result  # Hostname will not merge but error out


def test_merge_with_key_conflict(setup_endpoints, mocker):
    endpoints = setup_endpoints[:3]
    expected_result = {
        'Hostname': [{'Value': 'host1'}, {'Value': 'host1'}],
        'Port': [{'Value': 9090},{'Value': 8080}],
        'Protocol': {'Value': 'http'}
    }
    mock_error = mocker.patch.object(demisto, 'error')
    result = merge_endpoints(endpoints)
    mock_error.assert_called_once_with(
        "Conflict detected for 'Hostname'. Conflicting dictionaries: {'Value': 'host1'}, {'Value': 'host2'}"
    )
    assert result['Protocol'] == {'Value': 'http'}  # Protocol merges without conflict


def test_merge_empty_endpoints():
    endpoints = []
    result = merge_endpoints(endpoints)
    assert result == {}  # Merging empty list results in an empty dictionary

def test_get_raw_endpoints(mocker):

    raw_context = [
        {
            "Device": [
                {"data from Device for object_1": "value1"},
                {"data from Device for object_2": "value3"}
            ],
            "Endpoint": [
                {"data from Endpoint for object_1": "value2"},
                {"data from Endpoint for object_2": "value4"}
            ]
        }
    ]

    mock_get_outputs = mocker.patch('GetEndpointData.get_outputs')
    mock_get_outputs.side_effect = [
        [
            {"data from Endpoint for object_1": "value2"},
            {"data from Endpoint for object_2": "value4"}
        ],
        [
            {"data from Device for object_1": "value1"},
            {"data from Device for object_2": "value3"}
        ]
    ]

    expected_output = [
        {"data from Endpoint for object_1": "value2", "data from Device for object_1": "value1"},
        {"data from Endpoint for object_2": "value4", "data from Device for object_2": "value3"},
    ]

    result = get_raw_endpoints(['Endpoint', 'Device'], raw_context)
    assert result == expected_output, f"Expected {expected_output}, got {result}"

    raw_context = [
        {
            "Endpoint": {"data from Endpoint for object_1": "value1"},
            "Device": [{"data from Device for object_1": "value2"}]
        },
        {
            "Endpoint": {"data from Endpoint for object_2": "value3"},
            "Device": [{"data from Device for object_2": "value4"}]
        },
    ]

    mock_get_outputs.side_effect = [
        {"data from Endpoint for object_1": "value1"},
        [{"data from Device for object_1": "value2"}],
        {"data from Endpoint for object_2": "value3"},
        [{"data from Device for object_2": "value4"}]
    ]

    expected_output = [
        {"data from Endpoint for object_1": "value1", "data from Device for object_1": "value2"},
        {"data from Endpoint for object_2": "value3", "data from Device for object_2": "value4"},
    ]

    result = get_raw_endpoints(['Endpoint', 'Device'], raw_context)
    assert result == expected_output, f"Expected {expected_output}, got {result}"

def test_create_endpoints(mocker):
    raw_endpoints = [
        {"key1": "value1", "key2": "value2"},
        {"key1": "value4", "key2": "value3"},
    ]
    output_mapping = {"key1": "KEY_1", "key2": "KEY_2"}
    mock_create_endopint = mocker.patch('GetEndpointData.create_endpoint')
    mock_create_endopint.side_effect = [
        {'KEY_1': {'Value': 'value1'}, 'KEY_2': {'Value': 'value2'}},
        {'KEY_1': {'Value': 'value3'}, 'KEY_2': {'Value': 'value4'}},
        {'key1_from_callable': {'Value': 'value1'}, 'key2_from_callable': {'Value': 'value2'}},
        {'key1_from_callable': {'Value': 'value3'}, 'key2_from_callable': {'Value': 'value4'}},
    ]

    result = create_endpoints(raw_endpoints, output_mapping,'brand')
    assert result == [
        {'KEY_1': {'Value': 'value1'}, 'KEY_2': {'Value': 'value2'}},
        {'KEY_1': {'Value': 'value3'}, 'KEY_2': {'Value': 'value4'}},
    ]

    output_mapping = lambda x : {'key1': 'key1_from_callable', 'key2': 'key2_from_callable'}
    create_endpoints(raw_endpoints, output_mapping,'brand')
    mock_create_endopint.assert_has_calls([
        mocker.call(
            raw_endpoints[0],
            {'key1': 'KEY_1', 'key2': 'KEY_2'},
            'brand'
        ),
        mocker.call(
            raw_endpoints[1],
            {'key1': 'KEY_1', 'key2': 'KEY_2'},
            'brand'
        ),
        mocker.call(
            raw_endpoints[0],
            {'key1': 'key1_from_callable', 'key2': 'key2_from_callable'},
            'brand'
        ),
        mocker.call(
            raw_endpoints[1],
            {'key1': 'key1_from_callable', 'key2': 'key2_from_callable'},
            'brand'
        ),
    ])

    raw_endpoints = []
    result = create_endpoints(raw_endpoints, output_mapping,'brand')
    assert result == []


def test_merge_endpoint_logic(mocker):
    # Mock the `merge_endpoints` function
    mock_merge_endpoints = mocker.patch('GetEndpointData.merge_endpoints', side_effect=lambda x: {"merged": x})
    # Mock the `safe_list_get` function
    mock_safe_list_get = mocker.patch('GetEndpointData.safe_list_get',
                                      side_effect=lambda lst, idx, default: lst[idx] if idx < len(lst) else default)

    # Example input
    endpoint_outputs = [
        [{'a': 1}, {'b': 2}],  # First endpoint list
        [{'c': 3}, {'d': 4}],  # Second endpoint list
        [{'e': 5}],  # Third endpoint list (shorter)
    ]

    # Expected output
    expected_merged = [
        {"merged": [{'a': 1}, {'c': 3}, {'e': 5}]},
        {"merged": [{'b': 2}, {'d': 4}, {}]},
    ]

    result = merge_endpoint_outputs(endpoint_outputs)

    # Assertions
    assert result == expected_merged  # Ensure the function output matches the expected result

    # Verify `safe_list_get` was called with the right arguments
    mock_safe_list_get.assert_any_call(endpoint_outputs[0], 0, {})
    mock_safe_list_get.assert_any_call(endpoint_outputs[1], 0, {})
    mock_safe_list_get.assert_any_call(endpoint_outputs[2], 1, {})

    # Verify `merge_endpoints` was called with the right arguments
    mock_merge_endpoints.assert_any_call([{'a': 1}, {'c': 3}, {'e': 5}])
    mock_merge_endpoints.assert_any_call([{'b': 2}, {'d': 4}, {}])

