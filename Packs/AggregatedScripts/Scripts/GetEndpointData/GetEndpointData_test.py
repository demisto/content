from pytest_mock import MockerFixture
import pytest
from CommonServerPython import CommandResults, EntryType
from GetEndpointData import *


@pytest.fixture
def setup_for_test_module_manager():
    modules = {
        "module1": {"brand": "BrandA", "state": "active"},
        "module2": {"brand": "BrandB", "state": "inactive"},
    }
    brands_to_run = ["BrandA", "BrandC"]
    module_manager = ModuleManager(modules=modules, brands_to_run=brands_to_run)
    command = Command(brand="BrandA", name="TestCommand", output_keys=[], args_mapping={"id": "endpoint_id"}, output_mapping={})
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


@pytest.fixture
def setup(mocker):
    module_manager = mocker.Mock(spec=ModuleManager)
    command_runner = EndpointCommandRunner(module_manager=module_manager, add_additional_fields=False)
    command = Command(
        brand="TestBrand", name="test-command", output_keys=["output_key"], args_mapping={"id": "endpoint_id"}, output_mapping={}
    )
    return command_runner, module_manager, command


class TestEndpointCommandRunner:
    def test_is_command_runnable(self, setup, mocker):
        """
        Given:
            A command with different availability and argument scenarios.
        When:
            The is_command_runnable function is called with various conditions.
        Then:
            The function should return True when conditions are met, False otherwise.
        """
        command_runner, module_manager, command = setup

        # Mock debug to avoid actual logging
        mocker.patch("GetEndpointData.demisto.debug")

        # Command's brand is not available.
        module_manager.is_brand_available.return_value = False
        assert command_runner.is_command_runnable(command, {}) is False

        # No args provided but command has arg mapping
        command.args_mapping = {"arg1": "endpoint_arg1"}
        assert command_runner.is_command_runnable(command, {}) is False

        # Args are provided, command has args mapping, but brand is not available.
        args = {"endpoint_arg1": "value_1"}
        command.args_mapping = {"arg1": "endpoint_arg1"}
        assert command_runner.is_command_runnable(command, {}) is False

        # Args are provided, command has args mapping, and brand is available.
        module_manager.is_brand_available.return_value = True
        assert command_runner.is_command_runnable(command, args) is True

    def test_get_command_results(self, setup):
        """
        Given:
            Command outputs with various entry contexts and error types.
        When:
            The get_command_results function is called with those outputs.
        Then:
            The function should properly separate context outputs, readable outputs, and error outputs.
        """
        command_runner, _, command = setup
        command_results = [
            {"EntryContext": {"key": "value"}, "HumanReadable": "Readable output", "Type": EntryType.NOTE},
            {"EntryContext": {}, "HumanReadable": "Another output", "Type": EntryType.NOTE},
            {"EntryContext": {}, "Contents": "Error output", "Type": EntryType.ERROR},  # An entry with error
        ]
        expected_context_outputs = [{"key": "value"}, {}]
        expected_human_readable = f"#### Result for !{command.name} \nReadable output\nAnother output"
        expected_error_outputs = [
            CommandResults(
                readable_output=f"#### Error for !{command.name} \nError output",
                entry_type=EntryType.ERROR,
                mark_as_note=True,
            )
        ]

        context_outputs, human_readable_command_results, error_outputs = command_runner.get_command_results(
            "test-command", command_results, {}
        )
        human_readable = human_readable_command_results[0].readable_output
        assert context_outputs == expected_context_outputs
        assert human_readable == expected_human_readable
        for expected_error_output, error_output in zip(expected_error_outputs, error_outputs):
            assert error_output.readable_output == expected_error_output.readable_output

    def test_run_command_not_runnable(self, setup, mocker):
        """
        Given:
            A command that is not runnable due to brand unavailability.
        When:
            The run_command function is called with that command.
        Then:
            The run_command function returns two empty lists.
        """
        command_runner, module_manager, command = setup

        # Mock debug to avoid actual logging
        mocker.patch("GetEndpointData.demisto.debug")

        # command is not runnable
        module_manager.is_brand_available.return_value = False
        hr, endpoints = command_runner.run_command(command, {})
        assert hr == []
        assert endpoints == []

    def test_run_command_empty_outputs(self, mocker, setup):
        """
        Given:
            A command that returns empty outputs from execution.
        When:
            The run_command method is called and the command returns empty values.
        Then:
            The run_command function returns error results and empty endpoints list.
        """
        command_runner, module_manager, command = setup
        endpoint_args = {"endpoint_id": "value1"}

        # Mock brand availability and debug
        module_manager.is_brand_available.return_value = True
        mocker.patch("GetEndpointData.demisto.debug")

        # Mock prepare_args to return valid args
        mocker.patch("GetEndpointData.prepare_args", return_value={"id": "value1"})

        # Mock run_execute_command to return empty list
        mock_run_execute_command = mocker.patch.object(command_runner, "run_execute_command", return_value=[])

        # Mock get_command_results to return empty context and error results
        error_result = CommandResults(readable_output="No results found")
        mock_get_command_results = mocker.patch.object(
            command_runner, "get_command_results", return_value=([], [], [error_result])
        )

        # Mock get_endpoint_not_found
        mocker.patch("GetEndpointData.get_endpoint_not_found", return_value=[])

        hr, endpoints = command_runner.run_command(command, endpoint_args)
        assert hr == [error_result]
        assert endpoints == []

        mock_run_execute_command.assert_called_once()
        mock_get_command_results.assert_called_once()

    def test_run_command_normal_outputs(self, mocker, setup):
        """
        Given:
            A command that returns normal output values.
        When:
            The run_command method is called and the command returns normal values.
        Then:
            The run_command function returns the readable output and properly structured endpoints.
        """
        command_runner, module_manager, command = setup
        endpoint_args = {"endpoint_id": "value1"}

        # Mock brand availability and debug
        module_manager.is_brand_available.return_value = True
        mocker.patch("GetEndpointData.demisto.debug")

        # Mock prepare_args
        mocker.patch("GetEndpointData.prepare_args", return_value={"id": "value1"})

        # Mock run_execute_command
        mock_run_execute_command = mocker.patch.object(
            command_runner, "run_execute_command", return_value=[{"Type": 1, "Contents": "result"}]
        )

        # Mock get_command_results
        readable_result = CommandResults(readable_output="Readable output")
        mock_get_command_results = mocker.patch.object(
            command_runner,
            "get_command_results",
            return_value=([{"output_key": {"key": "value"}}], [readable_result], []),
        )

        # Mock entry_context_to_endpoints
        expected_endpoint = {"key": {"Source": "TestBrand", "Value": "value"}}
        mocker.patch("GetEndpointData.entry_context_to_endpoints", return_value=[expected_endpoint])

        # Mock get_endpoint_not_found
        mocker.patch("GetEndpointData.get_endpoint_not_found", return_value=[])

        hr, endpoints = command_runner.run_command(command, endpoint_args)

        assert hr == [readable_result]
        assert endpoints == [expected_endpoint]

        mock_run_execute_command.assert_called_once()
        mock_get_command_results.assert_called_once()

    def test_run_command_error_outputs(self, mocker, setup):
        """
        Given:
            A command that returns error outputs.
        When:
            The run_command method is called and the command returns an error output.
        Then:
            The run_command function returns the readable error and an empty endpoint list.
        """
        command_runner, module_manager, command = setup
        endpoint_args = {"endpoint_id": "value1"}

        # Mock brand availability and debug
        module_manager.is_brand_available.return_value = True
        mocker.patch("GetEndpointData.demisto.debug")

        # Mock prepare_args
        mocker.patch("GetEndpointData.prepare_args", return_value={"id": "value1"})

        # Mock run_execute_command
        mock_run_execute_command = mocker.patch.object(command_runner, "run_execute_command", return_value=["Error output"])

        # Mock get_command_results to return error
        error_result = CommandResults(readable_output="Error output")
        mock_get_command_results = mocker.patch.object(
            command_runner, "get_command_results", return_value=([], [], [error_result])
        )

        # Mock get_endpoint_not_found
        mocker.patch("GetEndpointData.get_endpoint_not_found", return_value=[])

        hr, endpoints = command_runner.run_command(command, endpoint_args)
        assert hr == [error_result]
        assert endpoints == []

        mock_run_execute_command.assert_called_once()
        mock_get_command_results.assert_called_once()


def test_is_private_ip():
    """
    Given:
        Various IPv4 addresses including private ranges, public addresses, and invalid formats.
    When:
        The is_private_ip function is called with these different address types.
    Then:
        It should correctly identify private IP addresses and return False for public or invalid addresses.
    """
    # Test Class A private range (10.0.0.0 - 10.255.255.255)
    assert is_private_ip("10.0.0.0") is True
    assert is_private_ip("10.255.255.255") is True
    assert is_private_ip("10.123.45.67") is True

    # Test Class B private range (172.16.0.0 - 172.31.255.255)
    assert is_private_ip("172.16.0.0") is True
    assert is_private_ip("172.31.255.255") is True
    assert is_private_ip("172.20.10.5") is True

    # Test Class C private range (192.168.0.0 - 192.168.255.255)
    assert is_private_ip("192.168.0.0") is True
    assert is_private_ip("192.168.255.255") is True
    assert is_private_ip("192.168.1.100") is True

    # Test loopback range (127.0.0.0 - 127.255.255.255)
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("127.255.255.255") is True
    assert is_private_ip("127.100.50.25") is True

    # Test link-local range (169.254.0.0 - 169.254.255.255)
    assert is_private_ip("169.254.0.0") is True
    assert is_private_ip("169.254.255.255") is True
    assert is_private_ip("169.254.100.200") is True

    # Test public IP addresses
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False
    assert is_private_ip("172.15.255.255") is False  # Just outside Class B private
    assert is_private_ip("172.32.0.0") is False  # Just outside Class B private
    assert is_private_ip("192.167.255.255") is False  # Just outside Class C private
    assert is_private_ip("9.255.255.255") is False  # Just outside Class A private
    assert is_private_ip("11.0.0.0") is False  # Just outside Class A private
    assert is_private_ip("203.0.113.1") is False  # Public address

    # Test invalid IP formats
    assert is_private_ip("256.1.1.1") is False  # Invalid octet > 255
    assert is_private_ip("10.256.1.1") is False  # Invalid octet > 255
    assert is_private_ip("10.1.1") is False  # Missing octet
    assert is_private_ip("10.1.1.1.1") is False  # Too many octets
    assert is_private_ip("abc.def.ghi.jkl") is False  # Non-numeric
    assert is_private_ip("") is False  # Empty string
    assert is_private_ip("10.1.1.1/24") is False  # CIDR notation


@pytest.fixture
def setup_command_runner(mocker: MockerFixture):
    command_runner = mocker.Mock(spec=EndpointCommandRunner)
    return command_runner


def test_run_single_args_commands_with_results(mocker: MockerFixture, setup_command_runner):
    """
    Given:
        A list of zipped endpoint arguments and single argument commands that return results.
    When:
        The run_single_args_commands function is called with verbose mode enabled.
    Then:
        It should return the aggregated endpoint outputs, command results from all commands and endpoint mapping.
    """
    # Setup mock command runner
    mock_command_runner = setup_command_runner
    endpoint_mapping = {
        "id2": {"ID": "id2", "Hostname": "host2", "Message": "Command successful", "Brand": Brands.CORTEX_CORE_IR}
    }
    # Setup test data
    zipped_args = [("id1", "192.168.1.1", "host1"), ("id2", "192.168.1.2", "host2")]
    single_args_commands = [
        Command(
            brand=Brands.ACTIVE_DIRECTORY_QUERY_V2,
            name="test-command-1",
            output_keys=[],
            args_mapping={"id": "endpoint_id"},
            output_mapping={},
        ),
        Command(
            brand=Brands.CORTEX_CORE_IR,
            name="test-command-2",
            output_keys=[],
            args_mapping={"hostname": "endpoint_hostname"},
            output_mapping={},
        ),
    ]

    # Mock command runner responses
    mock_command_runner.run_command.side_effect = [
        (
            ["Readable output 1"],
            [{"ID": "id1", "Hostname": "host1", "Message": "Command successful", "Brand": Brands.ACTIVE_DIRECTORY_QUERY_V2}],
        ),  # First command, first endpoint
        (["Readable output 2"], []),  # Second command, first endpoint (no results)
        (
            ["Readable output 3"],
            [{"ID": "id2", "Status": "Active", "Message": "Command successful", "Brand": Brands.FIREEYE_HX_V2}],
        ),  # First command, second endpoint
        (
            ["Readable output 4"],
            [
                {
                    "ID": "id2",
                    "Status": "Active",
                    "Hostname": "host2",
                    "Message": "Command successful",
                    "Brand": Brands.CORTEX_CORE_IR,
                    "RiskLevel": "Medium",
                }
            ],
        ),  # Second command, second endpoint
    ]

    # Mock debug function
    mock_debug = mocker.patch("GetEndpointData.demisto.debug")

    # Call the function
    endpoint_outputs, command_results = run_single_args_commands(
        zipped_args=zipped_args,
        single_args_commands=single_args_commands,
        command_runner=mock_command_runner,
        verbose=True,
        ir_mapping=endpoint_mapping,
    )

    # Assertions
    expected_endpoint_outputs = [
        {
            "ID": "id1",
            "Hostname": "host1",
            "Message": "Command successful",
            "Brand": Brands.ACTIVE_DIRECTORY_QUERY_V2,
        },
        {
            "ID": "id2",
            "Status": "Active",
            "Message": "Command successful",
            "Brand": Brands.FIREEYE_HX_V2,
        },
    ]
    expected_command_results = ["Readable output 1", "Readable output 2", "Readable output 3", "Readable output 4"]

    expected_endpoint_mapping = {
        "id2": {
            "ID": "id2",
            "Hostname": "host2",
            "Message": "Command successful",
            "Brand": Brands.CORTEX_CORE_IR,
            "RiskLevel": "Medium",
        }
    }

    assert endpoint_mapping == expected_endpoint_mapping
    assert endpoint_outputs == expected_endpoint_outputs
    assert command_results == expected_command_results
    assert mock_command_runner.run_command.call_count == 4
    mock_debug.assert_called_with("ending single arg loop with 2 new endpoints")


def test_run_single_args_commands_verbose_false(mocker: MockerFixture, setup_command_runner):
    """
    Given:
        A list of zipped endpoint arguments and single argument commands with verbose mode disabled.
    When:
        The run_single_args_commands function is called.
    Then:
        It should return endpoint outputs but empty command results list due to verbose being false.
    """
    # Setup mock command runner
    mock_command_runner = setup_command_runner
    endpoint_mapping = {}

    # Setup test data
    zipped_args = [("id1", "192.168.1.1", "host1")]
    single_args_commands = [
        Command(brand="TestBrand", name="test-command", output_keys=[], args_mapping={"id": "endpoint_id"}, output_mapping={})
    ]

    # Mock command runner response
    mock_command_runner.run_command.return_value = (["Readable output"], [{"ID": "id1"}])

    # Mock debug function
    mock_debug = mocker.patch("GetEndpointData.demisto.debug")

    # Call the function
    endpoint_outputs, command_results = run_single_args_commands(
        zipped_args=zipped_args,
        single_args_commands=single_args_commands,
        command_runner=mock_command_runner,
        verbose=False,
        ir_mapping=endpoint_mapping,
    )

    # Assertions
    assert endpoint_outputs == [{"ID": "id1"}]
    assert command_results == []  # Should be empty when verbose=False
    assert mock_command_runner.run_command.call_count == 1
    mock_debug.assert_called_with("ending single arg loop with 1 new endpoints")


def test_run_single_args_commands_no_endpoints_found(mocker: MockerFixture, setup_command_runner):
    """
    Given:
        A list of zipped endpoint arguments and single argument commands that return no endpoint results.
    When:
        The run_single_args_commands function is called.
    Then:
        It should return empty endpoint outputs list but still include command results if verbose is enabled.
    """
    # Setup mock command runner
    mock_command_runner = setup_command_runner
    endpoint_mapping = {}

    # Setup test data
    zipped_args = [("id1", "192.168.1.1", "host1")]
    single_args_commands = [
        Command(brand="TestBrand", name="test-command", output_keys=[], args_mapping={"id": "endpoint_id"}, output_mapping={})
    ]

    # Mock command runner response - no endpoints found
    mock_command_runner.run_command.return_value = (["No results found"], [])

    # Mock debug function
    mock_debug = mocker.patch("GetEndpointData.demisto.debug")

    # Call the function
    endpoint_outputs, command_results = run_single_args_commands(
        zipped_args=zipped_args,
        single_args_commands=single_args_commands,
        command_runner=mock_command_runner,
        verbose=True,
        ir_mapping=endpoint_mapping,
    )

    # Assertions
    assert endpoint_outputs == []
    assert command_results == ["No results found"]
    assert mock_command_runner.run_command.call_count == 1
    mock_debug.assert_called_once_with("ending single arg loop with 0 new endpoints")


def test_run_single_args_commands_empty_inputs(mocker: MockerFixture, setup_command_runner):
    """
    Given:
        Empty zipped arguments or empty single argument commands list.
    When:
        The run_single_args_commands function is called.
    Then:
        It should return empty lists for both endpoint outputs and command results.
    """
    # Setup mock command runner
    mock_command_runner = setup_command_runner
    endpoint_mapping = {}

    # Mock debug function
    mock_debug = mocker.patch("GetEndpointData.demisto.debug")

    # Test with empty zipped_args
    endpoint_outputs, command_results = run_single_args_commands(
        zipped_args=[],
        single_args_commands=[
            Command(brand="Test", name="test", output_keys=[], args_mapping={"id": "endpoint_id"}, output_mapping={})
        ],
        command_runner=mock_command_runner,
        verbose=True,
        ir_mapping=endpoint_mapping,
    )

    assert endpoint_outputs == []
    assert command_results == []
    assert mock_command_runner.run_command.call_count == 0
    mock_debug.assert_called_once_with("ending single arg loop with 0 new endpoints")

    # Reset mock
    mock_command_runner.reset_mock()
    mock_debug.reset_mock()

    # Test with empty commands
    endpoint_outputs, command_results = run_single_args_commands(
        zipped_args=[("id1", "ip1", "host1")],
        single_args_commands=[],
        command_runner=mock_command_runner,
        verbose=True,
        ir_mapping=endpoint_mapping,
    )

    assert endpoint_outputs == []
    assert command_results == []
    assert mock_command_runner.run_command.call_count == 0
    mock_debug.assert_called_once_with("ending single arg loop with 0 new endpoints")


def test_create_endpoint_with_endpoint_output():
    """
    Given:
        Command output and endpoint output with overlapping keys in the output mapping.
    When:
        The create_endpoint function is called with both command_output and endpoint_output provided.
    Then:
        It should prioritize endpoint_output values over command_output and include command_output in
            AdditionalFields when add_additional_fields is True.
    """
    command_output = {"host_name": "from_command", "extra_field": "extra_value", "cpu_count": 4}
    endpoint_output = {"host_name": "from_endpoint", "ip_addr": "192.168.1.1"}
    output_mapping = {"host_name": "Hostname", "ip_addr": "IPAddress"}
    brand = "TestBrand"

    result = create_endpoint(command_output, output_mapping, brand, add_additional_fields=True, endpoint_output=endpoint_output)

    expected = {
        "Message": COMMAND_SUCCESS_MSG,
        "Hostname": "from_endpoint",  # Should use value from endpoint_output
        "IPAddress": "192.168.1.1",  # Should use value from endpoint_output
        "Brand": "TestBrand",
        "AdditionalFields": command_output,  # Should include entire command_output as additional fields
    }

    assert result == expected


def test_create_endpoint_with_endpoint_output_no_additional_fields():
    """
    Given:
        Command output and endpoint output with mapped keys and add_additional_fields set to False.
    When:
        The create_endpoint function is called with endpoint_output provided.
    Then:
        It should use only the mapped values from endpoint_output and not include any additional fields from command_output.
    """
    command_output = {"host_name": "from_command", "extra_field": "extra_value"}
    endpoint_output = {"host_name": "from_endpoint", "ip_addr": "192.168.1.1"}
    output_mapping = {"host_name": "Hostname", "ip_addr": "IPAddress"}
    brand = "TestBrand"

    result = create_endpoint(command_output, output_mapping, brand, add_additional_fields=False, endpoint_output=endpoint_output)

    expected = {"Message": COMMAND_SUCCESS_MSG, "Hostname": "from_endpoint", "IPAddress": "192.168.1.1", "Brand": "TestBrand"}

    assert result == expected
    assert "AdditionalFields" not in result


def test_create_endpoint_with_endpoint_output_unmapped_keys():
    """
    Given:
        Endpoint output containing keys that are not present in the output mapping.
    When:
        The create_endpoint function is called with endpoint_output having unmapped keys.
    Then:
        It should only map the keys that exist in output_mapping and ignore unmapped keys from endpoint_output.
    """
    command_output = {"some_field": "some_value"}
    endpoint_output = {"host_name": "server1", "unmapped_key": "ignored_value", "another_unmapped": "also_ignored"}
    output_mapping = {"host_name": "Hostname"}
    brand = "TestBrand"

    result = create_endpoint(command_output, output_mapping, brand, add_additional_fields=True, endpoint_output=endpoint_output)

    expected = {"Message": COMMAND_SUCCESS_MSG, "Hostname": "server1", "Brand": "TestBrand", "AdditionalFields": command_output}

    assert result == expected
    assert "unmapped_key" not in result
    assert "another_unmapped" not in result


def test_prepare_args():
    """
    Given:
        A command, its arguments, its argument mapping and endpoint arguments.
    When:
        The prepare_args function is called with those parameters.
    Then:
        A dictionary of arguments with the mapped keys is returned.
    """
    command = Command(
        brand="BrandA",
        name="command1",
        output_keys=[],
        args_mapping={"cmd_arg1": "endpoint_arg1", "cmd_arg2": "endpoint_arg2"},
        output_mapping={},
    )

    # Example data
    endpoint_args = {
        "endpoint_arg1": "value1",
        "endpoint_arg2": "value2",
        "endpoint_arg3": "value3",  # Not in args_mapping
    }

    # Call the function
    result = prepare_args(command, endpoint_args)

    # Expected result
    expected = {"cmd_arg1": "value1", "cmd_arg2": "value2"}

    # Assertions
    assert result == expected

    # Test with missing or empty values
    endpoint_args = {
        "endpoint_arg1": "value1",
        "endpoint_arg2": "",  # Empty value
        "endpoint_arg3": None,  # None value
    }

    # Call the function again
    result = prepare_args(command, endpoint_args)

    # Expected result
    expected = {"cmd_arg1": "value1"}

    # Assertions
    assert result == expected


def test_hr_to_command_results():
    """
    Given:
        A command name, its arguments, and a human-readable output.
    When:
        a. The hr_to_command_results function is called with normal outputs.
        b. The hr_to_command_results function is called with error outputs.
        c. The hr_to_command_results function is called with no human-readable output.
    Then:
        a.  We get a CommandResults object with the correct HR, the correct entry type and is marked as note.
        b.  We get a CommandResults object with the Error HR, the correct entry type and is marked as Note.
        c. We get None.
    """
    # Example data
    command_name = "example-command"
    args = {
        "arg1": "value1",
        "arg2": "value2",
        "arg3": None,  # None value should be ignored
    }
    human_readable = "This is a human-readable result."

    # Call the function
    result = hr_to_command_results(command_name, args, human_readable)

    # Expected result
    expected_command = "!example-command arg1=value1 arg2=value2"
    expected_output = f"#### Result for {expected_command}\n{human_readable}"

    # Assertions
    assert result.readable_output == expected_output
    assert result.entry_type is EntryType.NOTE
    assert result.mark_as_note is True

    # Test error case
    error_human_readable = "An error occurred."
    result = hr_to_command_results(command_name, args, error_human_readable, entry_type=EntryType.ERROR)

    expected_output = f"#### Error for {expected_command}\n{error_human_readable}"

    # Assertions
    assert result.readable_output == expected_output
    assert result.entry_type == EntryType.ERROR
    assert result.mark_as_note is True

    # Test with no human_readable
    result = hr_to_command_results(command_name, args, "")

    # Assertions
    assert result is None


def test_get_output_key(mocker):
    """
    Given:
        Raw context, and an output key.
    When:
        a. The get_output_key function is called with an existing key.
        b. The get_output_key function is called with an existing, partial, key.
        c. The get_output_key function is called with a non-existing key.
        d. The get_output_key function is called with no context.
    Then:
        a + b. We get the full key.
        c. We get an empty string.
        d. We get an empty string.
    """
    # Example raw context with keys
    raw_context = {"key1": "value1", "key2(subkey)": "value2", "key3": "value3"}

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
    """
    Given:
        Raw context, and an output key.
    When:
        a. The get_outputs function is called with an existing key.
        b. The get_outputs function is called with an existing, partial, key.
        c. The get_outputs function is called with a non-existing key.
        d. The get_outputs function is called with no context.
    Then:
        a + b. We get the outputs.
        c. We get an empty dictionary.
        d. We get an empty dictionary.
    """
    raw_context = {"key1": "value1", "key2(subkey)": "value2", "key3": "value3"}

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
        {"Hostname": {"Value": "host1"}, "Port": {"Value": 8080}},
        {"Hostname": {"Value": "host2"}, "Port": {"Value": 9090}},
        {"Hostname": {"Value": "host1"}, "Protocol": {"Value": "http"}},
    ]


def test_get_raw_endpoints_single_entry(mocker):
    """
    Given:
        A single context entry representing two different endpoints.
    When:
        The get_raw_endpoints function is called with this entry.
    Then:
        A list of the two endpoints, in raw structure, is returned.
    """
    raw_context = [
        {
            "Device": [{"data from Device for object_1": "value1"}, {"data from Device for object_2": "value3"}],
            "Endpoint": [{"data from Endpoint for object_1": "value2"}, {"data from Endpoint for object_2": "value4"}],
        }
    ]

    mock_get_outputs = mocker.patch("GetEndpointData.get_outputs")
    mock_get_outputs.side_effect = [
        [{"data from Endpoint for object_1": "value2"}, {"data from Endpoint for object_2": "value4"}],
        [{"data from Device for object_1": "value1"}, {"data from Device for object_2": "value3"}],
    ]

    expected_output = [
        {"data from Endpoint for object_1": "value2", "data from Device for object_1": "value1"},
        {"data from Endpoint for object_2": "value4", "data from Device for object_2": "value3"},
    ]

    result = get_raw_endpoints(["Endpoint", "Device"], raw_context)
    assert result == expected_output, f"Expected {expected_output}, got {result}"


def test_get_raw_endpoints_multiple_entries(mocker):
    """
    Given:
        A two context entries representing two different endpoints.
    When:
        The get_raw_endpoints function is called with these entries.
    Then:
        A list of the two endpoints, in raw structure, is returned.
    """
    raw_context = [
        {"Endpoint": {"data from Endpoint for object_1": "value1"}, "Device": [{"data from Device for object_1": "value2"}]},
        {"Endpoint": {"data from Endpoint for object_2": "value3"}, "Device": [{"data from Device for object_2": "value4"}]},
    ]
    mock_get_outputs = mocker.patch("GetEndpointData.get_outputs")
    mock_get_outputs.side_effect = [
        {"data from Endpoint for object_1": "value1"},
        [{"data from Device for object_1": "value2"}],
        {"data from Endpoint for object_2": "value3"},
        [{"data from Device for object_2": "value4"}],
    ]

    expected_output = [
        {"data from Endpoint for object_1": "value1", "data from Device for object_1": "value2"},
        {"data from Endpoint for object_2": "value3", "data from Device for object_2": "value4"},
    ]

    result = get_raw_endpoints(["Endpoint", "Device"], raw_context)
    assert result == expected_output, f"Expected {expected_output}, got {result}"


def test_create_endpoints_with_empty_raw_endpoints_output():
    """
    Given:
        Raw endpoints data with no corresponding raw endpoints output provided.
    When:
        The create_endpoints function is called with an empty raw_endpoints_output list.
    Then:
        It should create empty dictionaries for each raw endpoint and pass them to create_endpoint.
    """
    raw_endpoints = [{"host_name": "server1"}, {"host_name": "server2"}]
    output_mapping = {"host_name": "Hostname"}
    brand = "TestBrand"
    add_additional_fields = False
    raw_endpoints_output = []

    result = create_endpoints(raw_endpoints, output_mapping, brand, add_additional_fields, raw_endpoints_output)

    # Should have called create_endpoint for each raw endpoint with empty dict as endpoint_output
    assert len(result) == 2


def test_create_endpoints_with_matching_raw_endpoints_output():
    """
    Given:
        Raw endpoints data with corresponding raw endpoints output of the same length.
    When:
        The create_endpoints function is called with matching raw_endpoints_output.
    Then:
        It should pair each raw endpoint with its corresponding output and create endpoints accordingly.
    """
    raw_endpoints = [{"host_name": "server1"}, {"host_name": "server2"}]
    output_mapping = {"host_name": "Hostname"}
    brand = "TestBrand"
    add_additional_fields = True
    raw_endpoints_output = [{"endpoint_data": "data1"}, {"endpoint_data": "data2"}]

    result = create_endpoints(raw_endpoints, output_mapping, brand, add_additional_fields, raw_endpoints_output)

    assert len(result) == 2


def test_create_endpoints_preserves_order(mocker):
    """
    Given:
        Multiple raw endpoints with corresponding output data in a specific order.
    When:
        The create_endpoints function is called with ordered input data.
    Then:
        It should preserve the order of endpoints in the returned list.
    """
    raw_endpoints = [{"host_name": "first-server"}, {"host_name": "second-server"}, {"host_name": "third-server"}]
    output_mapping = {"host_name": "Hostname"}
    brand = "TestBrand"
    add_additional_fields = False
    raw_endpoints_output = [{"priority": 1}, {"priority": 2}, {"priority": 3}]

    mock_create_endpoint = mocker.patch("GetEndpointData.create_endpoint")
    mock_create_endpoint.side_effect = [
        {"Hostname": "first-server", "Brand": "TestBrand"},
        {"Hostname": "second-server", "Brand": "TestBrand"},
        {"Hostname": "third-server", "Brand": "TestBrand"},
    ]

    result = create_endpoints(raw_endpoints, output_mapping, brand, add_additional_fields, raw_endpoints_output)

    assert len(result) == 3
    assert result[0]["Hostname"] == "first-server"
    assert result[1]["Hostname"] == "second-server"
    assert result[2]["Hostname"] == "third-server"


def test_create_endpoints_calls_create_endpoint_with_correct_parameters(mocker):
    """
    Given:
        Raw endpoints data with specific parameters for brand and additional fields.
    When:
        The create_endpoints function is called with these parameters.
    Then:
        It should call create_endpoint with exactly the correct parameters for each endpoint.
    """
    raw_endpoints = [{"host_name": "test-server"}]
    output_mapping = {"host_name": "Hostname"}
    brand = "SpecificBrand"
    add_additional_fields = True
    raw_endpoints_output = [{"extra": "output"}]

    mock_create_endpoint = mocker.patch("GetEndpointData.create_endpoint")
    mock_create_endpoint.return_value = {"Hostname": "test-server", "Brand": "SpecificBrand"}

    create_endpoints(raw_endpoints, output_mapping, brand, add_additional_fields, raw_endpoints_output)

    mock_create_endpoint.assert_called_once_with(
        raw_endpoints[0], output_mapping, brand, add_additional_fields, raw_endpoints_output[0]
    )


def test_create_endpoints_handles_none_values_in_output(mocker):
    """
    Given:
        Raw endpoints data with None values in the raw endpoints output.
    When:
        The create_endpoints function is called with None values in the output list.
    Then:
        It should pass None values to create_endpoint without modification.
    """
    raw_endpoints = [{"host_name": "server1"}, {"host_name": "server2"}]
    output_mapping = {"host_name": "Hostname"}
    brand = "TestBrand"
    add_additional_fields = False
    raw_endpoints_output = [None, {"valid": "output"}]

    mock_create_endpoint = mocker.patch("GetEndpointData.create_endpoint")
    mock_create_endpoint.side_effect = [
        {"Hostname": "server1", "Brand": "TestBrand"},
        {"Hostname": "server2", "Brand": "TestBrand"},
    ]

    result = create_endpoints(raw_endpoints, output_mapping, brand, add_additional_fields, raw_endpoints_output)

    assert len(result) == 2
    mock_create_endpoint.assert_any_call(raw_endpoints[0], output_mapping, brand, add_additional_fields, None)
    mock_create_endpoint.assert_any_call(raw_endpoints[1], output_mapping, brand, add_additional_fields, {"valid": "output"})


def test_get_endpoints_not_found_list_all_endpoints_found():
    """
    Given:
        A list of endpoints where all requested endpoints are found with matching IDs, IPs, and hostnames.
    When:
        The get_endpoints_not_found_list function is called with endpoints and zipped arguments.
    Then:
        It should return an empty list since all endpoints were successfully found.
    """
    endpoints = [
        {"Message": COMMAND_SUCCESS_MSG, "Hostname": "host1", "ID": "id1", "IPAddress": "192.168.1.1"},
        {"Message": COMMAND_SUCCESS_MSG, "Hostname": "host2", "ID": "id2", "IPAddress": "192.168.1.2"},
    ]
    zipped_args = [("id1", "192.168.1.1", "host1"), ("id2", "192.168.1.2", "host2")]

    result = get_endpoints_not_found_list(endpoints, zipped_args)

    assert result == []


def test_get_endpoints_not_found_list_some_endpoints_not_found():
    """
    Given:
        A list of endpoints where only some of the requested endpoints are found.
    When:
        The get_endpoints_not_found_list function is called with partial results.
    Then:
        It should return a list containing only the endpoints that were not found.
    """
    endpoints = [{"Message": COMMAND_SUCCESS_MSG, "Hostname": "host1", "ID": "id1", "IPAddress": "192.168.1.1"}]
    zipped_args = [("id1", "192.168.1.1", "host1"), ("id2", "192.168.1.2", "host2")]

    result = get_endpoints_not_found_list(endpoints, zipped_args)

    expected = [{"ID": "id2", "Hostname": "host2", "IPAddress": "192.168.1.2"}]
    assert result == expected


def test_get_endpoints_not_found_list_no_endpoints_found():
    """
    Given:
        An empty list of endpoints indicating no endpoints were found.
    When:
        The get_endpoints_not_found_list function is called with empty endpoint results.
    Then:
        It should return all requested endpoints as not found.
    """
    endpoints = []
    zipped_args = [("id1", "192.168.1.1", "host1"), ("id2", "192.168.1.2", "host2")]

    result = get_endpoints_not_found_list(endpoints, zipped_args)

    expected = [
        {"ID": "id1", "Hostname": "host1", "IPAddress": "192.168.1.1"},
        {"ID": "id2", "Hostname": "host2", "IPAddress": "192.168.1.2"},
    ]
    assert result == expected


def test_get_endpoints_not_found_list_with_failed_endpoints():
    """
    Given:
        A list of endpoints containing some with failed command messages.
    When:
        The get_endpoints_not_found_list function is called with mixed success and failure results.
    Then:
        It should ignore failed endpoints when building the found sets and return missing endpoints.
    """
    endpoints = [
        {"Message": COMMAND_SUCCESS_MSG, "Hostname": "host1", "ID": "id1", "IPAddress": "192.168.1.1"},
        {"Message": COMMAND_FAILED_MSG, "Hostname": "host2", "ID": "id2", "IPAddress": "192.168.1.2"},
    ]
    zipped_args = [("id1", "192.168.1.1", "host1"), ("id2", "192.168.1.2", "host2")]

    result = get_endpoints_not_found_list(endpoints, zipped_args)

    expected = [{"ID": "id2", "Hostname": "host2", "IPAddress": "192.168.1.2"}]
    assert result == expected


def test_get_endpoints_not_found_list_with_list_values(mocker):
    """
    Given:
        Endpoints where hostname, ID, and IP address values are returned as lists.
    When:
        The get_endpoints_not_found_list function is called with list-type endpoint values.
    Then:
        It should properly handle list values using to_list and find matches correctly.
    """
    mock_to_list = mocker.patch("GetEndpointData.to_list")
    mock_to_list.side_effect = [
        ["host1", "host1-alt"],  # Hostname list
        ["id1"],  # ID list
        ["192.168.1.1"],  # IPAddress list
        ["host2"],  # Hostname list
        ["id2"],  # ID list
        ["192.168.1.2"],  # IPAddress list
    ]

    endpoints = [
        {"Message": COMMAND_SUCCESS_MSG, "Hostname": ["host1", "host1-alt"], "ID": ["id1"], "IPAddress": ["192.168.1.1"]},
        {"Message": COMMAND_SUCCESS_MSG, "Hostname": ["host2"], "ID": ["id2"], "IPAddress": ["192.168.1.2"]},
    ]
    zipped_args = [("id1", "192.168.1.1", "host1"), ("id3", "192.168.1.3", "host3")]

    result = get_endpoints_not_found_list(endpoints, zipped_args)

    expected = [{"ID": "id3", "Hostname": "host3", "IPAddress": "192.168.1.3"}]
    assert result == expected


def test_get_endpoints_not_found_list_with_empty_values():
    """
    Given:
        Zipped arguments containing empty strings for some endpoint identifiers.
    When:
        The get_endpoints_not_found_list function is called with empty identifier values.
    Then:
        It should filter out empty values and return only non-empty identifiers in the result.
    """
    endpoints = [{"Message": COMMAND_SUCCESS_MSG, "Hostname": "host1", "ID": "id1", "IPAddress": "192.168.1.1"}]
    zipped_args = [("id1", "192.168.1.1", "host1"), ("", "", "host2"), ("id3", "", "")]

    result = get_endpoints_not_found_list(endpoints, zipped_args)

    expected = [{"Hostname": "host2"}, {"ID": "id3"}]
    assert result == expected


def test_get_endpoints_not_found_list_partial_match_by_hostname():
    """
    Given:
        An endpoint found by hostname but not by ID or IP address from the zipped arguments.
    When:
        The get_endpoints_not_found_list function is called with a hostname-only match.
    Then:
        It should not include the endpoint in the not found list since hostname was matched.
    """
    endpoints = [{"Message": COMMAND_SUCCESS_MSG, "Hostname": "host1", "ID": "different-id", "IPAddress": "different-ip"}]
    zipped_args = [("requested-id", "requested-ip", "host1")]

    result = get_endpoints_not_found_list(endpoints, zipped_args)

    assert result == []


def test_get_endpoints_not_found_list_partial_match_by_id():
    """
    Given:
        An endpoint found by ID but not by hostname or IP address from the zipped arguments.
    When:
        The get_endpoints_not_found_list function is called with an ID-only match.
    Then:
        It should not include the endpoint in the not found list since ID was matched.
    """
    endpoints = [{"Message": COMMAND_SUCCESS_MSG, "Hostname": "different-host", "ID": "id1", "IPAddress": "different-ip"}]
    zipped_args = [("id1", "requested-ip", "requested-host")]

    result = get_endpoints_not_found_list(endpoints, zipped_args)

    assert result == []


def test_get_endpoints_not_found_list_partial_match_by_ip():
    """
    Given:
        An endpoint found by IP address but not by hostname or ID from the zipped arguments.
    When:
        The get_endpoints_not_found_list function is called with an IP-only match.
    Then:
        It should not include the endpoint in the not found list since IP address was matched.
    """
    endpoints = [{"Message": COMMAND_SUCCESS_MSG, "Hostname": "different-host", "ID": "different-id", "IPAddress": "192.168.1.1"}]
    zipped_args = [("requested-id", "192.168.1.1", "requested-host")]

    result = get_endpoints_not_found_list(endpoints, zipped_args)

    assert result == []


def test_add_endpoint_to_mapping_new_brand():
    """
    Given:
        A list of endpoints with a new brand and ID.
    When:
        The add_endpoint_to_mapping function is called with the endpoints.
    Then:
        It should add the new endpoint to the mapping with the new brand and ID.
    """
    endpoints = [
        {"Message": COMMAND_SUCCESS_MSG, "Brand": Brands.CORTEX_XDR_IR, "ID": 1},
    ]
    mapping = {}
    add_endpoint_to_mapping(endpoints, mapping)
    assert mapping == {1: {"Message": COMMAND_SUCCESS_MSG, "Brand": Brands.CORTEX_XDR_IR, "ID": 1}}


def test_add_endpoint_to_mapping_skips_unsuccessful():
    """
    Given:
        A list of endpoints with a failed command message.
    When:
        The add_endpoint_to_mapping function is called with the endpoints.
    Then:
        It should skip the endpoint with the failed command message and return an empty mapping.
    """
    endpoints = [
        {"Message": "Some error", "Brand": "BrandA", "ID": 3},
    ]
    mapping = {}
    add_endpoint_to_mapping(endpoints, mapping)
    assert mapping == {}


def test_update_endpoint_in_mapping_updates_risk_level():
    """
    Given:
        An ir_mapping with an endpoint having a lower risk level and an incoming endpoint
        with a higher risk level and a success message.
    When:
        update_endpoint_in_mapping is called with the incoming endpoint and the mapping.
    Then:
        The risk level in the mapping should be updated to the higher level.
    """
    ir_mapping = {"1": {"Hostname": "host1", "RiskLevel": "LOW", "Message": COMMAND_SUCCESS_MSG}}
    endpoints = [{"Hostname": "host1", "RiskLevel": "HIGH", "Message": COMMAND_SUCCESS_MSG}]
    update_endpoint_in_mapping(endpoints, ir_mapping)
    assert ir_mapping["1"]["RiskLevel"] == "HIGH"


def test_update_endpoint_in_mapping_adds_risk_level_if_missing():
    """
    Given:
        An ir_mapping with an endpoint missing a risk level and an incoming endpoint with a risk level and a success message.
    When:
        update_endpoint_in_mapping is called.
    Then:
        The risk level should be added to the mapping.
    """
    ir_mapping = {"1": {"Hostname": "host1", "Message": COMMAND_SUCCESS_MSG}}
    endpoints = [{"Hostname": "host1", "RiskLevel": "Medium", "Message": COMMAND_SUCCESS_MSG}]
    update_endpoint_in_mapping(endpoints, ir_mapping)
    assert ir_mapping["1"]["RiskLevel"] == "Medium"


def test_update_endpoint_in_mapping_updates_additional_fields():
    """
    Given:
        An ir_mapping with an endpoint and an incoming endpoint with additional_fields and a success message.
    When:
        update_endpoint_in_mapping is called.
    Then:
        The additional fields should be merged into the mapping.
    """
    ir_mapping = {"1": {"Hostname": "host1", "Message": COMMAND_SUCCESS_MSG}}
    endpoints = [{"Hostname": "host1", "Message": COMMAND_SUCCESS_MSG, "RiskLevel": "LOW", "additional_fields": {"os": "Linux"}}]
    update_endpoint_in_mapping(endpoints, ir_mapping)
    assert ir_mapping["1"]["os"] == "Linux"


def test_update_endpoint_in_mapping_skips_unsuccessful():
    """
    Given:
        An endpoint with a failure message.
    When:
        update_endpoint_in_mapping is called with this endpoint.
    Then:
        The ir_mapping should remain unchanged.
    """
    ir_mapping = {"1": {"Hostname": "host1", "RiskLevel": "Low", "Message": COMMAND_SUCCESS_MSG}}
    endpoints = [{"Hostname": "host1", "RiskLevel": "High", "Message": "Some error"}]
    update_endpoint_in_mapping(endpoints, ir_mapping)
    # Should not update the mapping
    assert ir_mapping["1"]["RiskLevel"] == "Low"


def test_get_generic_command_returns_correct_command():
    """
    Given:
        - A list of commands including one with brand 'BrandA' and one with brand 'Generic Command'.
    When:
        The get_generic_command function is called with this list.
    Then:
        It should return the command with brand 'Generic Command'.
    """
    commands = [
        Command(brand="BrandA", name="commandA", output_keys=[], args_mapping={}, output_mapping={}),
        Command(brand=Brands.GENERIC_COMMAND, name="commandB", output_keys=[], args_mapping={}, output_mapping={}),
    ]
    result = get_generic_command(commands)
    assert result.brand == "Generic Command"


@pytest.mark.parametrize(
    "brands_to_run, available_brands, predefined_brands, expected",
    [
        (
            [],
            {"BrandA", "BrandD", "BrandE"},
            ["BrandA", "BrandB", "BrandC"],
            {"BrandD", "BrandE"},
        ),
        (
            ["BrandD"],
            {"BrandA", "BrandD", "BrandE"},
            ["BrandA", "BrandB", "BrandC"],
            {"BrandD"},
        ),
    ],
)
def test_create_using_brand_argument_to_generic_command_all_default(
    mocker, brands_to_run, available_brands, predefined_brands, expected
):
    """
    Given:
        - Enabled brands: BrandA, BrandD, BrandE (BrandB inactive).
        - Predefined brands: BrandA, BrandB, BrandC.
        - Empty 'using-brand' argument list provided.
    When:
        create_using_brand_argument_to_generic_command is called.
    Then:
        'using-brand' should contain only active brands not in the predefined list (BrandD, BrandE).
    """
    mocker.patch("GetEndpointData.Brands.get_all_values", return_value=predefined_brands)
    mock_module_manager = mocker.Mock()
    mock_module_manager.get_enabled_brands.return_value = available_brands

    command = Command(brand="Generic Command", name="gc", output_keys=[], args_mapping={}, output_mapping={})

    create_using_brand_argument_to_generic_command(brands_to_run, command, mock_module_manager)

    actual_set = set(command.additional_args["using-brand"].split(","))
    assert actual_set == expected


def test_get_extended_hostnames_set_typical():
    """
    Given:
        A mapping with Cortex XDR brand containing endpoints with hostnames and irrelevant brand.
    When:
        get_extended_hostnames_set is called with this mapping.
    Then:
        It returns a set of all hostnames from the Cortex XDR brand.
    """
    mapped_endpoints = {"1": {"Hostname": "host-xdr-1"}, "2": {"Hostname": "host-xdr-2"}}
    result = get_extended_hostnames_set(mapped_endpoints)
    assert result == {"host-xdr-1", "host-xdr-2"}


def test_get_extended_hostnames_set_empty():
    """
    Given:
        An empty mapping.
    When:
        get_extended_hostnames_set is called.
    Then:
        It returns an empty set.
    """
    assert get_extended_hostnames_set({}) == set()
