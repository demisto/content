import pytest
import demistomock as demisto
from CommonServerPython import CommandResults, EntryType
from GetEndpointData import MappedCommand, ModuleManager, EndpointCommandRunner


@pytest.fixture
def setup_module_manager():
    modules = {
        "module1": {"brand": "BrandA", "state": "active"},
        "module2": {"brand": "BrandB", "state": "inactive"},
    }
    brands_to_run = ["BrandA", "BrandC"]
    module_manager = ModuleManager(modules=modules, brands_to_run=brands_to_run)
    command = MappedCommand(brand="BrandA", name="TestCommand", output_keys=[], args_mapping={}, output_mapping={})
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
def setup_endpoint_command_runner(mocker):
    module_manager = mocker.Mock(spec=ModuleManager)
    arg_free_commands = ["test-command"]
    command_runner = EndpointCommandRunner(module_manager=module_manager, arg_free_commands=arg_free_commands)
    command = MappedCommand(brand="TestBrand", name="test-command", output_keys=[], args_mapping={}, output_mapping={})
    return command_runner, module_manager, command

class TestEndpointCommandRunner:
    def test_is_command_runnable(self, setup_endpoint_command_runner):
        command_runner, module_manager, command = setup_endpoint_command_runner

        module_manager.is_brand_available.return_value = True

        args = {"arg1": "value1"}
        assert command_runner.is_command_runnable(command, args) is True

        module_manager.is_brand_available.return_value = False
        assert command_runner.is_command_runnable(command, args) is False

        module_manager.is_brand_available.return_value = True
        args = {}  # No args provided but command listed in arg_free_commands
        assert command_runner.is_command_runnable(command, args) is True

        command_runner.arg_free_commands = []  # No args provided and command is not listed in arg_free_commands
        assert command_runner.is_command_runnable(command, args) is False

    def test_run_execute_command_with_list(self, mocker, setup_endpoint_command_runner):
        command_runner, _, command = setup_endpoint_command_runner

        mock_demisto_execute_command = mocker.patch.object(
            demisto,
            'executeCommand',
            return_value=[{"Type": 1, "Contents": "result"}]
        )
        result = command_runner.run_execute_command(command, {"arg1": "value1"})
        assert result == [{"Type": 1, "Contents": "result"}]
        mock_demisto_execute_command.assert_called_once_with("test-command", {"arg1": "value1"})

    def test_run_execute_command_with_dict(self, mocker, setup_endpoint_command_runner):
        command_runner, _, command = setup_endpoint_command_runner

        mock_demisto_execute_command = mocker.patch.object(
            demisto,
            'executeCommand',
            return_value={"Type": 1, "Contents": "result"}
        )
        result = command_runner.run_execute_command(command, {"arg1": "value1"})
        assert result == [{"Type": 1, "Contents": "result"}]
        mock_demisto_execute_command.assert_called_once_with("test-command", {"arg1": "value1"})

    def test_get_commands_outputs(self, mocker, setup_endpoint_command_runner):
        command_runner, _,command = setup_endpoint_command_runner
        command_results = [
            {"EntryContext": {"key": "value"}, "HumanReadable": "Readable output", "Type": EntryType.NOTE},
            {"EntryContext": {}, "HumanReadable": "Another output", "Type": EntryType.NOTE},
            {"EntryContext": {}, "Contents": "Error output", "Type": EntryType.ERROR }  # An entry with error
        ]
        expected_context_outputs = [{"key": "value"}, {}, {}]
        expected_human_readable = "Readable output\nAnother output"
        expected_error_outputs = [CommandResults(
                    readable_output=f"#### Error for !{command.name} \nError output",
                    entry_type=EntryType.ERROR,
                    mark_as_note=True,
                )]

        context_outputs, human_readable, error_outputs = command_runner.get_commands_outputs("test-command", command_results, {})
        assert context_outputs == expected_context_outputs
        assert human_readable == expected_human_readable
        for expected_error_output, error_output in zip(expected_error_outputs, error_outputs):
            assert error_output.readable_output == expected_error_output.readable_output

    def test_run_command(self, mocker, setup_endpoint_command_runner):
        command_runner, module_manager = setup_endpoint_command_runner
        command = MappedCommand(brand="TestBrand", name="test-command", output_keys=[], args_mapping={}, output_mapping={})
        endpoint_args = {"arg1": "value1"}

        mock_prepare_args = mocker.patch('your_module.prepare_args', return_value={"arg1": "value1"})
        mock_run_execute_command = mocker.patch.object(command_runner, 'run_execute_command', return_value=[{"Type": 1, "Contents": "result"}])
        mock_get_commands_outputs = mocker.patch.object(command_runner, 'get_commands_outputs', return_value=([{"key": "value"}], "Readable output", []))

        hr, endpoints = command_runner.run_command(command, endpoint_args)
        assert hr == "Readable output"
        assert endpoints == []

        mock_get_commands_outputs.return_value = ([], "Readable output", ["Error output"])
        hr, endpoints = command_runner.run_command(command, endpoint_args)
        assert hr == ["Error output"]
        assert endpoints == []

        mock_prepare_args.assert_called_with(command, endpoint_args)
        mock_run_execute_command.assert_called()
        mock_get_commands_outputs.assert_called()