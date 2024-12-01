import pytest
import demistomock as demisto
from pytest_mock import MockerFixture
from GetEndpointData import MappedCommand, ModuleManager, CommandRunner, to_list


@pytest.fixture
def mapped_command():
    return MappedCommand("test_brand", "test_command")


def test_mapped_command_initialization(mapped_command):
    assert mapped_command.brand == "test_brand"
    assert mapped_command.name == "test_command"
    assert mapped_command.args_mapping is None


def test_mapped_command_with_args_mapping():
    args_mapping = {"arg1": "mapped_arg1", "arg2": "mapped_arg2"}
    mapped_command = MappedCommand("test_brand", "test_command", args_mapping=args_mapping)
    assert mapped_command.args_mapping == args_mapping


def test_mapped_command_empty_mappings():
    mapped_command = MappedCommand("test_brand", "test_command", args_mapping={})
    assert mapped_command.args_mapping == {}


class TestModuleManager:
    def setup_method(self):
        self.modules = {
            "module1": {"brand": "BrandA", "state": "active"},
            "module2": {"brand": "BrandB", "state": "inactive"},
            "module3": {"brand": "BrandC", "state": "active"},
        }
        self.brands_to_run = ["BrandA", "BrandC"]
        self.module_manager = ModuleManager(self.modules, self.brands_to_run)

    def test_is_brand_in_brands_to_run(self):
        command = MappedCommand("BrandA", "Command1")
        assert self.module_manager.is_brand_in_brands_to_run(command) is True

        command = MappedCommand("BrandB", "Command2")
        assert self.module_manager.is_brand_in_brands_to_run(command) is False

        command = MappedCommand("BrandC", "Command3")
        assert self.module_manager.is_brand_in_brands_to_run(command) is True

        command = MappedCommand("BrandD", "Command4")
        assert self.module_manager.is_brand_in_brands_to_run(command) is False

    def test_is_brand_available(self):
        command = MappedCommand("BrandA", "Command1")
        assert self.module_manager.is_brand_available(command) is True

        command = MappedCommand("BrandB", "Command2")
        assert self.module_manager.is_brand_available(command) is False

        command = MappedCommand("BrandC", "Command3")
        assert self.module_manager.is_brand_available(command) is True

        command = MappedCommand("BrandD", "Command4")
        assert self.module_manager.is_brand_available(command) is False

    def test_with_empty_brands_to_run(self):
        module_manager = ModuleManager(self.modules, [])

        command = MappedCommand("BrandA", "Command1")
        assert module_manager.is_brand_in_brands_to_run(command) is True

        command = MappedCommand("BrandB", "Command2")
        assert module_manager.is_brand_in_brands_to_run(command) is True

        command = MappedCommand("BrandC", "Command3")
        assert module_manager.is_brand_in_brands_to_run(command) is True

        command = MappedCommand("BrandD", "Command4")
        assert module_manager.is_brand_in_brands_to_run(command) is True


class TestCommandRunner:
    def setup_method(self):
        self.modules = {
            "module1": {"brand": "BrandA", "state": "active"},
            "module2": {"brand": "BrandB", "state": "inactive"},
            "module3": {"brand": "BrandC", "state": "active"},
        }
        self.brands_to_run = ["BrandA", "BrandC"]
        self.module_manager = ModuleManager(self.modules, self.brands_to_run)

        self.endpoint_args = {"arg1": "value1", "arg2": "value2"}
        self.arg_free_commands = ["CommandFree"]

        self.command_runner = CommandRunner(self.module_manager, self.endpoint_args, self.arg_free_commands)

    def test_run_command_if_available(self, mocker: MockerFixture):
        command = MappedCommand("BrandA", "Command1", {"arg1": "arg1"})
        execute_command_mock_target = 'GetEndpointData.CommandRunner._run_execute_command'
        get_command_outputs_mock_target = 'GetEndpointData.CommandRunner._get_commands_outputs'
        execute_mock = mocker.patch(execute_command_mock_target, return_value="CommandResult")
        get_outputs_mock = mocker.patch(get_command_outputs_mock_target, return_value=({}, "", ""))
        context_outputs, human_readable, error_outputs = self.command_runner.run_command_if_available(command)

        execute_mock.assert_called_once_with(command)
        get_outputs_mock.assert_called_once_with("CommandResult")
        assert context_outputs == {}
        assert human_readable == ""
        assert error_outputs == ""


    def test_run_command_if_available_brand_not_available(self):
        command = MappedCommand("BrandB", "Command2", {"arg1": "arg1"})
        context_outputs, human_readable, error_outputs = self.command_runner.run_command_if_available(command)

        assert context_outputs == []
        assert human_readable == ""

    def test_run_execute_command_brand_available_with_args(self, mocker):
        command = MappedCommand("BrandA", "test_command", {"arg1": "mapped_arg1"})

        mock_execute = mocker.patch.object(demisto,'executeCommand', return_value=[{"Contents": "test_result"}])

        result = self.command_runner._run_execute_command(command)

        mock_execute.assert_called_once_with("test_command", {"arg1": "value1"})
        assert result == {'command': command, 'results': [{"Contents": "test_result"}]}

    def test_run_execute_command_brand_available_arg_free(self, mocker):
        command = MappedCommand("TestBrand", "test_command", {})
        self.arg_free_commands = ["test_command"]

        mocker.patch.object(self.module_manager, 'is_brand_available', return_value=True)
        mock_execute = mocker.patch('GetEndpointData.demisto.executeCommand', return_value=[{"Contents": "test_result"}])

        result = self.command_runner._run_execute_command(command)

        mock_execute.assert_called_once_with("test_command", {})
        assert result == {'command': command, 'results': [{"Contents": "test_result"}]}

    def test_run_execute_command_brand_available_no_args_not_arg_free(self, mocker):
        command = MappedCommand("TestBrand", "test_command", {})

        mocker.patch.object(self.module_manager, 'is_brand_available', return_value=True)
        mock_execute = mocker.patch('GetEndpointData.demisto.executeCommand')

        result = self.command_runner._run_execute_command(command)

        mock_execute.assert_not_called()
        assert result == {'command': command, 'results': []}

    def test_run_execute_command_brand_not_available(self, mocker):
        command = MappedCommand(self.modules['module2']['brand'], "test_command", {"arg1": "mapped_arg1"})

        mock_execute = mocker.patch.object(demisto,'executeCommand', return_value=[{"Contents": "test_result"}])
        mock_debug = mocker.patch.object(demisto, 'debug')

        result = self.command_runner._run_execute_command(command)

        mock_execute.assert_not_called()
        mock_debug.assert_called_once_with(f'Skipping command "{command.name}" since the brand {command.brand} is not available.')
        assert result == {'command': command, 'results': []}

    def test_run_execute_command_debug_logging(self, mocker):
        command = MappedCommand(self.modules['module1']['brand'], "test_command", {"arg1": "mapped_arg1"})
        self.endpoint_args = {"mapped_arg1": "value1"}

        mocker.patch.object(self.module_manager, 'is_brand_available', return_value=True)
        mock_debug = mocker.patch.object(demisto, 'debug')
        mock_execute = mocker.patch.object(demisto,'executeCommand', return_value=[{"Contents": "test_result"}])

        self.command_runner._run_execute_command(command)

        mock_debug.assert_any_call(f'Running "{command=}" with args={{"arg1": "value1"}}')
        mock_debug.assert_any_call(f'Command "{command.name}" returned [{{"Contents": "test_result"}}]')

    def test_run_execute_command_to_list_usage(self, mocker):
        command = MappedCommand("TestBrand", "test_command", {"arg1": "mapped_arg1"})
        self.endpoint_args = {"mapped_arg1": "value1"}

        mocker.patch.object(self.module_manager, 'is_brand_available', return_value=True)
        mock_execute = mocker.patch('GetEndpointData.demisto.executeCommand', return_value={"Contents": "test_result"})
        mock_to_list = mocker.patch('GetEndpointData.to_list', side_effect=lambda x: [x] if not isinstance(x, list) else x)

        result = self.command_runner._run_execute_command(command)

        mock_to_list.assert_called_once_with({"Contents": "test_result"})
        assert result == {'command': command, 'results': [{"Contents": "test_result"}]}