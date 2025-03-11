from IsolateEndpoint import *
import pytest


@pytest.fixture
def setup_for_test_module_manager():
    modules = {
        "module1": {"brand": "BrandA", "state": "active"},
        "module2": {"brand": "BrandB", "state": "inactive"},
    }
    brands_to_run = ["BrandA", "BrandC"]
    module_manager = ModuleManager(modules=modules, brands_to_run=brands_to_run)
    command = Command(brand="BrandA", name="TestCommand", arg_mapping={}, pre_command_check=None)
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


def test_get_args_from_endpoint_data():
    """
    Given:
        A dictionary containing endpoint data with nested 'Value' and 'Source' fields.
    When:
        The get_args_from_endpoint_data function is called with this dictionary.
    Then:
        It extracts and returns the correct values in a new dictionary.
    """
    endpoint_data = {
        "Hostname": {"Value": "host123"},
        "ID": {"Value": "agent-456", "Source": "brand-x"},
        "IPAddress": {"Value": "8.8.1.1"},
    }

    expected_output = {
        "agent_id": "agent-456",
        "agent_hostname": "host123",
        "agent_ip": "8.8.1.1",
        "agent_brand": "brand-x",
    }

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


def test_do_args_exist_in_valid():
    """
    Given:
        Different cases where the args dictionary contains agent_id, agent_ip, or agent_hostname.
    When:
        The do_args_exist_in_valid function is called with a list of valid_args.
    Then:
        It returns True if any match is found, otherwise False.
    """
    valid_args = [
        {"agent_id": "123", "agent_hostname": "host1", "agent_ip": "192.168.1.1"},
        {"agent_id": "456", "agent_hostname": "host2", "agent_ip": "192.168.1.2"},
    ]

    args = {"agent_id": "123", "agent_hostname": "", "agent_ip": ""}
    assert do_args_exist_in_valid(args, valid_args) is True

    args = {"agent_id": "", "agent_hostname": "host2", "agent_ip": ""}
    assert do_args_exist_in_valid(args, valid_args) is True

    args = {"agent_id": "", "agent_hostname": "", "agent_ip": "192.168.1.2"}
    assert do_args_exist_in_valid(args, valid_args) is True

    args = {"agent_id": "999", "agent_hostname": "unknown", "agent_ip": "10.0.0.1"}
    assert do_args_exist_in_valid(args, valid_args) is False

    args = {"agent_id": "", "agent_hostname": "", "agent_ip": ""}
    assert do_args_exist_in_valid(args, valid_args) is False


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

    base_command.hard_coded_args = None


def test_are_there_missing_args():
    """
    Given:
        - A Command object with `arg_mapping` defining expected argument keys.
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
        "OSVersion": {"Value": "Windows Server 2016"},
        "IsIsolated": {"Value": "No"},
        "Status": {"Value": "Online"}
    }
    assert is_endpoint_isolatable(endpoint_data, force=False, server_os_list=[]) == (
        False, "The endpoint is a server, therefore aborting isolation."
    )

    assert is_endpoint_isolatable(endpoint_data, force=True, server_os_list=[]) == (True, '')

    endpoint_data["OSVersion"]["Value"] = "example"
    endpoint_data["IsIsolated"]["Value"] = "Yes"
    assert is_endpoint_isolatable(endpoint_data, force=False, server_os_list=[]) == (
        False, "The endpoint is already isolated."
    )

    endpoint_data["IsIsolated"]["Value"] = "No"
    endpoint_data["Status"]["Value"] = "Offline"
    assert is_endpoint_isolatable(endpoint_data, force=False, server_os_list=[]) == (
        False, "The endpoint is offline."
    )

    endpoint_data = {
        "OSVersion": {"Value": "Windows 10"},
        "IsIsolated": {"Value": "No"},
        "Status": {"Value": "Online"}
    }
    assert is_endpoint_isolatable(endpoint_data, force=False, server_os_list=[]) == (True, '')

    endpoint_data["OSVersion"]["Value"] = "Ubuntu Server"
    assert is_endpoint_isolatable(endpoint_data, force=False, server_os_list=["Ubuntu Server"]) == (
        False, "The endpoint is a server, therefore aborting isolation."
    )
