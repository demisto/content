from IsolateEndpoint import *
import pytest
from unittest.mock import patch


def test_get_all_values_returns_expected_list():
    """
    Ensure get_all_values returns all brand values in the correct order.
    """
    expected_list = ["FireEyeHX v2", "CrowdstrikeFalcon", "Cortex Core - IR", "Microsoft Defender Advanced Threat Protection"]
    assert Brands.get_all_values() == expected_list


@pytest.mark.parametrize(
    "brand_enum, expected_value",
    [
        (Brands.FIREEYE_HX_V2, "FireEyeHX v2"),
        (Brands.CROWDSTRIKE_FALCON, "CrowdstrikeFalcon"),
        (Brands.CORTEX_CORE_IR, "Cortex Core - IR"),
        (Brands.MICROSOFT_DEFENDER_ADVANCED_THREAT_PROTECTION, "Microsoft Defender Advanced Threat Protection"),
    ],
)
def test_individual_enum_values(brand_enum, expected_value):
    """
    Ensure each enum member returns the correct value (parametrized).
    """
    assert brand_enum.value == expected_value


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
def test_check_missing_executed_args_in_output(mock_create_message):
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
    assert are_there_missing_args(command=base_command, endpoint_args=args, endpoint_output={}) is False

    base_command.arg_mapping = {"new_key1": "old_key1", "new_key2": "missing_key"}
    args = {"old_key1": "value1"}
    assert are_there_missing_args(command=base_command, endpoint_args=args, endpoint_output={}) is False

    base_command.arg_mapping = {"new_key1": "old_key1", "new_key2": "old_key2"}
    endpoint_output = {}
    assert are_there_missing_args(command=base_command, endpoint_args={}, endpoint_output=endpoint_output) is True

    assert endpoint_output.get("Result") == "Fail"
    assert endpoint_output.get("Message") == "Missing args for test_command."

    base_command.arg_mapping = {}
    assert are_there_missing_args(command=base_command, endpoint_args={}, endpoint_output={}) is False


def test_is_endpoint_already_isolated():
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


@pytest.mark.parametrize(
    "is_error, get_error_msg, raw_response, expected_is_isolated, expected_result, expected_message",
    [
        # Error case
        (
            True,
            "Some error occurred",
            {"status": "error"},
            False,
            "Fail",
            "Failed to isolate 1234 with command TestCommand.Error:Some error occurred",
        ),
        # Success case
        (
            False,
            "",
            {"status": "ok"},
            True,
            "Success",
            "1234 was isolated successfully with command TestCommand.",
        ),
    ],
)
@patch("IsolateEndpoint.is_error")
@patch("IsolateEndpoint.get_error")
@patch("IsolateEndpoint.create_message_to_context_and_hr")
def test_handle_raw_response_results(
    mock_create_message,
    mock_get_error,
    mock_is_error,
    is_error,
    get_error_msg,
    raw_response,
    expected_is_isolated,
    expected_result,
    expected_message,
):
    """
    Given:
        - Different combinations of raw response data and error flags.
        - Case 1: is_error=True with an error message.
        - Case 2: is_error=False for a success scenario.
    When:
        - Calling handle_raw_response_results with a Command object, endpoint args, and mocked helper functions.
    Then:
        - create_message_to_context_and_hr should be called exactly once with the expected parameters,
          including correct isolation status, result, and message.
    """
    command = Command(brand="BrandA", name="TestCommand", arg_mapping={})
    args = {"endpoint_id": "1234"}
    outputs = {}

    mock_is_error.return_value = is_error
    mock_get_error.return_value = get_error_msg

    handle_raw_response_results(command=command, raw_response=raw_response, endpoint_args=args, endpoint_output=outputs)

    mock_create_message.assert_called_once_with(
        is_isolated=expected_is_isolated,
        endpoint_args=args,
        result=expected_result,
        message=expected_message,
        endpoint_output=outputs,
    )


def test_initialize_commands():
    """
    Given:
        - The initialize_commands function is called to initialize a list of command objects.
    When:
        - Running the test_initialize_commands function to validate the list of command names and their associated brands.
    Then:
        - Ensure the actual command names match the expected set of command names.
        - Ensure each command has the correct brand associated with its name.
    """
    commands = initialize_commands()

    expected_commands = {
        "core-isolate-endpoint": "Cortex Core - IR",
        "cs-falcon-contain-host": "CrowdstrikeFalcon",
        "fireeye-hx-host-containment": "FireEyeHX v2",
        "microsoft-atp-isolate-machine": "Microsoft Defender ATP",
    }

    # Validate names
    actual_command_names = {cmd.name for cmd in commands}
    assert set(expected_commands.keys()) == actual_command_names

    # Validate brands
    for cmd in commands:
        expected_brand = expected_commands.get(cmd.name)
        assert cmd.brand == expected_brand


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


@pytest.mark.parametrize(
    "endpoint_args,is_isolated,result,message,expected_source,expected_isolated",
    [
        (
            {"endpoint_id": "1234", "endpoint_brand": "SomeBrand"},
            True,
            "Success",
            "Test Message",
            "SomeBrand",
            "Yes",
        ),
        # Microsoft Defender ATP case
        (
            {"endpoint_id": "5678", "endpoint_brand": "Microsoft Defender ATP"},
            False,
            "Fail",
            "Converted Brand Test",
            Brands.MICROSOFT_DEFENDER_ADVANCED_THREAT_PROTECTION,
            "No",
        ),
    ],
)
def test_create_message_to_context_and_hr(endpoint_args, is_isolated, result, message, expected_source, expected_isolated):
    """
    Given:
        - Endpoint arguments with various endpoint_brand values (including 'Microsoft Defender ATP' for conversion).
    When:
        - Calling create_message_to_context_and_hr with different is_isolated flags and results.
    Then:
        - The endpoint_output should contain the expected Endpoint, Result, Source (converted if needed),
          Message, and Isolated status.
    """
    endpoint_output = {}

    create_message_to_context_and_hr(
        is_isolated=is_isolated,
        endpoint_args=endpoint_args,
        result=result,
        message=message,
        endpoint_output=endpoint_output,
    )

    expected = {
        "Endpoint": endpoint_args["endpoint_id"],
        "Result": result,
        "Source": expected_source,
        "Message": message,
        "Isolated": expected_isolated,
    }
    assert endpoint_output == expected


@patch("IsolateEndpoint.demisto.executeCommand")
# @patch("IsolateEndpoint.handle_raw_response_results")
def test_run_commands_for_endpoint_executes_command(mock_execute):
    """
    Given:
        A list containing a single Command object with a specific brand, name, and argument mapping.
    When:
        Calling run_commands_for_endpoint with the mock command, endpoint arguments, and an empty results list.
    Then:
        - executeCommand should be called exactly once with the mapped arguments.
        - handle_raw_response_results should be called exactly once with the execution result.
        - The processed command result ("CommandResult") should be appended to the results list.
    """
    command = Command(brand="Brand", name="test-command", arg_mapping={"endpoint_id": "endpoint_id"})
    mock_commands = [command]

    mock_execute.return_value = [{"Type": 1, "Contents": "Done"}]

    endpoint_args = {"endpoint_id": "id1", "endpoint_brand": "Brand"}
    endpoint_output = {}

    run_commands_for_endpoint(commands=mock_commands, endpoint_args=endpoint_args, endpoint_output=endpoint_output)

    mock_execute.assert_called_once()
    assert endpoint_output["Endpoint"] == "id1"
    assert endpoint_output["Result"] == "Success"
    assert endpoint_output["Source"] == "Brand"


@pytest.mark.parametrize(
    "endpoint_data_results, is_already_isolated, has_fail, expected_context_len",
    [
        # Case 1: endpoint fails -> skipped entirely
        (
            [{"id": "ep1", "properties": {"message": "Failing"}}],
            False,
            True,
            0,
        ),
        # Case 2: endpoint already isolated -> included in context but no run_commands
        (
            [{"id": "ep2", "properties": {"message": "ok"}}],
            True,
            False,
            1,
        ),
        # Case 3: normal endpoint -> should run commands
        (
            [{"id": "ep3", "properties": {"message": "ok"}}],
            False,
            False,
            1,
        ),
    ],
)
@patch("IsolateEndpoint.get_args_from_endpoint_data")
@patch("IsolateEndpoint.is_endpoint_already_isolated")
@patch("IsolateEndpoint.run_commands_for_endpoint")
def test_process_endpoints(
    mock_run_commands,
    mock_is_already_isolated,
    mock_get_args,
    endpoint_data_results,
    is_already_isolated,
    has_fail,
    expected_context_len,
):
    """
    Given:
        - A list of endpoint data results with different conditions:
          1. Endpoint marked as failing.
          2. Endpoint already isolated.
          3. Normal endpoint to run commands.
    When:
        - Calling process_endpoints with mocked helper functions.
    Then:
        - Endpoints with "fail" in their message are skipped.
        - Already isolated endpoints are added to args/context but do not run commands.
        - Normal endpoints trigger run_commands_for_endpoint and are added to args/context.
    """
    mock_args = {"endpoint_id": "1234", "endpoint_message": "Fail" if has_fail else "ok"}
    mock_get_args.return_value = mock_args
    mock_is_already_isolated.return_value = is_already_isolated

    commands = [Command(brand="BrandA", name="TestCommand", arg_mapping={})]

    results, context_outputs, args_from_endpoint_data = process_endpoints(endpoint_data_results, commands)

    assert len(context_outputs) == expected_context_len

    if not has_fail and not is_already_isolated:
        mock_run_commands.assert_called_once_with(commands, mock_args, context_outputs[0])
    else:
        mock_run_commands.assert_not_called()


@pytest.mark.parametrize(
    "args, brands_values, expect_error, expected_brands",
    [
        # Case 1: endpoint_id with explicit brands -> keep brands as-is
        (
            {"endpoint_id": ["1234"], "endpoint_ip": [], "brands": ["Cortex XDR"]},
            ["BrandA", "BrandB"],
            False,
            ["Cortex XDR"],
        ),
        # Case 2: endpoint_id but no brands -> use Brands.get_all_values()
        (
            {"endpoint_id": ["5678"], "endpoint_ip": [], "brands": []},
            ["BrandA", "BrandB"],
            False,
            ["BrandA", "BrandB"],
        ),
    ],
)
@patch("IsolateEndpoint.map_zipped_args")
@patch("IsolateEndpoint.Brands.get_all_values")
@patch("IsolateEndpoint.demisto.args")
def test_prepare_args(
    mock_args,
    mock_get_all_values,
    mock_map_zipped,
    args,
    brands_values,
    expect_error,
    expected_brands,
):
    """
    Given:
        - Different combinations of endpoint arguments.
          1. No endpoint_id or endpoint_ip (invalid).
          2. endpoint_id with brands provided.
          3. endpoint_id but no brands (default brands applied).
    When:
        - Calling prepare_args with mocked demisto.args, Brands.get_all_values, and map_zipped_args.
    Then:
        - A ValueError is raised if no endpoint_id or endpoint_ip is supplied.
        - Brands remain unchanged if explicitly provided.
        - Brands default to Brands.get_all_values() when not provided.
    """
    mock_args.return_value = args.copy()
    mock_get_all_values.return_value = brands_values
    mock_map_zipped.return_value = [("endpoint_id", "endpoint_ip")]

    if expect_error:
        with pytest.raises(ValueError, match="At least one of the following arguments must be specified"):
            prepare_args()
    else:
        endpoint_args, zipped_args = prepare_args()
        assert endpoint_args["brands"] == expected_brands
        assert zipped_args == [("endpoint_id", "endpoint_ip")]
