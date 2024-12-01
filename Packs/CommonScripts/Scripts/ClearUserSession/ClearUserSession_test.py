from pytest_mock import MockerFixture

import demistomock as demisto
from CommonServerPython import *

from ClearUserSession import (
    Command,
    prepare_human_readable,
    get_output_key,
    run_execute_command,
    remove_system_user,
    extract_usernames_with_ids,
    get_user_data,
    get_user_id,
    clear_user_sessions,
    main,
)


def test_is_valid_args_with_valid_args():
    """
    Given:
        A Command object with valid arguments.

    When:
        is_valid_args is called with this Command object.

    Then:
        The function should return True.
    """
    command = Command(brand="TestBrand", name="test-command", args={"user_id": "123"})

    result = Command.is_valid_args(command)

    assert result is True


def test_is_valid_args_with_empty_args():
    """
    Given:
        A Command object with empty arguments.

    When:
        is_valid_args is called with this Command object.

    Then:
        The function should return True (as per the implementation).
    """
    command = Command(brand="TestBrand", name="test-command", args={})

    result = Command.is_valid_args(command)

    assert result is True


def test_is_valid_args_with_none_args():
    """
    Given:
        A Command object with None as arguments.

    When:
        is_valid_args is called with this Command object.

    Then:
        The function should return True (as per the implementation).
    """
    command = Command(brand="TestBrand", name="test-command", args=None)

    result = Command.is_valid_args(command)

    assert result is True


def test_is_valid_args_with_all_empty_values(mocker: MockerFixture):
    """
    Given:
        A Command object with arguments that all have empty values.

    When:
        is_valid_args is called with this Command object.

    Then:
        The function should return False and log a debug message.
    """
    command = Command(
        brand="TestBrand",
        name="test-command",
        args={"user_id": "", "user_name": "", "user_email": ""},
    )
    mock_debug = mocker.patch.object(demisto, "debug")

    result = Command.is_valid_args(command)

    assert result is False
    mock_debug.assert_called_once_with(
        "Skipping command 'test-command' since no required arguments were provided."
    )


def test_prepare_human_readable_success():
    """
    Given:
        A command name, arguments, and human-readable output for a successful command execution.

    When:
        prepare_human_readable is called with these inputs.

    Then:
        It should return a list with a single CommandResults object containing the formatted output.
    """
    command_name = "test-command"
    args = {"arg1": "value1", "arg2": "value2"}
    human_readable = "Test output"

    result = prepare_human_readable(command_name, args, human_readable)

    assert len(result) == 1
    assert isinstance(result[0], CommandResults)
    assert (
        result[0].readable_output
        == "#### Result for test-command arg1=value1 arg2=value2\nTest output"
    )
    assert result[0].mark_as_note is True


def test_prepare_human_readable_error():
    """
    Given:
        A command name, arguments, and human-readable output for a command execution that resulted in an error.

    When:
        prepare_human_readable is called with these inputs and is_error set to True.

    Then: It should return a list with a single CommandResults object containing the formatted error output.
    """
    command_name = "test-command"
    args = {"arg1": "value1"}
    human_readable = "Error occurred"

    result = prepare_human_readable(command_name, args, human_readable, is_error=True)

    assert len(result) == 1
    assert isinstance(result[0], CommandResults)
    assert (
        result[0].readable_output
        == "#### Error for test-command arg1=value1\nError occurred"
    )
    assert result[0].entry_type == EntryType.ERROR
    assert result[0].mark_as_note is True


def test_prepare_human_readable_empty_output():
    """
    Given:
        A command name and arguments, but an empty human-readable output.

    When:
        prepare_human_readable is called with these inputs.

    Then:
        It should return an empty list.
    """
    command_name = "test-command"
    args = {"arg1": "value1"}
    human_readable = ""

    result = prepare_human_readable(command_name, args, human_readable)

    assert result == []


def test_prepare_human_readable_empty_args():
    """
    Given:
        A command name, empty arguments, and human-readable output.

    When:
        prepare_human_readable is called with these inputs.

    Then:
        It should return a list with a single CommandResults object containing the formatted output without arguments.
    """
    command_name = "test-command"
    args = {}
    human_readable = "Test output"

    result = prepare_human_readable(command_name, args, human_readable)

    assert len(result) == 1
    assert isinstance(result[0], CommandResults)
    assert result[0].readable_output == "#### Result for test-command \nTest output"
    assert result[0].mark_as_note is True


def test_get_output_key_exact_match():
    """
    Given:
        A raw_context dictionary with an exact match for the output_key.

    When:
        get_output_key is called with the matching output_key.

    Then:
        The function should return the exact matching key.
    """
    raw_context = {"Account": {"Username": "john.doe"}}

    result = get_output_key("Account", raw_context)

    assert result == "Account"


def test_get_output_key_partial_match():
    """
    Given:
        A raw_context dictionary with a key that starts with the output_key followed by a parenthesis.

    When:
        get_output_key is called with the partial matching output_key.

    Then:
        The function should return the full key that starts with the output_key.
    """
    raw_context = {"Account(val.ID == obj.ID)": [{"Username": "john.doe"}]}

    result = get_output_key("Account", raw_context)

    assert result == "Account(val.ID == obj.ID)"


def test_get_output_key_no_match(mocker: MockerFixture):
    """
    Given:
        A raw_context dictionary without any key matching the output_key.

    When:
        get_output_key is called with a non-matching output_key.

    Then:
        The function should return an empty string and log a debug message.
    """
    raw_context = {"User": {"Name": "John Doe"}}
    mock_debug = mocker.patch.object(demisto, "debug")

    result = get_output_key("Account", raw_context)

    assert result == ""
    mock_debug.assert_called_once_with(
        "Output key Account not found in entry context keys: ['User']"
    )


def test_run_execute_command_success(mocker: MockerFixture):
    """
    Given:
        A command name and arguments for a successful command execution.

    When:
        The run_execute_command function is called.

    Then:
        It should return the expected entry context, human readable output, and an empty list of errors.
    """
    # Mock the necessary Demisto functions
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[
            {
                "Type": 1,
                "Contents": {"some": "data"},
                "ContentsFormat": "json",
                "HumanReadable": "Command executed successfully",
                "EntryContext": {"ContextKey": "ContextValue"},
            }
        ],
    )

    # Call the function
    entry_context, human_readable, errors = run_execute_command(
        "test-command", {"arg1": "value1"}
    )

    # Assert the results
    assert entry_context == [{"ContextKey": "ContextValue"}]
    assert human_readable == "Command executed successfully"
    assert errors == []
    demisto.debug.assert_called_with("Finished executing command: test-command")


def test_run_execute_command_error(mocker: MockerFixture):
    """
    Given:
        A command name and arguments for a command execution that results in an error.

    When:
        The run_execute_command function is called.

    Then:
        It should return an empty entry context, empty human readable output,
        and a list containing a CommandResults object with the error.
    """
    # Mock the necessary Demisto functions
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[
            {
                "Type": 4,
                "Contents": "Error occurred",
                "ContentsFormat": "text",
            }
        ],
    )

    # Mock the is_error and get_error functions
    mocker.patch("ClearUserSession.is_error", return_value=True)
    mocker.patch("ClearUserSession.get_error", return_value="Error occurred")

    # Mock the prepare_human_readable function
    mock_prepare_human_readable = mocker.patch(
        "ClearUserSession.prepare_human_readable",
        return_value=[mocker.Mock(spec=CommandResults)],
    )

    # Call the function
    entry_context, human_readable, errors = run_execute_command(
        "test-command", {"arg1": "value1"}
    )

    # Assert the results
    assert entry_context == [{}]
    assert human_readable == ""
    assert len(errors) == 1
    assert isinstance(errors[0], CommandResults)
    mock_prepare_human_readable.assert_called_once_with(
        "test-command", {"arg1": "value1"}, "Error occurred", is_error=True
    )
    demisto.debug.assert_called_with("Finished executing command: test-command")


def test_run_execute_command_multiple_entries(mocker: MockerFixture):
    """
    Given:
        A command name and arguments for a command execution that returns multiple entries.

    When:
        The run_execute_command function is called.

    Then:
        It should return a list of entry contexts, concatenated human readable output, and an empty list of errors.
    """
    # Mock the necessary Demisto functions
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[
            {
                "Type": 1,
                "Contents": {"data1": "value1"},
                "ContentsFormat": "json",
                "HumanReadable": "First entry",
                "EntryContext": {"Context1": "Value1"},
            },
            {
                "Type": 1,
                "Contents": {"data2": "value2"},
                "ContentsFormat": "json",
                "HumanReadable": "Second entry",
                "EntryContext": {"Context2": "Value2"},
            },
        ],
    )

    # Call the function
    entry_context, human_readable, errors = run_execute_command(
        "test-command", {"arg1": "value1"}
    )

    # Assert the results
    assert entry_context == [{"Context1": "Value1"}, {"Context2": "Value2"}]
    assert human_readable == "First entry\nSecond entry"
    assert errors == []
    demisto.debug.assert_called_with("Finished executing command: test-command")


def test_main_successful_execution(mocker: MockerFixture):
    """
    Given:
        Valid arguments for user_name and brands.
        Mocked responses for get_user_data, clear_user_sessions.
    When:
        The main function is called.
    Then:
        - The get_user_data function should retrieve user IDs successfully.
        - The clear_user_sessions function should process sessions.
        - The return_results function should be called with the correct results.
    """
    # Mock demisto.args()
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "user_name": "user1, user2",
            "verbose": "false",
            "brands": "Okta v2,Microsoft Graph User"
        },
    )

    # Mock get_user_data
    mock_get_user_data = mocker.patch(
        "ClearUserSession.get_user_data",
        return_value=(
            [
                CommandResults(readable_output="#### Result for !get-user-data user_name..."),
                CommandResults(readable_output="#### Result for !get-user-data user_name..."),
            ],
            {
                "user1": [{"Source": "Okta v2", "Value": "123"}],
                "user2": [{"Source": "Microsoft Graph User", "Value": "456"}],
            },
        ),
    )

    # Mock clear_user_sessions
    mock_clear_user_sessions = mocker.patch(
        "ClearUserSession.clear_user_sessions",
        return_value=([CommandResults()], "", "")
    )

    # Mock return_results
    mock_return_results = mocker.patch("ClearUserSession.return_results")

    # Call the main function
    main()

    # Assert that return_results was called
    assert mock_get_user_data.called
    assert mock_clear_user_sessions.called
    assert mock_return_results.called


def test_main_user_not_found(mocker: MockerFixture):
    """
    Given:
        Valid user identification information is provided, but no user data is found.
    When:
        The main function is called.
    Then:
        The function should add the user to the users_not_found_list and return appropriate results.
    """
    # Mock demisto.args()
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "user_name": "user1, system"
        },
    )

    # Mock all user data retrieval functions to return empty results
    mocker.patch("ClearUserSession.get_user_data", return_value=([], {}))
    mocker.patch("ClearUserSession.clear_user_sessions", return_value=([], ""))

    # Mock return_results
    mock_return_results = mocker.patch("ClearUserSession.return_results")

    # Call the main function
    main()

    # Assert that return_results was called with the correct arguments
    mock_return_results.assert_called_once()
    args, _ = mock_return_results.call_args
    assert len(args[0]) == 1
    assert isinstance(args[0][0], CommandResults)
    assert "Skipping session clearing: User is a system user." in args[0][0].readable_output
    assert (
        "user1" in args[0][0].readable_output
    )


def test_remove_system_user_with_system_users():
    users = ["administrator", "user1", "system", "user2"]

    # Expected filtered users and data for system users
    expected_filtered_users = ["user1", "user2"]
    expected_data_user = [
        {
            "UserName": "administrator",
            "Result": "Failed",
            "Message": "Skipping session clearing: User is a system user.",
            "Source": [],
        },
        {
            "UserName": "system",
            "Result": "Failed",
            "Message": "Skipping session clearing: User is a system user.",
            "Source": [],
        }
    ]

    filtered_users, data_user = remove_system_user(users)

    # Assertions to verify the correctness of the result
    assert filtered_users == expected_filtered_users
    assert data_user == expected_data_user


def test_remove_system_user_no_system_users():
    users = ["user1", "user2"]

    # When there are no system users, the output should be the same
    expected_filtered_users = ["user1", "user2"]
    expected_data_user = []

    filtered_users, data_user = remove_system_user(users)

    assert filtered_users == expected_filtered_users
    assert data_user == expected_data_user


def test_extract_usernames_with_ids():
    context = {
        "Account(val.Username && val.Username == obj.Username)": [
            {
                "ID": [{"Source": "Okta v2", "Value": "1234"}],
                "Username": "user1@test.com",
            },
            {
                "ID": [{"Source": "Microsoft Graph User", "Value": "5678"}],
                "Username": "user2@demistodev.onmicrosoft.com",
            },
            {
                "ID": [{"Source": "Okta v2", "Value": "789"}],
                "Username": "user3@example.com",
            },
            {
                "ID": [],
                "Username": "user4@example.com",
            }
        ]
    }
    output_key = "Account(val.Username && val.Username == obj.Username)"

    expected_result = {
        "user1@test.com": [{"Source": "Okta v2", "Value": "1234"}],
        "user2@demistodev.onmicrosoft.com": [{"Source": "Microsoft Graph User", "Value": "5678"}],
        "user3@example.com": [{"Source": "Okta v2", "Value": "789"}],
    }

    result = extract_usernames_with_ids(context, output_key)

    assert result == expected_result


def test_get_user_data(mocker: MockerFixture):
    command = Command(name="get-user-data", args={"user_name": ["user1", "user2"], "brands": "brand_name"})

    expected_entry_context = [{"Account(val.Username && val.Username == obj.Username)": [
        {"ID": [{"Source": "Okta v2", "Value": "1234"}], "Username": "user1@test.com"},
        {"ID": [{"Source": "Microsoft Graph User", "Value": "5678"}], "Username": "user2@demistodev.onmicrosoft.com"}
    ]}]
    expected_id_info = {
        "user1@test.com": [{"Source": "Okta v2", "Value": "1234"}],
        "user2@demistodev.onmicrosoft.com": [{"Source": "Microsoft Graph User", "Value": "5678"}]
    }

    # Mocking the functions
    mocker.patch("ClearUserSession.run_execute_command", return_value=(expected_entry_context, "Human-readable output",
                                                                       [CommandResults(), CommandResults()]))

    # Calling the function
    _, id_info = get_user_data(command)

    assert id_info == expected_id_info


def test_get_user_id():
    users_ids = {
        "user1@test.com": [{"Source": "Okta v2", "Value": "1234"}],
        "user2@test.com": [
            {"Source": "Microsoft Graph User", "Value": "5678"},
            {"Source": "Okta v2", "Value": "91011"}
        ],
    }
    brand_name = "Okta v2"
    user_name = "user1@test.com"

    expected_result = "1234"

    result = get_user_id(users_ids, brand_name, user_name)

    assert result == expected_result


def test_clear_user_sessions(mocker: MockerFixture):
    command = Command(name="okta-clear-sessions", args={"user_id": "12345"})

    expected_error_message = "Error: User session clearance failed."

    # Mocking `run_execute_command` to return simulated results
    mocker.patch(
        "ClearUserSession.run_execute_command",
        return_value=(
            [],
            "Session clearance completed successfully.",
            [CommandResults(readable_output="Error: User session clearance failed.")],
        ),
    )

    _, _, error_message = clear_user_sessions(command)
    assert error_message == expected_error_message
