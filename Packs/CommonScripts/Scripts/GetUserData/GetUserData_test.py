from pytest_mock import MockerFixture

import demistomock as demisto
from CommonServerPython import *

from GetUserData import (
    create_account,
    merge_accounts,
    Modules,
    prepare_human_readable,
    get_output_key,
    get_outputs,
    run_execute_command,
)


def test_create_account_with_all_fields():
    """
    Given:
        All fields are provided for an account.

    When:
        create_account is called with these fields.

    Then:
        It should return a dictionary with all the provided information.
    """
    account = create_account(
        id="123",
        username="johndoe",
        display_name="John Doe",
        email_address="john@example.com",
        groups=["Group1", "Group2"],
        type="AD",
        job_title="Developer",
        office="New York",
        telephone_number="123-456-7890",
        is_enabled=True,
        manager_email="manager@example.com",
        manager_display_name="Manager Name",
        risk_level="LOW",
    )

    assert account == {
        "id": "123",
        "username": "johndoe",
        "display_name": "John Doe",
        "email_address": "john@example.com",
        "groups": ["Group1", "Group2"],
        "type": "AD",
        "job_title": "Developer",
        "office": "New York",
        "telephone_number": "123-456-7890",
        "is_enabled": True,
        "manager_email": "manager@example.com",
        "manager_display_name": "Manager Name",
        "risk_level": "LOW",
    }


def test_create_account_with_partial_fields():
    """
    Given:
        Only some fields are provided for an account.

    When:
        create_account is called with these fields.

    Then:
        It should return a dictionary with only the provided information.
    """
    account = create_account(
        id="456", username="janedoe", email_address="jane@example.com", is_enabled=False
    )

    assert account == {
        "id": "456",
        "username": "janedoe",
        "email_address": "jane@example.com",
        "is_enabled": False,
    }


def test_create_account_with_single_item_list():
    """
    Given:
        A field is provided as a single-item list.

    When:
        create_account is called with this field.

    Then:
        It should return a dictionary with the field value extracted from the list.
    """
    account = create_account(id="789", username="bobsmith", groups=["SingleGroup"])

    assert account == {"id": "789", "username": "bobsmith", "groups": "SingleGroup"}


def test_create_account_with_empty_fields():
    """
    Given:
        All fields are provided as None or empty lists.

    When:
        create_account is called with these fields.

    Then:
        It should return an empty dictionary.
    """
    account = create_account(
        id=None,
        username=None,
        display_name=None,
        email_address=None,
        groups=[],
        type=None,
        job_title=None,
        office=None,
        telephone_number=None,
        is_enabled=None,
        manager_email=None,
        manager_display_name=None,
        risk_level=None,
    )

    assert account == {}


def test_merge_accounts_with_no_conflicts(mocker: MockerFixture):
    """
    Given:
        A list of account dictionaries with no conflicting values.

    When:
        merge_accounts is called with these dictionaries.

    Then:
        It should return a merged dictionary with all unique key-value pairs.
    """
    mock_account = mocker.Mock()
    mock_account.to_context.return_value = {
        "Account": {"id": "123", "name": "John Doe", "email": "john@example.com"}
    }
    mocker.patch.object(Common, "Account", return_value=mock_account)
    mocker.patch.object(Common.Account, "CONTEXT_PATH", "Account")

    accounts = [{"id": "123"}, {"name": "John Doe"}, {"email": "john@example.com"}]

    result = merge_accounts(accounts)

    assert result == {"id": "123", "name": "John Doe", "email": "john@example.com"}


def test_merge_accounts_with_conflicts(mocker: MockerFixture):
    """
    Given:
        A list of account dictionaries with conflicting values.

    When:
        merge_accounts is called with these dictionaries.

    Then:
        It should return a merged dictionary with the first encountered value
        for conflicting keys and log debug messages for conflicts.
    """
    mock_account = mocker.Mock()
    mock_account.to_context.return_value = {
        "Account": {"id": "123", "name": "John Doe", "email": "john@example.com"}
    }
    mocker.patch.object(Common, "Account", return_value=mock_account)
    mocker.patch.object(Common.Account, "CONTEXT_PATH", "Account")
    mock_debug = mocker.patch.object(demisto, "debug")

    accounts = [
        {"id": "123", "name": "John Doe"},
        {"id": "456", "email": "john@example.com"},
        {"name": "Jane Doe"},
    ]

    result = merge_accounts(accounts)

    assert result == {"id": "123", "name": "John Doe", "email": "john@example.com"}
    mock_debug.assert_any_call("Conflicting values for key 'id': '123' vs '456'")
    mock_debug.assert_any_call(
        "Conflicting values for key 'name': 'John Doe' vs 'Jane Doe'"
    )


def test_merge_accounts_with_empty_list():
    """
    Given:
        An empty list of account dictionaries.

    When:
        merge_accounts is called with this empty list.

    Then:
        It should return an empty dictionary.
    """
    result = merge_accounts([])

    assert result == {}


def test_merge_accounts_with_single_account(mocker: MockerFixture):
    """
    Given:
        A list containing a single account dictionary.

    When:
        merge_accounts is called with this list.

    Then:
        It should return a dictionary with the same key-value pairs as the input account.
    """
    mock_account = mocker.Mock()
    mock_account.to_context.return_value = {
        "Account": {"id": "123", "name": "John Doe"}
    }
    mocker.patch.object(Common, "Account", return_value=mock_account)
    mocker.patch.object(Common.Account, "CONTEXT_PATH", "Account")

    accounts = [{"id": "123", "name": "John Doe"}]

    result = merge_accounts(accounts)

    assert result == {"id": "123", "name": "John Doe"}


def test_modules_init_with_active_brands():
    """
    Given:
        A dictionary of modules with some active brands.

    When:
        Initializing a Modules instance with this dictionary.

    Then:
        The _enabled_brands set should contain only the active brands.
    """
    mock_modules = {
        "module1": {"brand": "Brand1", "state": "active"},
        "module2": {"brand": "Brand2", "state": "inactive"},
        "module3": {"brand": "Brand3", "state": "active"},
    }
    modules = Modules(mock_modules)

    assert modules._enabled_brands == {"Brand1", "Brand3"}


def test_modules_init_with_no_active_brands():
    """
    Given:
        A dictionary of modules with no active brands.

    When:
        Initializing a Modules instance with this dictionary.

    Then:
        The _enabled_brands set should be empty.
    """
    mock_modules = {
        "module1": {"brand": "Brand1", "state": "inactive"},
        "module2": {"brand": "Brand2", "state": "inactive"},
        "module3": {"brand": "Brand3", "state": "inactive"},
    }
    modules = Modules(mock_modules)

    assert modules._enabled_brands == set()


def test_is_brand_available_with_active_brand():
    """
    Given:
        A Modules instance with an active brand.

    When:
        Checking if the active brand is available.

    Then:
        The method should return True.
    """
    mock_modules = {
        "module1": {"brand": "ActiveBrand", "state": "active"},
        "module2": {"brand": "InactiveBrand", "state": "inactive"},
    }
    modules = Modules(mock_modules)

    assert modules.is_brand_available("ActiveBrand") is True


def test_is_brand_available_with_inactive_brand():
    """
    Given:
        A Modules instance with an inactive brand.

    When:
        Checking if the inactive brand is available.

    Then:
        The method should return False.
    """
    mock_modules = {
        "module1": {"brand": "ActiveBrand", "state": "active"},
        "module2": {"brand": "InactiveBrand", "state": "inactive"},
    }
    modules = Modules(mock_modules)

    assert modules.is_brand_available("InactiveBrand") is False


def test_is_brand_available_with_nonexistent_brand():
    """
    Given:
        A Modules instance with some brands.

    When:
        Checking if a nonexistent brand is available.

    Then:
        The method should return False.
    """
    mock_modules = {
        "module1": {"brand": "ActiveBrand", "state": "active"},
        "module2": {"brand": "InactiveBrand", "state": "inactive"},
    }
    modules = Modules(mock_modules)

    assert modules.is_brand_available("NonexistentBrand") is False


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
        == "#### Result for !test-command arg1=value1 arg2=value2\nTest output"
    )
    assert result[0].mark_as_note is True


def test_prepare_human_readable_error():
    """
    Given:
        A command name, arguments, and human-readable output for a command execution that resulted in an error.

    When:
        prepare_human_readable is called with these inputs and is_error set to True.

    Then:
        It should return a list with a single CommandResults object containing the formatted error output.
    """
    command_name = "test-command"
    args = {"arg1": "value1"}
    human_readable = "Error occurred"

    result = prepare_human_readable(command_name, args, human_readable, is_error=True)

    assert len(result) == 1
    assert isinstance(result[0], CommandResults)
    assert (
        result[0].readable_output
        == "#### Error for !test-command arg1=value1\nError occurred"
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
    assert result[0].readable_output == "#### Result for !test-command \nTest output"
    assert result[0].mark_as_note is True


def test_get_output_key_exact_match(mocker: MockerFixture):
    """
    Given:
        A raw_context dictionary with an exact match for the output_key.

    When:
        get_output_key is called with the matching output_key.

    Then:
        The function should return the exact matching key.
    """
    raw_context = {"Account": {"Username": "john.doe"}}
    mock_debug = mocker.patch.object(demisto, "debug")

    result = get_output_key("Account", raw_context)

    assert result == "Account"
    mock_debug.assert_not_called()


def test_get_output_key_partial_match(mocker: MockerFixture):
    """
    Given:
        A raw_context dictionary with a key that starts with the output_key followed by a parenthesis.

    When:
        get_output_key is called with the partial matching output_key.

    Then:
        The function should return the full key that starts with the output_key.
    """
    raw_context = {"Account(val.ID == obj.ID)": [{"Username": "john.doe"}]}
    mock_debug = mocker.patch.object(demisto, "debug")

    result = get_output_key("Account", raw_context)

    assert result == "Account(val.ID == obj.ID)"
    mock_debug.assert_not_called()


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


def test_get_output_key_empty_context():
    """
    Given
        An empty raw_context dictionary.

    When:
        get_output_key is called with any output_key.

    Then:
        The function should return an empty string without logging any debug message.
    """
    result = get_output_key("Account", {})

    assert result == ""


def test_get_outputs_with_single_item():
    """
    Given:
        A raw_context dictionary with a single item for the output key.

    When:
        get_outputs is called with the output key.

    Then:
        It should return the single item as a dictionary.
    """
    raw_context = {
        "Account(val.Username == obj.Username)": {
            "Username": "john.doe",
            "Email": "john.doe@example.com",
            "DisplayName": "John Doe",
        }
    }
    output_key = "Account(val.Username == obj.Username)"

    result = get_outputs(output_key, raw_context)

    assert result == {
        "Username": "john.doe",
        "Email": "john.doe@example.com",
        "DisplayName": "John Doe",
    }


def test_get_outputs_with_list():
    """
    Given:
        A raw_context dictionary with a list for the output key.

    When:
        get_outputs is called with the output key.

    Then:
        It should return the first item of the list as a dictionary.
    """
    raw_context = {
        "Account(val.Username == obj.Username)": [
            {
                "Username": "john.doe",
                "Email": "john.doe@example.com",
                "DisplayName": "John Doe",
            },
            {
                "Username": "jane.doe",
                "Email": "jane.doe@example.com",
                "DisplayName": "Jane Doe",
            },
        ]
    }
    output_key = "Account(val.Username == obj.Username)"

    result = get_outputs(output_key, raw_context)

    assert result == {
        "Username": "john.doe",
        "Email": "john.doe@example.com",
        "DisplayName": "John Doe",
    }


def test_get_outputs_with_empty_context():
    """
    Given:
        An empty raw_context dictionary.

    When:
        get_outputs is called with any output key.

    Then:
        It should return an empty dictionary.
    """
    raw_context = {}
    output_key = "Account(val.Username == obj.Username)"

    result = get_outputs(output_key, raw_context)

    assert result == {}


def test_get_outputs_with_missing_key():
    """
    Given:
        A raw_context dictionary without the specified output key.

    When:
        get_outputs is called with a non-existent output key.

    Then:
        It should return an empty dictionary.
    """
    raw_context = {"OtherKey": {"SomeData": "Value"}}
    output_key = "Account(val.Username == obj.Username)"

    result = get_outputs(output_key, raw_context)

    assert result == {}


def test_run_execute_command_success(mocker):
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


def test_run_execute_command_error(mocker):
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
    mocker.patch("GetUserData.is_error", return_value=True)
    mocker.patch("GetUserData.get_error", return_value="Error occurred")

    # Mock the prepare_human_readable function
    mock_prepare_human_readable = mocker.patch(
        "GetUserData.prepare_human_readable",
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


def test_run_execute_command_multiple_entries(mocker):
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
