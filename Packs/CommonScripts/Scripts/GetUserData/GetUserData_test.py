from pytest_mock import MockerFixture

import demistomock as demisto
from CommonServerPython import *

from GetUserData import (
    Modules,
    Command,
    is_valid_args,
    create_account,
    merge_accounts,
    enrich_data_with_source,
    prepare_human_readable,
    get_output_key,
    get_outputs,
    run_execute_command,
    identityiq_search_identities,
    identitynow_get_accounts,
    ad_get_user,
    ad_get_user_manager,
    pingone_get_user,
    okta_get_user,
    aws_iam_get_user,
    msgraph_user_get,
    msgraph_user_get_manager,
    xdr_list_risky_users,
    iam_get_user_command,
    main,
)


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
    modules = Modules(mock_modules, [])

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
    modules = Modules(mock_modules, [])

    assert modules._enabled_brands == set()


def test_is_brand_in_brands_to_run_brand_in_list():
    """
    Given:
        A Modules instance with a list of brands to run.

    When:
        is_brand_in_brands_to_run is called with a Command for a brand in the list.

    Then:
        The method should return True.
    """
    modules = Modules({}, ["Brand1", "Brand2", "Brand3"])
    command = Command(brand="Brand2", name="test-command", args={})

    result = modules.is_brand_in_brands_to_run(command)

    assert result is True


def test_is_brand_in_brands_to_run_brand_not_in_list(mocker: MockerFixture):
    """
    Given:
        A Modules instance with a list of brands to run.

    When:
        is_brand_in_brands_to_run is called with a Command for a brand not in the list.

    Then:
        The method should return False and log a debug message.
    """
    modules = Modules({}, ["Brand1", "Brand2", "Brand3"])
    command = Command(brand="Brand4", name="test-command", args={})
    mock_debug = mocker.patch.object(demisto, "debug")

    result = modules.is_brand_in_brands_to_run(command)

    assert result is False
    mock_debug.assert_called_once_with(
        "Skipping command 'test-command' since the brand 'Brand4' is not in the list of brands to run."
    )


def test_is_brand_in_brands_to_run_empty_brands_list():
    """
    Given:
        A Modules instance with an empty list of brands to run.

    When:
        is_brand_in_brands_to_run is called with any Command.

    Then:
        The method should return True.
    """
    modules = Modules({}, [])
    command = Command(brand="AnyBrand", name="test-command", args={})

    result = modules.is_brand_in_brands_to_run(command)

    assert result is True


def test_is_brand_available_brand_enabled_and_in_brands_to_run(mocker: MockerFixture):
    """
    Given:
        A Modules instance with an enabled brand that is in the brands to run.

    When:
        is_brand_available is called with a Command for that brand.

    Then:
        The method should return True.
    """
    mock_modules = {"module1": {"brand": "TestBrand", "state": "active"}}
    modules = Modules(mock_modules, ["TestBrand"])
    mocker.patch.object(modules, "is_brand_in_brands_to_run", return_value=True)

    command = Command(brand="TestBrand", name="test-command", args={})
    result = modules.is_brand_available(command)

    assert result is True


def test_is_brand_available_brand_not_enabled(mocker: MockerFixture):
    """
    Given:
        A Modules instance with a brand that is not enabled.

    When:
        is_brand_available is called with a Command for that brand.

    Then:
        The method should return False and log a debug message.
    """
    mock_modules = {"module1": {"brand": "TestBrand", "state": "inactive"}}
    modules = Modules(mock_modules, [])
    mock_debug = mocker.patch.object(demisto, "debug")

    command = Command(brand="TestBrand", name="test-command", args={})
    result = modules.is_brand_available(command)

    assert result is False
    mock_debug.assert_called_once_with(
        "Skipping command 'test-command' since the brand 'TestBrand' is not available."
    )


def test_is_brand_available_brand_not_in_brands_to_run(mocker: MockerFixture):
    """
    Given:
        A Modules instance with an enabled brand that is not in the brands to run.

    When:
        is_brand_available is called with a Command for that brand.

    Then:
        The method should return False.
    """
    mock_modules = {"module1": {"brand": "TestBrand", "state": "active"}}
    modules = Modules(mock_modules, ["OtherBrand"])
    mocker.patch.object(modules, "is_brand_in_brands_to_run", return_value=False)

    command = Command(brand="TestBrand", name="test-command", args={})
    result = modules.is_brand_available(command)

    assert result is False


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

    result = is_valid_args(command)

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

    result = is_valid_args(command)

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

    result = is_valid_args(command)

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

    result = is_valid_args(command)

    assert result is False
    mock_debug.assert_called_once_with(
        "Skipping command 'test-command' since no required arguments were provided."
    )


def test_create_account_with_minimal_info():
    """
    Given:
        Minimal account information (source and username).
    When:
        The create_account function is called.
    Then:
        It should return a dictionary with the provided information and source.
    """
    # Arrange
    source = "TestSource"
    username = "testuser"

    # Act
    result = create_account(source=source, username=username)

    # Assert
    assert result == {"username": {"Value": "testuser", "Source": "TestSource"}}


def test_create_account_with_all_fields():
    """
    Given:
        All fields are provided for an account.

    When:
        create_account is called with these fields.

    Then:
        It should return a dictionary with all the provided information.
    """
    account_info = {
        "source": "FullTestSource",
        "id": "123",
        "username": "fulluser",
        "display_name": "Full User",
        "email_address": "full@test.com",
        "groups": ["group1", "group2"],
        "type": "employee",
        "job_title": "Manager",
        "office": "HQ",
        "telephone_number": "123-456-7890",
        "is_enabled": True,
        "manager_email": "manager@test.com",
        "manager_display_name": "Manager Name",
        "risk_level": "Low",
    }

    result = create_account(**account_info)

    expected = {
        k: {"Value": v, "Source": "FullTestSource"}
        for k, v in account_info.items()
        if k != "source"
    }
    assert result == expected


def test_create_account_with_additional_fields():
    """
    Given:
        Account information with additional fields.
    When:
        The create_account function is called with extra kwargs.
    Then:
        It should include the additional fields in the result.
    """
    source = "ExtraSource"
    username = "extrauser"
    extra_field = "extra_value"

    result = create_account(source=source, username=username, extra_field=extra_field)

    assert result == {
        "username": {"Value": "extrauser", "Source": "ExtraSource"},
        "extra_field": {"Value": "extra_value", "Source": "ExtraSource"},
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
    source = "SingleListSource"
    username = "listuser"
    groups = ["singlegroup"]

    result = create_account(source=source, username=username, groups=groups)

    assert result == {
        "username": {"Value": "listuser", "Source": "SingleListSource"},
        "groups": {"Value": "singlegroup", "Source": "SingleListSource"},
    }


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
        source="EmptyFieldsSource",
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


def test_enrich_data_with_source_simple():
    """
    Given:
        A simple dictionary with string values and a source string.
    When:
        The enrich_data_with_source function is called with this data.
    Then:
        The function returns a dictionary with each value wrapped in a dictionary containing 'Value' and 'Source' keys.
    """
    data = {"name": "John", "age": "30"}
    source = "TestSource"

    result = enrich_data_with_source(data, source)

    expected = {
        "name": {"Value": "John", "Source": "TestSource"},
        "age": {"Value": "30", "Source": "TestSource"},
    }
    assert result == expected


def test_enrich_data_with_source_nested(mocker):
    """
    Given:
        A dictionary with nested structures and a source string.
    When:
        The enrich_data_with_source function is called with this data.
    Then:
        The function returns a dictionary with all values, including nested ones, enriched with source information.
    """
    data = {
        "user": {
            "name": "Alice",
            "contacts": {"email": "alice@example.com", "phone": ["123-456-7890"]},
        }
    }
    source = "UserDB"

    result = enrich_data_with_source(data, source)

    expected = {
        "user": {
            "name": {"Value": "Alice", "Source": "UserDB"},
            "contacts": {
                "email": {"Value": "alice@example.com", "Source": "UserDB"},
                "phone": {"Value": "123-456-7890", "Source": "UserDB"},
            },
        }
    }
    assert result == expected


def test_enrich_data_with_source_empty_elements(mocker):
    """
    Given:
        A dictionary with empty elements and a source string.
    When:
        The enrich_data_with_source function is called with this data.
    Then:
        The function returns a dictionary with empty elements removed and remaining elements enriched with source information.
    """
    mock_remove_empty = mocker.patch(
        "GetUserData.remove_empty_elements", return_value={"name": "John"}
    )

    data = {"name": "John", "age": "", "email": None}
    source = "CleanDB"

    result = enrich_data_with_source(data, source)

    mock_remove_empty.assert_called_once_with(data)
    expected = {"name": {"Value": "John", "Source": "CleanDB"}}
    assert result == expected


def test_merge_accounts_with_multiple_accounts():
    """
    Given:
        A list of multiple account dictionaries with various fields.
    When:
        The merge_accounts function is called with this list.
    Then:
        It should return a merged account dictionary with combined information from all input accounts.
    """
    accounts = [
        {
            "username": {"Value": "user1", "Source": "Source1"},
            "email_address": {"Value": "user1@example.com", "Source": "Source1"},
        },
        {
            "username": {"Value": "user1", "Source": "Source2"},
            "email_address": {"Value": "123-456-7890", "Source": "Source2"},
            "telephone_number": [{"Value": "123-456-7890", "Source": "Source2"}],
        },
    ]

    result = merge_accounts(accounts)

    assert result == {
        "Username": [
            {"Value": "user1", "Source": "Source1"},
            {"Value": "user1", "Source": "Source2"},
        ],
        "Email": {
            "Address": [
                {"Value": "user1@example.com", "Source": "Source1"},
                {"Value": "123-456-7890", "Source": "Source2"},
            ]
        },
        "TelephoneNumber": [{"Value": "123-456-7890", "Source": "Source2"}],
    }


def test_merge_accounts_with_nested_dictionaries():
    """
    Given:
        A list of account dictionaries with nested structures.
    When:
        The merge_accounts function is called with this list.
    Then:
        It should return a merged account dictionary with properly combined nested structures.
    """
    accounts = [
        {
            "personal_info": {
                "name": {"Value": "John Doe", "Source": "Source1"},
                "age": {"Value": 30, "Source": "Source1"},
            }
        },
        {
            "personal_info": {
                "name": {"Value": "John Doe", "Source": "Source2"},
                "address": {"Value": "123 Main St", "Source": "Source2"},
            }
        },
    ]

    result = merge_accounts(accounts)

    assert result == {
        "personal_info": {
            "name": [
                {"Value": "John Doe", "Source": "Source1"},
                {"Value": "John Doe", "Source": "Source2"},
            ],
            "age": [{"Value": 30, "Source": "Source1"}],
            "address": [{"Value": "123 Main St", "Source": "Source2"}],
        }
    }


def test_merge_accounts_with_empty_list():
    """
    Given:
        An empty list of account dictionaries.
    When:
        The merge_accounts function is called with this empty list.
    Then:
        It should return an empty dictionary.
    """
    result = merge_accounts([])

    assert result == {}


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
    args = {"arg1": "value1", "arg2": {"nested": "value2"}}
    human_readable = "Test output"

    result = prepare_human_readable(command_name, args, human_readable)

    assert len(result) == 1
    assert isinstance(result[0], CommandResults)
    assert (
        result[0].readable_output
        == '#### Result for !test-command arg1="value1" arg2="{\\\\"nested\\\\": \\\\"value2\\\\"}"\nTest output'
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
        == '#### Error for !test-command arg1="value1"\nError occurred'
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


class TestGetUserData:
    def test_identityiq_search_identities(self, mocker: MockerFixture):
        """
        Given:
            A Command object for identityiq_search_identities.
        When:
            The function is called with the Command object.
        Then:
            It returns the expected tuple of readable outputs and account output.
        """
        command = Command(
            "SailPointIdentityIQ", "identityiq-search-identities", {"id": "123"}
        )
        mock_outputs = {
            "id": "123",
            "userName": "test_user",
            "displayName": "Test User",
            "name": {"formatted": "Test User"},
            "emails": {"value": "test@example.com"},
            "active": True,
        }
        expected_account = {
            "id": {"Value": "123", "Source": "SailPointIdentityIQ"},
            "username": {"Value": "test_user", "Source": "SailPointIdentityIQ"},
            "display_name": {"Value": "Test User", "Source": "SailPointIdentityIQ"},
            "email_address": {
                "Value": "test@example.com",
                "Source": "SailPointIdentityIQ",
            },
            "is_enabled": {"Value": True, "Source": "SailPointIdentityIQ"},
            "name": {
                "formatted": {"Value": "Test User", "Source": "SailPointIdentityIQ"}
            },
        }

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="IdentityIQ.Identity")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = identityiq_search_identities(command)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert isinstance(result[1], dict)
        assert result[1] == expected_account

    def test_identitynow_get_accounts(self, mocker: MockerFixture):
        """
        Given:
            A Command object for identitynow_get_accounts.
        When:
            The function is called with the Command object.
        Then:
            It returns the expected tuple of readable outputs and account output.
        """
        command = Command(
            "SailPointIdentityNow", "identitynow-get-accounts", {"id": "456"}
        )
        mock_outputs = {"id": "456", "name": "test_account", "disabled": False}
        expected_account = {
            "id": {"Value": "456", "Source": "SailPointIdentityNow"},
            "username": {"Value": "test_account", "Source": "SailPointIdentityNow"},
            "is_enabled": {"Value": True, "Source": "SailPointIdentityNow"},
        }

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="IdentityNow.Account")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = identitynow_get_accounts(command)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert isinstance(result[1], dict)
        assert result[1] == expected_account

    def test_ad_get_user(self, mocker: MockerFixture):
        """
        Given:
            A Command object for ad_get_user.
        When:
            The function is called with the Command object.
        Then:
            It returns the expected tuple of readable outputs, account output, and manager DN.
        """
        command = Command(
            "Active Directory Query v2", "ad-get-user", {"username": "ad_user"}
        )
        mock_outputs = {
            "sAMAccountName": "ad_user",
            "displayName": "AD User",
            "mail": "ad_user@example.com",
            "memberOf": ["Group1"],
            "userAccountControlFields": {"ACCOUNTDISABLE": False},
            "manager": ["CN=Manager,OU=Users,DC=example,DC=com"],
        }
        expected_account = {
            "username": {"Value": "ad_user", "Source": "Active Directory Query v2"},
            "display_name": {"Value": "AD User", "Source": "Active Directory Query v2"},
            "email_address": {
                "Value": "ad_user@example.com",
                "Source": "Active Directory Query v2",
            },
            "groups": {"Value": "Group1", "Source": "Active Directory Query v2"},
            "is_enabled": {"Value": True, "Source": "Active Directory Query v2"},
        }

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="ActiveDirectory.Users")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = ad_get_user(command)

        assert isinstance(result, tuple)
        assert len(result) == 3
        assert isinstance(result[0], list)
        assert isinstance(result[1], dict)
        assert isinstance(result[2], str)
        assert result[1] == expected_account
        assert result[2] == "CN=Manager,OU=Users,DC=example,DC=com"

    def test_ad_get_user_attributes(self, mocker: MockerFixture):
        """
        Given:
            A Command object for ad_get_user.
        When:
            The function is called with the Command object and attributes.
        Then:
            It returns the expected tuple of readable outputs, account output, and manager DN.
        """
        command = Command(
            "Active Directory Query v2", "ad-get-user", {"username": "ad_user", "attributes": "whenCreated"}
        )
        mock_outputs = {
            "sAMAccountName": "ad_user",
            "displayName": "AD User",
            "mail": "ad_user@example.com",
            "memberOf": ["Group1"],
            "userAccountControlFields": {"ACCOUNTDISABLE": False},
            "manager": ["CN=Manager,OU=Users,DC=example,DC=com"],
            "whenCreated": ["2024-11-05 09:11:18+00:00"]
        }
        expected_account = {
            "username": {"Value": "ad_user", "Source": "Active Directory Query v2"},
            "display_name": {"Value": "AD User", "Source": "Active Directory Query v2"},
            "email_address": {
                "Value": "ad_user@example.com",
                "Source": "Active Directory Query v2",
            },
            "groups": {"Value": "Group1", "Source": "Active Directory Query v2"},
            "is_enabled": {"Value": True, "Source": "Active Directory Query v2"},
            "whenCreated": {'Source': 'Active Directory Query v2',
                            'Value': '2024-11-05 09:11:18+00:00'}
        }

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="ActiveDirectory.Users")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = ad_get_user(command)

        assert isinstance(result, tuple)
        assert len(result) == 3
        assert isinstance(result[0], list)
        assert isinstance(result[1], dict)
        assert isinstance(result[2], str)
        assert result[1] == expected_account
        assert result[2] == "CN=Manager,OU=Users,DC=example,DC=com"
        assert len(result[1])
        assert "whenCreated" in result[1]

    def test_ad_get_user_manager(self, mocker: MockerFixture):
        """
        Given:
            A Command object for ad_get_user_manager.
        When:
            The function is called with the Command object.
        Then:
            It returns the expected tuple of readable outputs and account output.
        """
        command = Command(
            "Active Directory Query v2",
            "ad-get-user",
            {"dn": "CN=Manager,OU=Users,DC=example,DC=com"},
        )
        mock_outputs = {"displayName": "Manager Name", "mail": "manager@example.com"}
        expected_account = {
            "manager_email": {
                "Value": "manager@example.com",
                "Source": "Active Directory Query v2",
            },
            "manager_display_name": {
                "Value": "Manager Name",
                "Source": "Active Directory Query v2",
            },
        }

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="ActiveDirectory.Users")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = ad_get_user_manager(command)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert isinstance(result[1], dict)
        assert result[1] == expected_account

    def test_pingone_get_user(self, mocker: MockerFixture):
        """
        Given:
            A Command object for pingone_get_user.
        When:
            The function is called with the Command object.
        Then:
            It returns the expected tuple of readable outputs and account output.
        """
        command = Command("PingOne", "pingone-get-user", {"userId": "789"})
        mock_outputs = {
            "ID": "789",
            "Username": "pingone_user",
            "DisplayName": "PingOne User",
            "Email": "pingone@example.com",
            "Enabled": True,
        }
        expected_account = {
            "id": {"Value": "789", "Source": "PingOne"},
            "username": {"Value": "pingone_user", "Source": "PingOne"},
            "display_name": {"Value": "PingOne User", "Source": "PingOne"},
            "email_address": {"Value": "pingone@example.com", "Source": "PingOne"},
            "is_enabled": {"Value": True, "Source": "PingOne"},
        }

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="PingOne.Account")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = pingone_get_user(command)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert isinstance(result[1], dict)
        assert result[1] == expected_account

    def test_okta_get_user(self, mocker: MockerFixture):
        """
        Given:
            A Command object for okta_get_user.
        When:
            The function is called with the Command object.
        Then:
            It returns the expected tuple of readable outputs and account output.
        """
        command = Command("Okta v2", "okta-get-user", {"userId": "101112"})
        mock_outputs = {
            "ID": "101112",
            "Username": "okta_user",
            "DisplayName": "Okta User",
            "Email": "okta@example.com",
            "Status": "ACTIVE",
            "Manager": "Okta Manager",
        }
        expected_account = {
            "id": {"Value": "101112", "Source": "Okta v2"},
            "username": {"Value": "okta_user", "Source": "Okta v2"},
            "display_name": {"Value": "Okta User", "Source": "Okta v2"},
            "email_address": {"Value": "okta@example.com", "Source": "Okta v2"},
            "is_enabled": {"Value": True, "Source": "Okta v2"},
            "manager_display_name": {"Value": "Okta Manager", "Source": "Okta v2"},
        }

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="Account")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = okta_get_user(command)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert isinstance(result[1], dict)
        assert result[1] == expected_account

    def test_aws_iam_get_user(self, mocker: MockerFixture):
        """
        Given:
            A Command object for aws_iam_get_user.
        When:
            The function is called with the Command object.
        Then:
            It returns the expected tuple of readable outputs and account output.
        """
        command = Command("AWS - IAM", "aws-iam-get-user", {"userName": "aws_user"})
        mock_outputs = {"UserId": "AIDAXXXXXXXXXXXXXXXX", "UserName": "aws_user"}
        expected_account = {
            "id": {"Value": "AIDAXXXXXXXXXXXXXXXX", "Source": "AWS - IAM"},
            "username": {"Value": "aws_user", "Source": "AWS - IAM"},
        }

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="AWS.IAM.Users")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = aws_iam_get_user(command)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert isinstance(result[1], dict)
        assert result[1] == expected_account

    def test_msgraph_user_get(self, mocker: MockerFixture):
        """
        Given:
            A Command object for msgraph_user_get.
        When:
            The function is called with the Command object.
        Then:
            It returns the expected tuple of readable outputs and account output.
        """
        command = Command(
            "Microsoft Graph User", "msgraph-user-get", {"user": "graph_user"}
        )
        mock_outputs = {
            "ID": "131415",
            "Username": "graph_user",
            "DisplayName": "Graph User",
            "Email": {"Address": "graph@example.com"},
            "JobTitle": "Developer",
            "Office": "HQ",
            "TelephoneNumber": "123-456-7890",
            "Type": "Member",
        }
        expected_account = {
            "id": {"Value": "131415", "Source": "Microsoft Graph User"},
            "username": {"Value": "graph_user", "Source": "Microsoft Graph User"},
            "display_name": {"Value": "Graph User", "Source": "Microsoft Graph User"},
            "email_address": {
                "Value": "graph@example.com",
                "Source": "Microsoft Graph User",
            },
            "job_title": {"Value": "Developer", "Source": "Microsoft Graph User"},
            "office": {"Value": "HQ", "Source": "Microsoft Graph User"},
            "telephone_number": {
                "Value": "123-456-7890",
                "Source": "Microsoft Graph User",
            },
            "type": {"Value": "Member", "Source": "Microsoft Graph User"},
        }

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="Account")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = msgraph_user_get(command)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert isinstance(result[1], dict)
        assert result[1] == expected_account

    def test_msgraph_user_get_manager(self, mocker: MockerFixture):
        """
        Given:
            A Command object for msgraph_user_get_manager.
        When:
            The function is called with the Command object.
        Then:
            It returns the expected tuple of readable outputs and account output.
        """
        command = Command(
            "Microsoft Graph User", "msgraph-user-get-manager", {"user": "graph_user"}
        )
        mock_outputs = {
            "Manager": {"DisplayName": "Graph Manager", "Mail": "manager@example.com"}
        }
        expected_account = {
            "manager_display_name": {
                "Value": "Graph Manager",
                "Source": "Microsoft Graph User",
            },
            "manager_email": {
                "Value": "manager@example.com",
                "Source": "Microsoft Graph User",
            },
        }

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="MSGraphUserManager")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = msgraph_user_get_manager(command)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert isinstance(result[1], dict)
        assert result[1] == expected_account

    def test_xdr_list_risky_users(self, mocker: MockerFixture):
        """
        Given:
            A Command object for xdr_list_risky_users.
        When:
            The function is called with the Command object.
        Then:
            It returns the expected tuple of readable outputs and account output.
        """
        user_name = "xdr_user"
        outputs_key_field = "PaloAltoNetworksXDR"
        command = Command(
            "Cortex XDR - IR", "xdr-list-risky-users", {"user_id": user_name}
        )
        mock_outputs = {"id": "xdr_user", "risk_level": "HIGH"}
        expected_account = {
            "id": {"Value": "xdr_user", "Source": "Cortex XDR - IR"},
            "risk_level": {"Value": "HIGH", "Source": "Cortex XDR - IR"},
            "username": {"Value": "xdr_user", "Source": "Cortex XDR - IR"},
        }

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch(
            "GetUserData.get_output_key", return_value="PaloAltoNetworksXDR.RiskyUser"
        )
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = xdr_list_risky_users(command, user_name, outputs_key_field)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert result[1] == expected_account

    def test_iam_get_user_command(self, mocker: MockerFixture):
        """
        Given:
            User identification data for iam_get_user_command.
        When:
            The iam_get_user_command function is called with the user data.
        Then:
            It returns the expected tuple of readable outputs and account outputs.
        """
        user_id = "789"
        user_name = "test_user"
        user_email = "test@example.com"
        domain = "example.com"

        mock_outputs = [
            {
                "success": True,
                "id": "789",
                "brand": "TestBrand",
                "username": "test_user",
                "email": "test@example.com",
                "active": True,
            }
        ]
        expected_accounts = [
            {
                "id": {"Value": "789", "Source": "TestBrand"},
                "username": {"Value": "test_user", "Source": "TestBrand"},
                "email_address": {"Value": "test@example.com", "Source": "TestBrand"},
                "is_enabled": {"Value": True, "Source": "TestBrand"},
                "success": {"Value": True, "Source": "TestBrand"},
            }
        ]

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=(
                [{"IAM.Vendor": mock_output} for mock_output in mock_outputs],
                "Human readable output",
                [],
            ),
        )
        mocker.patch("GetUserData.get_output_key", return_value="IAM.Vendor")
        mocker.patch("GetUserData.get_outputs", side_effect=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = iam_get_user_command(user_id, user_name, user_email, domain)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert isinstance(result[1], list)
        assert result[1] == expected_accounts


def test_main_successful_execution(mocker: MockerFixture):
    """
    Given:
        Valid arguments for user_id, user_name, and user_email.
    When:
        The main function is called.
    Then:
        The function should execute successfully and return results for the user.
    """
    # Mock demisto.args()
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "user_id": "123",
            "user_name": "johndoe",
            "user_email": "john@example.com",
        },
    )

    # Mock demisto.getModules()
    mocker.patch.object(demisto, "getModules", return_value={})

    # Mock other necessary functions
    mocker.patch("GetUserData.identitynow_get_accounts", return_value=([], {}))
    mocker.patch("GetUserData.ad_get_user", return_value=([], {}, None))
    mocker.patch("GetUserData.pingone_get_user", return_value=([], {}))
    mocker.patch("GetUserData.okta_get_user", return_value=([], {}))
    mocker.patch("GetUserData.aws_iam_get_user", return_value=([], {}))
    mocker.patch("GetUserData.msgraph_user_get", return_value=([], {}))
    mocker.patch("GetUserData.identityiq_search_identities", return_value=([], {}))
    mocker.patch("GetUserData.xdr_list_risky_users", return_value=([], {}))
    mocker.patch("GetUserData.iam_get_user_command", return_value=([], []))

    # Mock return_results
    mock_return_results = mocker.patch("GetUserData.return_results")

    # Call the main function
    main()

    # Assert that return_results was called
    assert mock_return_results.called


def test_main_no_user_info_provided(mocker: MockerFixture):
    """
    Given:
        No user identification information is provided in the arguments.
    When:
        The main function is called.
    Then:
        The function should raise a ValueError.
    """
    # Mock demisto.args() to return empty arguments
    mocker.patch.object(demisto, "args", return_value={})

    # Mock demisto.getModules()
    mocker.patch.object(demisto, "getModules", return_value={})

    # Mock return_error
    mock_return_error = mocker.patch("GetUserData.return_error")

    # Call the main function
    main()

    # Assert that return_error was called with the correct error message
    mock_return_error.assert_called_once_with(
        "Failed to execute get-user-data. Error: At least one of the following arguments must be specified: "
        "user_id, user_name or user_email."
    )


def test_main_domain_without_username(mocker: MockerFixture):
    """
    Given:
        A domain is provided in the arguments without a user_name.
    When:
        The main function is called.
    Then:
        The function should raise a ValueError.
    """
    # Mock demisto.args() to return a domain without a user_name
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "domain": "example.com",
            "user_id": "123",
        },
    )

    # Mock demisto.getModules()
    mocker.patch.object(demisto, "getModules", return_value={})

    # Mock return_error
    mock_return_error = mocker.patch("GetUserData.return_error")

    # Call the main function
    main()

    # Assert that return_error was called with the correct error message
    mock_return_error.assert_called_once_with(
        "Failed to execute get-user-data. Error: When specifying the domain argument, "
        "the user_name argument must also be provided."
    )


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
            "user_id": "123",
            "user_name": "johndoe",
            "user_email": "john@example.com",
        },
    )

    # Mock demisto.getModules()
    mocker.patch.object(demisto, "getModules", return_value={})

    # Mock all user data retrieval functions to return empty results
    mocker.patch("GetUserData.identitynow_get_accounts", return_value=([], {}))
    mocker.patch("GetUserData.ad_get_user", return_value=([], {}, None))
    mocker.patch("GetUserData.pingone_get_user", return_value=([], {}))
    mocker.patch("GetUserData.okta_get_user", return_value=([], {}))
    mocker.patch("GetUserData.aws_iam_get_user", return_value=([], {}))
    mocker.patch("GetUserData.msgraph_user_get", return_value=([], {}))
    mocker.patch("GetUserData.identityiq_search_identities", return_value=([], {}))
    mocker.patch("GetUserData.xdr_list_risky_users", return_value=([], {}))
    mocker.patch("GetUserData.iam_get_user_command", return_value=([], []))

    # Mock return_results
    mock_return_results = mocker.patch("GetUserData.return_results")

    # Call the main function
    main()

    # Assert that return_results was called with the correct arguments
    mock_return_results.assert_called_once()
    args, _ = mock_return_results.call_args
    assert len(args[0]) == 1
    assert isinstance(args[0][0], CommandResults)
    assert "User(s) not found" in args[0][0].readable_output
    assert (
        "123" in args[0][0].readable_output
        or "johndoe" in args[0][0].readable_output
        or "john@example.com" in args[0][0].readable_output
    )
