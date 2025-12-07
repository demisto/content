import demistomock as demisto
import pytest
from CommonServerPython import *
from GetUserData import (
    Command,
    Modules,
    ad_get_user,
    aws_iam_get_user,
    create_user,
    get_output_key,
    get_outputs,
    is_valid_args,
    main,
    msgraph_user_get,
    msgraph_user_get_manager,
    okta_get_user,
    prepare_human_readable,
    run_execute_command,
    run_list_risky_users_command,
    run_list_users_command,
    xdr_and_core_list_all_users,
    get_data,
    prisma_cloud_get_user,
    azure_get_risky_user,
    iam_get_user,
    gsuite_get_user,
)
from pytest_mock import MockerFixture


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
    mock_debug.assert_called_once_with("Skipping command 'test-command' since the brand 'TestBrand' is not available.")


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
    mock_debug.assert_called_once_with("Skipping command 'test-command' since no required arguments were provided.")


def test_create_user_with_minimal_info():
    """
    Given:
        Minimal user information (source and username).
    When:
        The create_user function is called.
    Then:
        It should return a dictionary with the provided information and source.
    """
    # Arrange
    source = "TestSource"
    username = "testuser"

    # Act
    result = create_user(source=source, username=username)

    # Assert
    assert result == {"Source": "TestSource", "Brand": "TestSource", "Username": "testuser", "Instance": None}


def test_create_user_with_additional_fields():
    """
    Given:
        Additional fields are provided for a user.

    When:
        create_user is called with these fields.

    Then:
        It should return a dictionary with additional_fields key.
    """
    user_info = {
        "source": "FullTestSource",
        "id": "123",
        "username": "fulluser",
        "display_name": "Full User",
        "email_address": "full@test.com",
        "job_title": "Manager",
        "manager_email": "manager@test.com",
        "manager_display_name": "Manager Name",
        "risk_level": "Low",
    }

    result = create_user(**user_info, additional_fields=True)
    expected = {
        "AdditionalFields": {
            "display_name": "Full User",
            "job_title": "Manager",
            "manager_display_name": "Manager Name",
            "manager_email": "manager@test.com",
        },
        "Email": "full@test.com",
        "ID": "123",
        "RiskLevel": "Low",
        "Source": "FullTestSource",
        "Brand": "FullTestSource",
        "Username": "fulluser",
        "Instance": None,
    }

    assert result == expected


def test_create_user_without_additional_fields():
    """
    Given:
        Additional fields are provided for a user with additional_fields arg set to false.

    When:
        create_user is called with these fields.

    Then:
        It should return a dictionary with main keys only.
    """
    user_info = {
        "source": "FullTestSource",
        "id": "123",
        "username": "fulluser",
        "display_name": "Full User",
        "email_address": "full@test.com",
        "job_title": "Manager",
        "manager_email": "manager@test.com",
        "manager_display_name": "Manager Name",
        "risk_level": "Low",
    }

    result = create_user(**user_info, additional_fields=False)
    expected = {
        "Email": "full@test.com",
        "ID": "123",
        "RiskLevel": "Low",
        "Source": "FullTestSource",
        "Brand": "FullTestSource",
        "Username": "fulluser",
        "Instance": None,
    }

    assert result == expected


def test_create_user_with_single_item_list():
    """
    Given:
        A field is provided as a single-item list.

    When:
        create_user is called with this field.

    Then:
        It should return a dictionary with the field value extracted from the list.
    """
    source = "SingleListSource"
    username = "listuser"
    groups = ["singlegroup"]

    result = create_user(source=source, username=username, groups=groups, additional_fields=True)

    assert result == {
        "AdditionalFields": {"groups": ["singlegroup"]},
        "Source": "SingleListSource",
        "Brand": "SingleListSource",
        "Username": "listuser",
        "Instance": None,
    }


def test_create_user_with_empty_fields():
    """
    Given:
        All fields are provided as None or empty lists.

    When:
        create_user is called with these fields.

    Then:
        It should return an empty dictionary.
    """
    user = create_user(
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
        additional_fields=True,
    )

    assert user == {"Source": "EmptyFieldsSource", "Brand": "EmptyFieldsSource", "Instance": None}


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
    assert result[0].readable_output == '#### Error for !test-command arg1="value1"\nError occurred'
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
    mock_debug.assert_called_once_with("Output key Account not found in entry context keys: ['User']")


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
                "ModuleName": "inst1",
            }
        ],
    )

    # Call the function
    entry_context, human_readable, errors = run_execute_command("test-command", {"arg1": "value1"})

    # Assert the results
    assert entry_context == [{"ContextKey": "ContextValue", "instance": "inst1"}]
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
                "ModuleName": "inst1",
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
    entry_context, human_readable, errors = run_execute_command("test-command", {"arg1": "value1"})

    # Assert the results
    assert entry_context == [{"instance": "inst1"}]
    assert human_readable == ""
    assert len(errors) == 1
    assert isinstance(errors[0], CommandResults)
    mock_prepare_human_readable.assert_called_once_with("test-command", {"arg1": "value1"}, "Error occurred", is_error=True)
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
                "ModuleName": "inst1",
            },
            {
                "Type": 1,
                "Contents": {"data2": "value2"},
                "ContentsFormat": "json",
                "HumanReadable": "Second entry",
                "EntryContext": {"Context2": "Value2"},
                "ModuleName": "inst2",
            },
        ],
    )

    # Call the function
    entry_context, human_readable, errors = run_execute_command("test-command", {"arg1": "value1"})

    # Assert the results
    assert entry_context == [
        {
            "Context1": "Value1",
            "instance": "inst1",
        },
        {
            "Context2": "Value2",
            "instance": "inst2",
        },
    ]
    assert human_readable == "First entry\nSecond entry"
    assert errors == []
    demisto.debug.assert_called_with("Finished executing command: test-command")


class TestGetUserData:
    def test_ad_get_user(self, mocker: MockerFixture):
        """
        Given:
            A Command object for ad_get_user.
        When:
            The function is called with the Command object.
        Then:
            It returns the expected tuple of readable outputs, account output, and manager DN.
        """
        command = Command("Active Directory Query v2", "ad-get-user", {"username": "ad_user"})
        mock_outputs = {
            "name": ["ad_user"],
            "sAMAccountName": ["ad_user_sam"],
            "displayName": ["AD User"],
            "mail": ["ad_user@example.com"],
            "memberOf": ["Group1", "Group2"],
            "userAccountControlFields": {"ACCOUNTDISABLE": False},
            "manager": ["CN=Manager,OU=Users,DC=example,DC=com"],
        }
        expected_user = [
            {
                "AdditionalFields": {
                    "displayName": "AD User",
                    "manager": "CN=Manager,OU=Users,DC=example,DC=com",
                    "memberOf": ["Group1", "Group2"],
                    "name": "ad_user",
                    "userAccountControlFields": {"ACCOUNTDISABLE": False},
                },
                "Email": "ad_user@example.com",
                "Source": "Active Directory Query v2",
                "Brand": "Active Directory Query v2",
                "Username": "ad_user_sam",
                "Instance": None,
            }
        ]

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="ActiveDirectory.Users")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = ad_get_user(command, additional_fields=True)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert result[1] == expected_user

    def test_ad_get_user_attributes(self, mocker: MockerFixture):
        """
        Given:
            A Command object for ad_get_user.
        When:
            The function is called with the Command object and attributes.
        Then:
            It returns the expected tuple of readable outputs, account output, and manager DN.
        """
        command = Command("Active Directory Query v2", "ad-get-user", {"username": "ad_user", "attributes": "whenCreated"})
        mock_outputs = {
            "name": "ad_user",
            "displayName": "AD User",
            "mail": "ad_user@example.com",
            "memberOf": ["Group1"],
            "userAccountControlFields": {"ACCOUNTDISABLE": False},
            "manager": ["CN=Manager,OU=Users,DC=example,DC=com"],
            "whenCreated": ["2024-11-05 09:11:18+00:00"],
        }
        expected_account = [
            {
                "AdditionalFields": {
                    "displayName": "AD User",
                    "manager": "CN=Manager,OU=Users,DC=example,DC=com",
                    "memberOf": "Group1",
                    "name": "ad_user",
                    "userAccountControlFields": {"ACCOUNTDISABLE": False},
                    "whenCreated": "2024-11-05 09:11:18+00:00",
                },
                "Email": "ad_user@example.com",
                "Source": "Active Directory Query v2",
                "Brand": "Active Directory Query v2",
                "Instance": None,
            }
        ]

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="ActiveDirectory.Users")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = ad_get_user(command, additional_fields=True)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
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
        expected_account = [
            {
                "AdditionalFields": {"DisplayName": "Okta User", "Manager": "Okta Manager", "Status": "ACTIVE"},
                "Email": "okta@example.com",
                "ID": "101112",
                "Source": "Okta v2",
                "Brand": "Okta v2",
                "Username": "okta_user",
                "Instance": None,
            }
        ]

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="Account")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = okta_get_user(command, additional_fields=True)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
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
        expected_account = [
            {"ID": "AIDAXXXXXXXXXXXXXXXX", "Source": "AWS - IAM", "Brand": "AWS - IAM", "Username": "aws_user", "Instance": None}
        ]

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="AWS.IAM.Users")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = aws_iam_get_user(command, additional_fields=True)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
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
        command = Command("Microsoft Graph User", "msgraph-user-get", {"user": "graph_user"})
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
        expected_account = [
            {
                "AdditionalFields": {
                    "DisplayName": "Graph User",
                    "JobTitle": "Developer",
                    "Office": "HQ",
                    "TelephoneNumber": "123-456-7890",
                    "Type": "Member",
                },
                "Email": "graph@example.com",
                "ID": "131415",
                "Source": "Microsoft Graph User",
                "Brand": "Microsoft Graph User",
                "Username": "graph_user",
                "Instance": None,
            }
        ]

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="Account")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = msgraph_user_get(command, additional_fields=True)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
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
        command = Command("Microsoft Graph User", "msgraph-user-get-manager", {"user": "graph_user"})
        mock_outputs = {"Manager": {"DisplayName": "Graph Manager", "Mail": "manager@example.com"}}
        expected_account = {"ManagerDisplayName": "Graph Manager", "ManagerEmail": "manager@example.com"}

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="MSGraphUserManager")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = msgraph_user_get_manager(command)

        assert isinstance(result, dict)
        assert result == expected_account

    def test_azure_list_risky_users(self, mocker: MockerFixture):
        """
        Given:
            A Command object for azure_list_risky_users.
        When:
            The function is called with the Command object.
        Then:
            It returns the expected tuple of readable outputs and account output.
        """
        user_name = "azure_user"
        command = Command("Azure Risky Users", "azure-risky-user-get", {"user_id": user_name})
        mock_outputs = {"id": "azure_user", "riskLevel": "HIGH"}
        expected_account = [
            {
                "ID": "azure_user",
                "RiskLevel": "HIGH",
                "Source": "Azure Risky Users",
                "Brand": "Azure Risky Users",
                "Username": "azure_user",
                "Instance": None,
            }
        ]

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="AzureRiskyUsers.RiskyUser")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = azure_get_risky_user(command, additional_fields=True)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert result[1] == expected_account

    def test_prisma_cloud_get_user(self, mocker: MockerFixture):
        """
        Given:
            A Command object for prisma_cloud_get_user.
        When:
            The function is called with the Command object.
        Then:
            It returns the expected tuple of readable outputs and account output.
        """
        command = Command("PrismaCloud v2", "prisma-cloud-users-list", {"usernames": "prisma_user"})
        mock_outputs = {"email": "user_email.com", "username": "prisma_user"}
        expected_account = [
            {
                "Email": "user_email.com",
                "Source": "PrismaCloud v2",
                "Brand": "PrismaCloud v2",
                "Username": "prisma_user",
                "Instance": None,
            }
        ]

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="PrismaCloud.Users")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = prisma_cloud_get_user(command, additional_fields=True)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert result[1] == expected_account

    def test_iam_get_user(self, mocker: MockerFixture):
        """
        Given:
            A Command object for iam_cloud_get_user.
        When:
            The function is called with the Command object.
        Then:
            It returns the expected tuple of readable outputs and user output.
        """
        command = Command("Okta IAM", "iam-get-user", {"user-profile": "user"})
        mock_outputs = {"email": "user_email.com", "username": "name_user", "id": "user_id", "success": True}
        expected_account = [
            {
                "Email": "user_email.com",
                "Source": "Okta IAM",
                "Brand": "Okta IAM",
                "Username": "name_user",
                "ID": "user_id",
                "Instance": None,
                "AdditionalFields": {"success": True},
            }
        ]

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="IAM.Vendor")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = iam_get_user(command, additional_fields=True)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert result[1] == expected_account

    def test_gsuite_get_user(self, mocker: MockerFixture):
        """
        Given:
            A Command object for iam_cloud_get_user.
        When:
            The function is called with the Command object.
        Then:
            It returns the expected tuple of readable outputs and user output.
        """
        command = Command("GSuiteAdmin", "gsuite-user-get", {"user": "user"})
        mock_outputs = {"primaryEmail": "user_email.com", "fullName": "name_user", "id": "user_id"}
        expected_account = [
            {
                "Email": "user_email.com",
                "Source": "GSuiteAdmin",
                "Brand": "GSuiteAdmin",
                "Username": "name_user",
                "ID": "user_id",
                "Instance": None,
            }
        ]

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="GSuite.User")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = gsuite_get_user(command, additional_fields=True)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert result[1] == expected_account


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
            "user_id": ["123", "456"],
            "user_name": ["johndoe", "usertwo"],
            "user_email": ["john@example.com"],
        },
    )

    # Mock demisto.getModules()
    mocker.patch.object(demisto, "getModules", return_value={})

    mocker.patch.object(Modules, "is_brand_in_brands_to_run", return_value=True)
    mocker.patch.object(Modules, "is_brand_available", return_value=True)

    # Mock other necessary functions
    mocker.patch("GetUserData.ad_get_user", return_value=(["test"], [{"Source": "test", "Brand": "test", "Instance": None}]))
    mocker.patch("GetUserData.okta_get_user", return_value=([], []))
    mocker.patch("GetUserData.aws_iam_get_user", return_value=([], []))
    mocker.patch("GetUserData.msgraph_user_get", return_value=([], []))
    mocker.patch("GetUserData.get_core_and_xdr_data", return_value=([], []))
    mocker.patch("GetUserData.azure_get_risky_user", return_value=([], []))
    mocker.patch("GetUserData.prisma_cloud_get_user", return_value=([], []))
    mocker.patch("GetUserData.iam_get_user", return_value=([], []))
    mocker.patch("GetUserData.gsuite_get_user", return_value=([], []))
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
        "Failed to execute get-user-data. Error: At least one of the following arguments must"
        " be specified: user_id, user_name, user_email or users_sid."
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


def test_get_data_with_found_user(mocker: MockerFixture):
    modules = Modules({}, ["Brand1"])

    mocker.patch.object(Modules, "is_brand_in_brands_to_run", return_value=True)
    mocker.patch.object(Modules, "is_brand_available", return_value=True)

    # Mock other necessary functions
    mock_get_user = mocker.patch(
        "GetUserData.ad_get_user",
        return_value=(["test"], [{"Source": "test", "Brand": "test", "Username": "test user", "Instance": None}]),
    )

    result = get_data(
        modules=modules,
        brand_name="Brand1",
        command_name="test_command",
        arg_name="test_arg",
        arg_value="test_value",
        cmd=mock_get_user,
        additional_fields=True,
    )

    assert result[1]
    assert result[1][0].get("Status") == "found"


def test_get_data_without_found_user(mocker: MockerFixture):
    modules = Modules({}, ["Brand1"])

    mocker.patch.object(Modules, "is_brand_in_brands_to_run", return_value=True)
    mocker.patch.object(Modules, "is_brand_available", return_value=True)

    # Mock other necessary functions
    mock_get_user = mocker.patch(
        "GetUserData.ad_get_user", return_value=([], [{"Source": "test", "Brand": "test", "Instance": "inst"}])
    )

    result = get_data(
        modules=modules,
        brand_name="Brand1",
        command_name="test_command",
        arg_name="test_arg",
        arg_value="test_value",
        cmd=mock_get_user,
        additional_fields=True,
    )

    assert result[1][0].get("Status") == "User not found - userId: test_value."


def test_xdr_and_core_list_all_users_with_list_non_risky_users_true_and_additional_fields_true(mocker: MockerFixture):
    """
    Given:
        list_non_risky_users is set to True and additional_fields=True.
        A user with an email that did not appear in the email_list was found.
    When:
        xdr_and_core_list_all_users is called.
    Then:
        It should process both risky and non-risky users with additional fields.
    """
    # Arrange
    risky_commands = [Command("Cortex XDR - IR", "xdr-list-risky-users", {"user_id": "risky1"})]
    list_users_command = Command("Cortex XDR - IR", "xdr-list-users", {})
    outputs_key_field = "PaloAltoNetworksXDR"
    additional_fields = True
    list_non_risky_users = True
    email_list = ["user1@example.com", "user2@example.com"]

    # Mock risky users results
    risky_readable_outputs = [mocker.Mock(spec=CommandResults)]
    risky_users = [{"ID": "risky1", "Email": "risky@example.com", "Status": "found", "additional_field": "risky_value"}]

    # Mock final results after processing non-risky users
    # Include a user found that wasn't in the email_list
    final_readable_outputs = [mocker.Mock(spec=CommandResults), mocker.Mock(spec=CommandResults)]
    final_users = [
        {"ID": "risky1", "Email": "risky@example.com", "Status": "found", "additional_field": "risky_value"},
        {"ID": "user1", "Email": "user1@example.com", "Status": "found", "additional_field": "user1_value"},
        {"ID": "user2", "Email": "user2@example.com", "Status": "found", "additional_field": "user2_value"},
        {
            "ID": "unexpected",
            "Email": "unexpected@example.com",
            "Status": "found",
            "additional_field": "unexpected_value",
        },  # Not in email_list
    ]

    mock_run_list_risky_users = mocker.patch(
        "GetUserData.run_list_risky_users_command", return_value=(risky_readable_outputs, risky_users)
    )
    mock_run_list_users = mocker.patch("GetUserData.run_list_users_command", return_value=(final_readable_outputs, final_users))

    # Act
    readable_outputs, users = xdr_and_core_list_all_users(
        risky_commands, list_users_command, outputs_key_field, additional_fields, list_non_risky_users, email_list
    )

    # Assert
    assert readable_outputs == final_readable_outputs
    assert users == final_users
    assert len(users) == 4  # 1 risky + 3 non-risky users

    # Verify that a user not in email_list was found
    unexpected_users = [user for user in users if user["Email"] == "unexpected@example.com"]
    assert len(unexpected_users) == 1
    assert unexpected_users[0]["additional_field"] == "unexpected_value"

    mock_run_list_risky_users.assert_called_once_with(risky_commands, True, outputs_key_field)
    mock_run_list_users.assert_called_once_with(
        list_users_command, True, outputs_key_field, email_list, risky_users, risky_readable_outputs
    )


def test_xdr_and_core_list_all_users_with_list_non_risky_users_false(mocker: MockerFixture):
    """
    Given:
        list_non_risky_users is set to False.
    When:
        xdr_and_core_list_all_users is called.
    Then:
        It should only process risky users and not call run_list_users_command.
    """
    # Arrange
    risky_commands = [
        Command("Cortex XDR - IR", "xdr-list-risky-users", {"user_id": "risky1"}),
        Command("Cortex Core - IR", "core-list-risky-users", {"user_id": "risky2"}),
    ]
    list_users_command = Command("Cortex XDR - IR", "xdr-list-users", {})
    outputs_key_field = "PaloAltoNetworksXDR"
    additional_fields = True
    list_non_risky_users = False
    email_list = ["user1@example.com", "user2@example.com"]

    # Mock risky users results
    risky_readable_outputs = [mocker.Mock(spec=CommandResults), mocker.Mock(spec=CommandResults)]
    risky_users = [
        {"ID": "risky1", "Email": "risky1@example.com", "Status": "found", "risk_level": "HIGH"},
        {"ID": "risky2", "Email": "risky2@example.com", "Status": "found", "risk_level": "MEDIUM"},
    ]

    mock_run_list_risky_users = mocker.patch(
        "GetUserData.run_list_risky_users_command", return_value=(risky_readable_outputs, risky_users)
    )
    mock_run_list_users = mocker.patch("GetUserData.run_list_users_command")

    # Act
    readable_outputs, users = xdr_and_core_list_all_users(
        risky_commands, list_users_command, outputs_key_field, additional_fields, list_non_risky_users, email_list
    )

    # Assert
    assert readable_outputs == risky_readable_outputs
    assert users == risky_users
    assert len(users) == 2  # Only risky users

    mock_run_list_risky_users.assert_called_once_with(risky_commands, additional_fields, outputs_key_field)
    mock_run_list_users.assert_not_called()  # Should not be called when list_non_risky_users=False


def test_run_list_risky_users_command_single_command_success(mocker: MockerFixture):
    """
    Given:
        A single Command object for listing risky users with valid response.
    When:
        run_list_risky_users_command is called with the command.
    Then:
        It should return readable outputs and user data with 'found' status.
    """
    # Arrange
    command = Command("Cortex XDR - IR", "xdr-list-risky-users", {"user_id": "test_user"})
    commands = [command]
    additional_fields = True
    outputs_key_field = "PaloAltoNetworksXDR"

    mock_entry_context = [
        {
            "PaloAltoNetworksXDR.RiskyUser": {
                "id": "test_user",
                "risk_level": "HIGH",
                "email": "test@example.com",
                "department": "IT",
            },
            "instance": "xdr_instance",
        }
    ]

    mock_run_execute_command = mocker.patch(
        "GetUserData.run_execute_command", return_value=(mock_entry_context, "Human readable output", [])
    )
    mock_prepare_human_readable = mocker.patch(
        "GetUserData.prepare_human_readable", return_value=[mocker.Mock(spec=CommandResults)]
    )

    # Act
    readable_outputs, users = run_list_risky_users_command(commands, additional_fields, outputs_key_field)

    # Assert
    assert len(readable_outputs) == 1
    assert len(users) == 1

    user = users[0]
    assert user["ID"] == "test_user"
    assert user["Username"] == "test_user"
    assert user["RiskLevel"] == "HIGH"
    assert user["Email"] == "test@example.com"
    assert user["Source"] == "Cortex XDR - IR"
    assert user["Brand"] == "Cortex XDR - IR"
    assert user["Instance"] == "xdr_instance"
    assert user["Status"] == "found"
    assert "AdditionalFields" in user
    assert user["AdditionalFields"]["department"] == "IT"

    mock_run_execute_command.assert_called_once_with("xdr-list-risky-users", {"user_id": "test_user"})
    mock_prepare_human_readable.assert_called_once()


def test_run_list_risky_users_command_multiple_commands_success(mocker: MockerFixture):
    """
    Given:
        Multiple Command objects for listing risky users.
    When:
        run_list_risky_users_command is called with the commands.
    Then:
        It should return readable outputs and user data for all commands.
    """
    # Arrange
    command1 = Command("Cortex Core - IR", "xdr-list-risky-users", {"user_id": "user1"})
    command2 = Command("Cortex Core - IR", "core-list-risky-users", {"user_id": "user2"})
    commands = [command1, command2]
    additional_fields = False
    outputs_key_field = "Core"

    mock_entry_contexts = [
        [{"Core.RiskyUser": {"id": "user1", "risk_level": "HIGH", "email": "user1@example.com"}, "instance": "xdr_instance"}],
        [{"Core.RiskyUser": {"id": "user2", "risk_level": "MEDIUM", "email": "user2@example.com"}, "instance": "core_instance"}],
    ]

    mock_run_execute_command = mocker.patch(
        "GetUserData.run_execute_command",
        side_effect=[(mock_entry_contexts[0], "Output 1", []), (mock_entry_contexts[1], "Output 2", [])],
    )

    # Act
    readable_outputs, users = run_list_risky_users_command(commands, additional_fields, outputs_key_field)

    # Assert
    assert len(readable_outputs) == 2
    assert len(users) == 2

    # Check first user
    user1 = users[0]
    assert user1["ID"] == "user1"
    assert user1["Username"] == "user1"
    assert user1["RiskLevel"] == "HIGH"
    assert user1["Email"] == "user1@example.com"
    assert user1["Source"] == "Cortex Core - IR"
    assert user1["Instance"] == "xdr_instance"
    assert user1["Status"] == "found"
    assert "AdditionalFields" not in user1  # additional_fields=False

    # Check second user
    user2 = users[1]
    assert user2["ID"] == "user2"
    assert user2["Username"] == "user2"
    assert user2["RiskLevel"] == "MEDIUM"
    assert user2["Email"] == "user2@example.com"
    assert user2["Source"] == "Cortex Core - IR"
    assert user2["Instance"] == "core_instance"
    assert user2["Status"] == "found"

    assert mock_run_execute_command.call_count == 2


def test_run_list_risky_users_command_user_not_found(mocker: MockerFixture):
    """
    Given:
        A Command object that returns empty user data (user not found).
    When:
        run_list_risky_users_command is called with the command.
    Then:
        It should return user data with 'User not found' status.
    """
    # Arrange
    command = Command("Cortex XDR - IR", "xdr-list-risky-users", {"user_id": "nonexistent_user"})
    commands = [command]
    additional_fields = True
    outputs_key_field = "PaloAltoNetworksXDR"

    mock_entry_context = [{"PaloAltoNetworksXDR.RiskyUser": {}, "instance": "xdr_instance"}]

    mocker.patch("GetUserData.run_execute_command", return_value=(mock_entry_context, "No user found", []))

    # Act
    _, users = run_list_risky_users_command(commands, additional_fields, outputs_key_field)

    # Assert
    assert len(users) == 1
    user = users[0]

    # User should only have Source, Brand, and Instance keys when not found
    expected_keys = {"Source", "Brand", "Instance"}
    actual_keys = set(user.keys()) - {"Status"}  # Exclude Status key for comparison
    assert actual_keys == expected_keys

    assert user["Source"] == "Cortex XDR - IR"
    assert user["Brand"] == "Cortex XDR - IR"
    assert user["Instance"] == "xdr_instance"
    assert user["Status"] == "User not found - userId: nonexistent_user."


def test_run_list_risky_users_command_with_errors(mocker: MockerFixture):
    """
    Given:
        A Command object that returns errors during execution.
    When:
        run_list_risky_users_command is called with the command.
    Then:
        It should return readable outputs including error messages.
    """
    # Arrange
    command = Command("Cortex XDR - IR", "xdr-list-risky-users", {"user_id": "test_user"})
    commands = [command]
    additional_fields = True
    outputs_key_field = "PaloAltoNetworksXDR"

    mock_entry_context = [{"PaloAltoNetworksXDR.RiskyUser": {"id": "test_user", "risk_level": "LOW"}, "instance": "xdr_instance"}]

    error_result = mocker.Mock(spec=CommandResults)

    mocker.patch("GetUserData.run_execute_command", return_value=(mock_entry_context, "Human readable output", [error_result]))

    # Act
    readable_outputs, users = run_list_risky_users_command(commands, additional_fields, outputs_key_field)

    # Assert
    assert len(readable_outputs) == 2  # 1 error + 1 human readable
    assert error_result in readable_outputs

    assert len(users) == 1
    user = users[0]
    assert user["Status"] == "found"
    assert user["RiskLevel"] == "LOW"


def test_run_list_risky_users_command_empty_commands_list():
    """
    Given:
        An empty list of commands.
    When:
        run_list_risky_users_command is called with the empty list.
    Then:
        It should return empty readable outputs and users lists.
    """
    # Arrange
    commands = []
    additional_fields = True
    outputs_key_field = "PaloAltoNetworksXDR"

    # Act
    readable_outputs, users = run_list_risky_users_command(commands, additional_fields, outputs_key_field)

    # Assert
    assert readable_outputs == []
    assert users == []


def test_run_list_risky_users_command_additional_fields_true(mocker: MockerFixture):
    """
    Given:
        A Command object with additional_fields set to True.
    When:
        run_list_risky_users_command is called.
    Then:
        It should include AdditionalFields in the user data.
    """
    # Arrange
    command = Command("Cortex XDR - IR", "xdr-list-risky-users", {"user_id": "test_user"})
    commands = [command]
    additional_fields = True
    outputs_key_field = "PaloAltoNetworksXDR"

    mock_entry_context = [
        {
            "PaloAltoNetworksXDR.RiskyUser": {
                "id": "test_user",
                "risk_level": "HIGH",
                "email": "test@example.com",
                "department": "IT",
                "extra_field": "extra_value",
            },
            "instance": "xdr_instance",
        }
    ]

    mocker.patch("GetUserData.run_execute_command", return_value=(mock_entry_context, "Human readable output", []))

    # Act
    _, users = run_list_risky_users_command(commands, additional_fields, outputs_key_field)

    # Assert
    assert len(users) == 1
    user = users[0]

    # Should have AdditionalFields when additional_fields=True
    assert "AdditionalFields" in user
    assert user["AdditionalFields"]["department"] == "IT"
    assert user["AdditionalFields"]["extra_field"] == "extra_value"
    assert user["ID"] == "test_user"
    assert user["Username"] == "test_user"
    assert user["RiskLevel"] == "HIGH"
    assert user["Email"] == "test@example.com"
    assert user["Status"] == "found"


def test_run_list_users_command_no_email_one_user_additional_fields_false(mocker: MockerFixture):
    """
    Given:
        No email given, one user appears under users but additional_fields = False
    When:
        run_list_users_command is called.
    Then:
        It should return the existing users without modification and not call the command.
    """
    # Arrange
    command = Command("Cortex XDR - IR", "xdr-list-users", {})
    additional_fields = False
    outputs_key_field = "PaloAltoNetworksXDR"
    email_list = []
    existing_users = [{"Email": "existing@example.com", "ID": "existing_id", "Status": "found", "AdditionalFields": {}}]
    readable_outputs_list = []

    # Mock the command execution and debug logging
    mock_run_execute_command = mocker.patch("GetUserData.run_execute_command")
    mock_debug = mocker.patch("GetUserData.demisto.debug")

    # Act
    readable_outputs, users = run_list_users_command(
        command, additional_fields, outputs_key_field, email_list, existing_users, readable_outputs_list
    )

    # Assert
    # Command should not be called since email_list is empty
    mock_run_execute_command.assert_not_called()

    # Debug message should be logged about no emails to search for
    mock_debug.assert_called_with("Did not recieve any email to search for, skipping list users command.")

    # Users should remain unchanged
    assert readable_outputs == []
    assert users == existing_users  # Should remain unchanged since email_list is empty
    assert len(users) == 1
    assert users[0]["Email"] == "existing@example.com"


def test_run_list_users_command_no_email_one_user_additional_fields_true(mocker: MockerFixture):
    """
    Given:
        No email given, one user appears under users but additional_fields = True
    When:
        run_list_users_command is called.
    Then:
        It should update the existing user with additional fields from the command output.
    """
    # Arrange
    command = Command("Cortex XDR - IR", "xdr-list-users", {})
    additional_fields = True
    outputs_key_field = "PaloAltoNetworksXDR"
    email_list = []
    existing_users = [
        {"Email": "existing@example.com", "ID": "existing_id", "Status": "found", "AdditionalFields": {"original": "value"}}
    ]
    readable_outputs_list = []

    mock_entry_context = [
        {
            "PaloAltoNetworksXDR.User": [
                {"id": "existing_id", "user_email": "existing@example.com", "department": "Engineering", "location": "NY"}
            ],
            "instance": "xdr_instance",
        }
    ]

    mocker.patch("GetUserData.run_execute_command", return_value=(mock_entry_context, "Human readable output", []))

    # Act
    readable_outputs, users = run_list_users_command(
        command, additional_fields, outputs_key_field, email_list, existing_users, readable_outputs_list
    )

    # Assert
    assert readable_outputs == []
    assert len(users) == 1
    user = users[0]
    assert user["Email"] == "existing@example.com"
    assert user["AdditionalFields"]["original"] == "value"
    assert user["AdditionalFields"]["department"] == "Engineering"
    assert user["AdditionalFields"]["location"] == "NY"


def test_run_list_users_command_one_email_no_user_found_additional_fields_false(mocker: MockerFixture):
    """
    Given:
        One email given, no user appears under users but the mail was not found after listing the users.
    When:
        run_list_users_command is called with additional_fields=False.
    Then:
        It should add the user with 'not found' status.
    """
    # Arrange
    command = Command("Cortex XDR - IR", "xdr-list-users", {})
    additional_fields = False
    outputs_key_field = "PaloAltoNetworksXDR"
    email_list = ["notfound@example.com"]
    existing_users = []
    readable_outputs_list = []

    mock_entry_context = [{"PaloAltoNetworksXDR.User": [], "instance": "xdr_instance"}]

    mocker.patch("GetUserData.run_execute_command", return_value=(mock_entry_context, "Human readable output", []))

    # Act
    _, users = run_list_users_command(
        command, additional_fields, outputs_key_field, email_list, existing_users, readable_outputs_list
    )

    # Assert
    assert len(users) == 1
    user = users[0]
    assert user["Email"] == "notfound@example.com"
    assert user["Source"] == "Cortex XDR - IR"
    assert user["Status"] == "not found"


def test_run_list_users_command_email_in_both_lists_additional_fields_false(mocker: MockerFixture):
    """
    Given:
        The email_list contains an email which is also related to a user that appears under users and additional_fields=false
    When:
        run_list_users_command is called.
    Then:
        It should find the user and not update additional fields since additional_fields=False.
    """
    # Arrange
    command = Command("Cortex XDR - IR", "xdr-list-users", {})
    additional_fields = False
    outputs_key_field = "PaloAltoNetworksXDR"
    email_list = ["shared@example.com"]
    existing_users = [
        {
            "Email": "shared@example.com",
            "ID": "existing_id",
            "Source": "Previous Source",
            "Status": "found",
        }
    ]
    readable_outputs_list = []

    mock_entry_context = [
        {
            "PaloAltoNetworksXDR.User": [
                {"id": "existing_id", "user_email": "shared@example.com", "department": "Engineering", "location": "SF"}
            ],
            "instance": "xdr_instance",
        }
    ]

    mocker.patch("GetUserData.run_execute_command", return_value=(mock_entry_context, "Human readable output", []))

    # Act
    _, users = run_list_users_command(
        command, additional_fields, outputs_key_field, email_list, existing_users, readable_outputs_list
    )

    # Assert
    assert len(users) == 1
    user = users[0]
    assert user["Email"] == "shared@example.com"
    assert user["ID"] == "existing_id"
    assert "AdditionalFields" not in user


def test_run_list_users_command_multiple_emails_mixed_results(mocker: MockerFixture):
    """
    Given:
        Multiple emails with mixed results - some found, some not found, with additional_fields=True
    When:
        run_list_users_command is called.
    Then:
        It should process found users and add not found users with appropriate status.
    """
    # Arrange
    command = Command("Cortex XDR - IR", "xdr-list-users", {})
    additional_fields = True
    outputs_key_field = "PaloAltoNetworksXDR"
    email_list = ["found1@example.com", "notfound@example.com", "found2@example.com"]
    existing_users = []
    readable_outputs_list = []

    mock_entry_context = [
        {
            "PaloAltoNetworksXDR.User": [
                {"id": "user1_id", "user_email": "found1@example.com", "department": "IT", "risk_level": "LOW"},
                {"id": "user2_id", "user_email": "found2@example.com", "department": "HR", "risk_level": "MEDIUM"},
            ],
            "instance": "xdr_instance",
        }
    ]

    mocker.patch("GetUserData.run_execute_command", return_value=(mock_entry_context, "Human readable output", []))

    # Act
    _, users = run_list_users_command(
        command, additional_fields, outputs_key_field, email_list, existing_users, readable_outputs_list
    )

    # Assert
    assert len(users) == 3  # 2 found + 1 not found

    found_users = [user for user in users if user["Status"] == "found"]
    not_found_users = [user for user in users if user["Status"] == "not found"]

    assert len(found_users) == 2
    assert len(not_found_users) == 1

    # Check found users have additional fields
    found1 = next(user for user in found_users if user["Email"] == "found1@example.com")
    assert found1["AdditionalFields"]["department"] == "IT"
    assert found1["RiskLevel"] == "LOW"

    found2 = next(user for user in found_users if user["Email"] == "found2@example.com")
    assert found2["AdditionalFields"]["department"] == "HR"
    assert found2["RiskLevel"] == "MEDIUM"

    # Check not found user
    not_found = not_found_users[0]
    assert not_found["Email"] == "notfound@example.com"
    assert not_found["Status"] == "not found"


def test_run_list_users_command_empty_user_email_field(mocker: MockerFixture):
    """
    Given:
        API returns users without user_email field
    When:
        run_list_users_command is called.
    Then:
        It should skip users without email and mark searched emails as not found.
    """
    # Arrange
    command = Command("Cortex XDR - IR", "xdr-list-users", {})
    additional_fields = False
    outputs_key_field = "PaloAltoNetworksXDR"
    email_list = ["search@example.com"]
    existing_users = []
    readable_outputs_list = []

    mock_entry_context = [
        {
            "PaloAltoNetworksXDR.User": [
                {"id": "user_without_email", "department": "IT"},  # No user_email field
                {"id": "user_with_empty_email", "user_email": "", "department": "HR"},  # Empty user_email
            ],
            "instance": "xdr_instance",
        }
    ]

    mocker.patch("GetUserData.run_execute_command", return_value=(mock_entry_context, "Human readable output", []))

    # Act
    _, users = run_list_users_command(
        command, additional_fields, outputs_key_field, email_list, existing_users, readable_outputs_list
    )

    # Assert
    assert len(users) == 1  # Only the not found user
    user = users[0]
    assert user["Email"] == "search@example.com"
    assert user["Status"] == "not found"


def test_run_list_users_command_api_command_failure(mocker: MockerFixture):
    """
    Given:
        run_execute_command returns an error entry and no users
    When:
        run_list_users_command is called.
    Then:
        It should receive the error entry and mark searched emails as not found.
    """
    # Arrange
    command = Command("Cortex XDR - IR", "xdr-list-users", {})
    additional_fields = False
    outputs_key_field = "PaloAltoNetworksXDR"
    email_list = ["test@example.com"]
    existing_users = []
    readable_outputs_list = []

    # Mock run_execute_command to return error entry and empty user list
    error_result = mocker.Mock(spec=CommandResults)
    mock_entry_context = [{"PaloAltoNetworksXDR.User": [], "instance": "xdr_instance"}]

    mocker.patch("GetUserData.run_execute_command", return_value=(mock_entry_context, "Human readable output", [error_result]))

    # Act
    readable_outputs, users = run_list_users_command(
        command, additional_fields, outputs_key_field, email_list, existing_users, readable_outputs_list
    )

    # Assert
    assert error_result in readable_outputs
    assert len(users) == 1  # User not found should be added
    assert users[0]["Email"] == "test@example.com"
    assert users[0]["Status"] == "not found"


def test_run_list_users_command_risky_user_not_in_email_list_additional_fields_false(mocker: MockerFixture):
    """
    Given:
        Email in risky_users but not in email_list with additional_fields=False
    When:
        run_list_users_command is called.
    Then:
        It should not process the risky user since additional_fields=False.
    """
    # Arrange
    command = Command("Cortex XDR - IR", "xdr-list-users", {})
    additional_fields = False
    outputs_key_field = "PaloAltoNetworksXDR"
    email_list = ["search@example.com"]
    existing_users = [
        {
            "Email": "risky@example.com",
            "ID": "risky_id",
            "Source": "Risky Source",
        }
    ]
    readable_outputs_list = []

    mock_entry_context = [
        {
            "PaloAltoNetworksXDR.User": [
                {"id": "risky_id", "user_email": "risky@example.com", "department": "Security"},
            ],
            "instance": "xdr_instance",
        }
    ]

    mocker.patch("GetUserData.run_execute_command", return_value=(mock_entry_context, "Human readable output", []))

    # Act
    _, users = run_list_users_command(
        command, additional_fields, outputs_key_field, email_list, existing_users, readable_outputs_list
    )

    # Assert
    assert len(users) == 2  # Original risky user + not found search user

    risky_user = next(user for user in users if user["Email"] == "risky@example.com")
    assert "AdditionalFields" not in risky_user

    not_found_user = next(user for user in users if user["Email"] == "search@example.com")
    assert not_found_user["Status"] == "not found"


def test_run_list_users_command_empty_outputs_from_api(mocker: MockerFixture):
    """
    Given:
        API returns valid structure but empty user list
    When:
        run_list_users_command is called.
    Then:
        It should mark all searched emails as not found.
    """
    # Arrange
    command = Command("Cortex XDR - IR", "xdr-list-users", {})
    additional_fields = True
    outputs_key_field = "PaloAltoNetworksXDR"
    email_list = ["test1@example.com", "test2@example.com"]
    existing_users = []
    readable_outputs_list = []

    mock_entry_context = [
        {
            "PaloAltoNetworksXDR.User": [],  # Empty user list
            "instance": "xdr_instance",
        }
    ]

    mocker.patch("GetUserData.run_execute_command", return_value=(mock_entry_context, "Human readable output", []))

    # Act
    _, users = run_list_users_command(
        command, additional_fields, outputs_key_field, email_list, existing_users, readable_outputs_list
    )

    # Assert
    assert len(users) == 2  # Both emails marked as not found
    assert all(user["Status"] == "not found" for user in users)
    assert {user["Email"] for user in users} == set(email_list)


# --- helpers to mute all other adapters so main can run quietly ---
def _mute_all_other_adapters(mocker: MockerFixture, except_fn: str | None = None):
    fns = {
        "ad_get_user",
        "okta_get_user",
        "aws_iam_get_user",
        "msgraph_user_get",
        "prisma_cloud_get_user",
        "iam_get_user",  # <- shared by Okta IAM and AWS-ILM
        "gsuite_get_user",
        "azure_get_risky_user",
    }
    for fn in fns:
        if fn == except_fn:
            continue
        mocker.patch(f"GetUserData.{fn}", return_value=([], []))


# -------------- Testing Calling the right argument per command --------------
# ---------- Username flows (no domain) ----------
@pytest.mark.parametrize(
    "brand_name,command_name,adapter_fn,expected_key,expected_value",
    [
        ("Active Directory Query v2", "ad-get-user", "ad_get_user", "username", "alice"),
        ("Okta v2", "okta-get-user", "okta_get_user", "username", "alice"),
        ("AWS - IAM", "aws-iam-get-user", "aws_iam_get_user", "userName", "alice"),
        ("Microsoft Graph User", "msgraph-user-get", "msgraph_user_get", "user", "alice"),
        ("PrismaCloud v2", "prisma-cloud-users-list", "prisma_cloud_get_user", "usernames", "alice"),
        ("Okta IAM", "iam-get-user", "iam_get_user", "user-profile", '{"login":"alice"}'),
        ("AWS-ILM", "iam-get-user", "iam_get_user", "user-profile", '{"login":"alice"}'),
    ],
)
def test_username_arg_mapping_to_adapter(
    mocker: MockerFixture, brand_name, command_name, adapter_fn, expected_key, expected_value
):
    """
    Given:
        - calling get-user-data with username = alice.
        - brand_name = brand_name.
    When:
        - main() executes by username flows.
    Then:
        - The right command is being called with the right argument name.
    """
    mocker.patch.object(demisto, "args", return_value={"user_name": ["alice"]})
    mocker.patch.object(demisto, "getModules", return_value={})
    mocker.patch.object(Modules, "is_brand_in_brands_to_run", return_value=True)
    mocker.patch.object(Modules, "is_brand_available", return_value=True)
    mocker.patch("GetUserData.get_core_and_xdr_data", return_value=([], []))
    mocker.patch("GetUserData.return_results")

    _mute_all_other_adapters(mocker, except_fn=adapter_fn)
    seen = {"ok": False}

    def _assert_adapter(command: Command, additional_fields: bool):
        # Only assert for the exact brand+command under test; ignore other calls to the same adapter.
        if command.brand != brand_name or command.name != command_name:
            return ([], [])
        assert command.args.get(expected_key) == expected_value
        assert command.args.get("using-brand") == brand_name
        if expected_key == "username":
            assert "name" not in command.args  # regression guard
        seen["ok"] = True
        return ([], [])

    mocker.patch(f"GetUserData.{adapter_fn}", side_effect=_assert_adapter)
    main()
    assert seen["ok"] is True


# ---------- Username flow with domain prefix (DOMAIN\\username) ----------
def test_domain_username_branch_uses_username_key_for_ad(mocker: MockerFixture):
    """
    Given:
        - calling get-user-data with username = ACME\\alice.
        - brand_name = brand_name.
    When:
        - main() executes by username flows.
    Then:
        - The right command is being called with the right argument name.
    """
    mocker.patch.object(demisto, "args", return_value={"user_name": ["ACME\\alice"]})
    mocker.patch.object(demisto, "getModules", return_value={})
    mocker.patch.object(Modules, "is_brand_in_brands_to_run", return_value=True)
    mocker.patch.object(Modules, "is_brand_available", return_value=True)
    mocker.patch("GetUserData.get_core_and_xdr_data", return_value=([], []))
    mocker.patch("GetUserData.return_results")

    _mute_all_other_adapters(mocker, except_fn="ad_get_user")
    hit = {"seen": False}

    def _assert_ad(command: Command, additional_fields: bool):
        if command.brand != "Active Directory Query v2" or command.name != "ad-get-user":
            return ([], [])
        assert command.args.get("username") == "alice"
        assert "name" not in command.args
        assert command.args.get("using-brand") == "Active Directory Query v2"
        hit["seen"] = True
        return ([], [])

    mocker.patch("GetUserData.ad_get_user", side_effect=_assert_ad)
    main()
    assert hit["seen"] is True


# ---------- User ID flows ----------
@pytest.mark.parametrize(
    "brand_name,command_name,adapter_fn,expected_key,expected_value",
    [
        ("Okta v2", "okta-get-user", "okta_get_user", "userId", "u123"),
        ("Microsoft Graph User", "msgraph-user-get", "msgraph_user_get", "user", "u123"),
        ("AzureRiskyUsers", "azure-risky-user-get", "azure_get_risky_user", "id", "u123"),
        ("Okta IAM", "iam-get-user", "iam_get_user", "user-profile", '{"id":"u123"}'),
        ("AWS-ILM", "iam-get-user", "iam_get_user", "user-profile", '{"id":"u123"}'),
        ("GSuiteAdmin", "gsuite-user-get", "gsuite_get_user", "user", "u123"),
    ],
)
def test_userid_arg_mapping_to_adapter(mocker: MockerFixture, brand_name, command_name, adapter_fn, expected_key, expected_value):
    """
    Given:
        - calling get-user-data with user_id = u123.
        - brand_name = brand_name.
    When:
        -main() executes by user ID flows.
    Then:
        - The right command is being called with the right argument name.
    """
    mocker.patch.object(demisto, "args", return_value={"user_id": ["u123"]})
    mocker.patch.object(demisto, "getModules", return_value={})
    mocker.patch.object(Modules, "is_brand_in_brands_to_run", return_value=True)
    mocker.patch.object(Modules, "is_brand_available", return_value=True)
    mocker.patch("GetUserData.get_core_and_xdr_data", return_value=([], []))
    mocker.patch("GetUserData.return_results")

    _mute_all_other_adapters(mocker, except_fn=adapter_fn)
    seen = {"ok": False}

    def _assert_adapter(command: Command, additional_fields: bool):
        if command.brand != brand_name or command.name != command_name:
            return ([], [])
        assert command.args.get(expected_key) == expected_value
        assert command.args.get("using-brand") == brand_name
        seen["ok"] = True
        return ([], [])

    mocker.patch(f"GetUserData.{adapter_fn}", side_effect=_assert_adapter)
    main()
    assert seen["ok"] is True


# ---------- Email flows ----------
@pytest.mark.parametrize(
    "brand_name,command_name,adapter_fn,expected_key,expected_value",
    [
        ("Active Directory Query v2", "ad-get-user", "ad_get_user", "email", "john@example.com"),
        ("Okta IAM", "iam-get-user", "iam_get_user", "user-profile", '{"email":"john@example.com"}'),
        ("AWS-ILM", "iam-get-user", "iam_get_user", "user-profile", '{"email":"john@example.com"}'),
        ("GSuiteAdmin", "gsuite-user-get", "gsuite_get_user", "user", "john@example.com"),
    ],
)
def test_email_arg_mapping_to_adapter(mocker: MockerFixture, brand_name, command_name, adapter_fn, expected_key, expected_value):
    """
    Given:
        - calling get-user-data with user_email = john@example.com.
        - brand_name = brand_name.
    When:
        - main() executes by email flows.
    Then:
        - The right command is being called with the right argument name.
    """
    mocker.patch.object(demisto, "args", return_value={"user_email": ["john@example.com"]})
    mocker.patch.object(demisto, "getModules", return_value={})
    mocker.patch.object(Modules, "is_brand_in_brands_to_run", return_value=True)
    mocker.patch.object(Modules, "is_brand_available", return_value=True)
    mocker.patch("GetUserData.get_core_and_xdr_data", return_value=([], []))
    mocker.patch("GetUserData.return_results")

    _mute_all_other_adapters(mocker, except_fn=adapter_fn)
    seen = {"ok": False}

    def _assert_adapter(command: Command, additional_fields: bool):
        if command.brand != brand_name or command.name != command_name:
            return ([], [])
        assert command.args.get(expected_key) == expected_value
        assert command.args.get("using-brand") == brand_name
        seen["ok"] = True
        return ([], [])

    mocker.patch(f"GetUserData.{adapter_fn}", side_effect=_assert_adapter)
    main()
    assert seen["ok"] is True
