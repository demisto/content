import demistomock as demisto
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
    xdr_list_risky_users,
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
            "sAMAccountName": ["ad_user"],
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
                    "sAMAccountName": "ad_user",
                    "userAccountControlFields": {"ACCOUNTDISABLE": False},
                },
                "Email": "ad_user@example.com",
                "Source": "Active Directory Query v2",
                "Brand": "Active Directory Query v2",
                "Username": "ad_user",
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
            "sAMAccountName": "ad_user",
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
                    "sAMAccountName": "ad_user",
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
        command = Command("Cortex XDR - IR", "xdr-list-risky-users", {"user_id": user_name})
        mock_outputs = {"id": "xdr_user", "risk_level": "HIGH"}
        expected_account = [
            {
                "ID": "xdr_user",
                "RiskLevel": "HIGH",
                "Source": "Cortex XDR - IR",
                "Brand": "Cortex XDR - IR",
                "Username": "xdr_user",
                "Instance": None,
            }
        ]

        mocker.patch(
            "GetUserData.run_execute_command",
            return_value=([mock_outputs], "Human readable output", []),
        )
        mocker.patch("GetUserData.get_output_key", return_value="PaloAltoNetworksXDR.RiskyUser")
        mocker.patch("GetUserData.get_outputs", return_value=mock_outputs)
        mocker.patch("GetUserData.prepare_human_readable", return_value=[])

        result = xdr_list_risky_users(command, outputs_key_field, additional_fields=True)

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert result[1] == expected_account

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
    mocker.patch("GetUserData.xdr_list_risky_users", return_value=([], []))
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
