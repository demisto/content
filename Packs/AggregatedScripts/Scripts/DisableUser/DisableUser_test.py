from unittest.mock import patch, MagicMock
from CommonServerPython import *
import pytest
from DisableUser import (
    execute_command,
    get_module_command_func,
    run_active_directory_query_v2,
    run_microsoft_graph_user,
    run_okta_v2,
    run_iam_disable_user,
    run_gsuiteadmin,
    validate_input,
    get_users,
    disable_users,
    main,
    HUMAN_READABLES,
    User,
    CmdFuncRes,
)


@pytest.fixture(autouse=True)
def clear_human_readables():
    HUMAN_READABLES.clear()


@pytest.fixture
def mock_demisto():
    with patch("DisableUser.demisto") as mock_demisto_obj:
        yield mock_demisto_obj


@pytest.fixture
def mock_execute_command():
    with patch("DisableUser.execute_command") as mock_exec_cmd:
        yield mock_exec_cmd


@pytest.fixture
def mock_return_results():
    with patch("DisableUser.return_results") as mock_rr_cmd:
        yield mock_rr_cmd


@pytest.fixture
def mock_return_error():
    with patch("DisableUser.return_error") as mock_re_cmd:
        yield mock_re_cmd


def test_execute_command_success(mock_demisto):
    """
    Given: demisto.executeCommand returns results with various types and human-readables.
    When: execute_command is called.
    Then: It should filter out non-Type 1 or 4 results, and append all human-readables to HUMAN_READABLES.
    """
    mock_demisto.executeCommand.return_value = [
        {"Type": 1, "Contents": "Success", "HumanReadable": "HR1"},
        {"Type": 4, "Contents": "Log", "HumanReadable": "HR2"},
        {"Type": 10, "Contents": "Other Type", "HumanReadable": "HR3"},
    ]
    results = execute_command("test-cmd", {})
    assert len(results) == 2
    assert results[0]["Contents"] == "Success"
    assert results[1]["Contents"] == "Log"
    assert HUMAN_READABLES == ["HR1", "HR2", "HR3"]


def test_execute_command_no_human_readable(mock_demisto):
    """
    Given: demisto.executeCommand returns results without human-readables.
    When: execute_command is called.
    Then: It should filter results correctly and HUMAN_READABLES should remain empty.
    """
    mock_demisto.executeCommand.return_value = [
        {"Type": 1, "Contents": "Success"},
    ]
    results = execute_command("test-cmd", {})
    assert len(results) == 1
    assert HUMAN_READABLES == []


def test_get_module_command_func_valid_module():
    """
    Given: A valid module name.
    When: get_module_command_func is called with the module name.
    Then: It should return the correct corresponding function.
    """
    assert (
        get_module_command_func("Active Directory Query v2")
        == run_active_directory_query_v2
    )
    assert get_module_command_func("Microsoft Graph User") == run_microsoft_graph_user
    assert get_module_command_func("Okta v2") == run_okta_v2
    assert get_module_command_func("Okta IAM") == run_iam_disable_user
    assert get_module_command_func("AWS-ILM") == run_iam_disable_user
    assert get_module_command_func("GSuiteAdmin") == run_gsuiteadmin


def test_get_module_command_func_invalid_module():
    """
    Given: An invalid module name.
    When: get_module_command_func is called with the invalid module name.
    Then: It should raise a DemistoException.
    """
    with pytest.raises(
        DemistoException, match="Unable to find module: 'InvalidModule'"
    ):
        get_module_command_func("InvalidModule")


def test_run_active_directory_query_v2_success(mock_execute_command):
    """
    Given: An Active Directory user and a mock execute_command that simulates a successful disable.
    When: run_active_directory_query_v2 is called.
    Then: It should return a CmdFuncRes indicating success and Disabled=True.
    """
    user: User = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "AD",
        "Instance": "inst1",
    }
    mock_execute_command.return_value = [{"Contents": "User testuser was disabled"}]
    result = run_active_directory_query_v2(user, "inst1")
    expected: list[CmdFuncRes] = [
        {"Disabled": True, "Result": "Success", "Message": "User testuser was disabled"}
    ]
    assert result == expected
    mock_execute_command.assert_called_with(
        "ad-disable-account", {"username": "testuser", "using": "inst1"}
    )


def test_run_active_directory_query_v2_failure(mock_execute_command):
    """
    Given: An Active Directory user and a mock execute_command that simulates a failed disable.
    When: run_active_directory_query_v2 is called.
    Then: It should return a CmdFuncRes indicating failure and Disabled=False.
    """
    user: User = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "AD",
        "Instance": "inst1",
    }
    mock_execute_command.return_value = [{"Contents": "Error disabling user"}]
    result = run_active_directory_query_v2(user, "inst1")
    expected: list[CmdFuncRes] = [
        {"Disabled": False, "Result": "Failed", "Message": "Error disabling user"}
    ]
    assert result == expected


def test_run_microsoft_graph_user_success(mock_execute_command):
    """
    Given: A Microsoft Graph user and a mock execute_command that simulates a successful disable.
    When: run_microsoft_graph_user is called.
    Then: It should return a CmdFuncRes indicating success and Disabled=True.
    """
    user: User = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "MSGraph",
        "Instance": "inst1",
    }
    mock_execute_command.return_value = [
        {"HumanReadable": 'user: "testuser" account has been disabled successfully.'}
    ]
    result = run_microsoft_graph_user(user, "inst1")
    expected: list[CmdFuncRes] = [
        {
            "Disabled": True,
            "Result": "Success",
            "Message": 'user: "testuser" account has been disabled successfully.',
        }
    ]
    assert result == expected
    mock_execute_command.assert_called_with(
        "msgraph-user-account-disable", {"user": "testuser", "using": "inst1"}
    )


def test_run_microsoft_graph_user_failure(mock_execute_command):
    """
    Given: A Microsoft Graph user and a mock execute_command that simulates a failed disable.
    When: run_microsoft_graph_user is called.
    Then: It should return a CmdFuncRes indicating failure and Disabled=False.
    """
    user: User = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "MSGraph",
        "Instance": "inst1",
    }
    mock_execute_command.return_value = [
        {"HumanReadable": "Error disabling user", "Content": "Error details"}
    ]
    result = run_microsoft_graph_user(user, "inst1")
    expected: list[CmdFuncRes] = [
        {"Disabled": False, "Result": "Failed", "Message": "Error details"}
    ]
    assert result == expected


def test_run_okta_v2_success(mock_execute_command):
    """
    Given: An Okta v2 user and a mock execute_command that simulates a successful suspend.
    When: run_okta_v2 is called.
    Then: It should return a CmdFuncRes indicating success and Disabled=True.
    """
    user: User = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "Okta v2",
        "Instance": "inst1",
    }
    mock_execute_command.return_value = [
        {"Contents": "### testuser status is Suspended"}
    ]
    result = run_okta_v2(user, "inst1")
    expected: list[CmdFuncRes] = [
        {
            "Disabled": True,
            "Result": "Success",
            "Message": "### testuser status is Suspended",
        }
    ]
    assert result == expected
    mock_execute_command.assert_called_with(
        "okta-suspend-user", {"username": "testuser", "using": "inst1"}
    )


def test_run_okta_v2_cannot_suspend_inactive(mock_execute_command):
    """
    Given: An Okta v2 user and a mock execute_command indicating user is already inactive.
    When: run_okta_v2 is called.
    Then: It should return a CmdFuncRes indicating failure, but Disabled=True as no action is needed.
    """
    user: User = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "Okta v2",
        "Instance": "inst1",
    }
    mock_execute_command.return_value = [
        {"Contents": "Cannot suspend a user that is not active"}
    ]
    result = run_okta_v2(user, "inst1")
    expected: list[CmdFuncRes] = [
        {
            "Disabled": True,
            "Result": "Failed",
            "Message": "Cannot suspend a user that is not active",
        }
    ]
    assert result == expected


def test_run_okta_v2_failure(mock_execute_command):
    """
    Given: An Okta v2 user and a mock execute_command simulating an unknown failure.
    When: run_okta_v2 is called.
    Then: It should return a CmdFuncRes indicating failure and Disabled=False.
    """
    user: User = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "Okta v2",
        "Instance": "inst1",
    }
    mock_execute_command.return_value = [{"Contents": "Unknown Okta error"}]
    result = run_okta_v2(user, "inst1")
    expected: list[CmdFuncRes] = [
        {"Disabled": False, "Result": "Failed", "Message": "Unknown Okta error"}
    ]
    assert result == expected


def test_run_okta_iam_success(mock_execute_command):
    """
    Given: An Okta IAM user and a mock execute_command simulating a successful disable.
    When: run_okta_iam is called.
    Then: It should return a CmdFuncRes indicating success. Disabled should be False as per IAM standard for disabled users.
    """
    user: User = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "Okta IAM",
        "Instance": "inst1",
    }
    mock_execute_command.return_value = [
        {
            "Contents": {"IAM": {"Vendor": {"active": False, "success": True, "errorMessage": ""}}},
            "HumanReadable": "User disabled.",
            "Type": 1,
        }
    ]
    result = run_iam_disable_user(user, "inst1")
    expected: list[CmdFuncRes] = [
        {"Disabled": True, "Result": "Success", "Message": "User disabled."}
    ]
    assert result == expected
    mock_execute_command.assert_called_with(
        "iam-disable-user",
        {"user-profile": '{"email":"test@example.com"}', "using": "inst1"},
    )


def test_run_okta_iam_failure_error_message(mock_execute_command):
    """
    Given: An Okta IAM user and a mock execute_command simulating a failed disable with an error message.
    When: run_okta_iam is called.
    Then: It should return a CmdFuncRes indicating failure, with the error message.
    """
    user: User = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "Okta IAM",
        "Instance": "inst1",
    }
    mock_execute_command.return_value = [
        {
            "Type": 4,
            "Contents": {"IAM": {
                "Vendor": {
                    "active": True,
                    "success": False,
                    "errorMessage": "IAM error.",
                }
            },
        }}
    ]
    result = run_iam_disable_user(user, "inst1")
    expected: list[CmdFuncRes] = [
        {"Disabled": False, "Result": "Failed", "Message": "IAM error."}
    ]
    assert result == expected


def test_run_gsuiteadmin_success(mock_execute_command):
    """
    Given: A GSuiteAdmin user and a mock execute_command simulating a successful suspension.
    When: run_gsuiteadmin is called.
    Then: It should return a CmdFuncRes indicating success and Disabled=True.
    """
    user: User = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "GSuiteAdmin",
        "Instance": "inst1",
    }
    mock_execute_command.return_value = [
        {
            "Contents": {"suspended": True},
            "HumanReadable": "User suspended in GSuite.",
            "Type": 1,
        }
    ]
    result = run_gsuiteadmin(user, "inst1")
    expected: list[CmdFuncRes] = [
        {"Disabled": True, "Result": "Success", "Message": "User suspended in GSuite."}
    ]
    assert result == expected
    mock_execute_command.assert_called_with(
        "gsuite-user-update",
        {"user_key": "test@example.com", "suspended": "true", "using": "inst1"},
    )


def test_run_gsuiteadmin_failure(mock_execute_command):
    """
    Given: A GSuiteAdmin user and a mock execute_command simulating a failed suspension.
    When: run_gsuiteadmin is called.
    Then: It should return a CmdFuncRes indicating failure and Disabled=False.
    """
    user: User = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "GSuiteAdmin",
        "Instance": "inst1",
    }
    mock_execute_command.return_value = [
        {"Type": 4, "Contents": "Error in GSuite", "HumanReadable": "GSuite error HR."}
    ]
    result = run_gsuiteadmin(user, "inst1")
    expected: list[CmdFuncRes] = [
        {"Disabled": False, "Result": "Failed", "Message": "GSuite error HR."}
    ]
    assert result == expected


def test_validate_input_success_user_id():
    """
    Given: Arguments with 'user_id' specified.
    When: validate_input is called.
    Then: It should not raise any exception.
    """
    validate_input({"user_id": "123"})


def test_validate_input_success_user_name():
    """
    Given: Arguments with 'user_name' specified.
    When: validate_input is called.
    Then: It should not raise any exception.
    """
    validate_input({"user_name": "test"})


def test_validate_input_success_user_email():
    """
    Given: Arguments with 'user_email' specified.
    When: validate_input is called.
    Then: It should not raise any exception.
    """
    validate_input({"user_email": "test@example.com"})


def test_validate_input_failure_no_args():
    """
    Given: Arguments with none of 'user_id', 'user_name', or 'user_email' specified.
    When: validate_input is called.
    Then: It should raise a DemistoException.
    """
    with pytest.raises(
        DemistoException,
        match="At least one of the following arguments must be specified: user_id, user_name or user_email.",
    ):
        validate_input({})


def test_get_users_success(mock_execute_command, mock_return_error):
    """
    Given: A mock execute_command that returns a successful user data lookup.
    When: get_users is called with arguments.
    Then: It should return the list of user data and append the human-readable to HUMAN_READABLES.
    """
    mock_execute_command.return_value = [
        {
            "Type": 1,
            "Contents": {"UserData": [
                {
                    "ID": "1",
                    "Username": "testuser",
                    "Email": "test@example.com",
                    "Status": "found",
                    "Brand": "AD",
                    "Instance": "inst1",
                }
            ]},
            "HumanReadable": "User data HR",
        }
    ]
    users = get_users({"user_name": "testuser"})
    expected_users: list[User] = [
        {
            "ID": "1",
            "Username": "testuser",
            "Email": "test@example.com",
            "Status": "found",
            "Brand": "AD",
            "Instance": "inst1",
        }
    ]
    assert users == expected_users
    assert HUMAN_READABLES == ["User data HR"]
    mock_execute_command.assert_called_with("get-user-data", {"user_name": "testuser"})
    mock_return_error.assert_not_called()


def test_get_users_failure(mock_execute_command, mock_return_error):
    """
    Given: A mock execute_command that returns an error for user data lookup.
    When: get_users is called.
    Then: It should call demisto.return_error with the appropriate error message.
    """
    mock_execute_command.return_value = [
        {"Type": 4, "Contents": {"UserData": "User not found"}, "HumanReadable": "User not found"}
    ]
    with patch("DisableUser.get_error", return_value="User not found error"):
        get_users({"user_name": "nonexistent"})
    mock_return_error.assert_called_once_with("User not found error")
    assert HUMAN_READABLES == ["User not found"]


def test_disable_users_single_user_success(mock_execute_command):
    """
    Given: A list containing a single 'found' user.
    When: disable_users is called.
    Then: It should call the correct module's disable function and return a successful context entry.
    """
    users: list[User] = [
        {
            "ID": "1",
            "Username": "testuser",
            "Email": "test@example.com",
            "Status": "found",
            "Brand": "Active Directory Query v2",
            "Instance": "inst1",
        }
    ]
    mock_execute_command.return_value = [
        {"Contents": "User testuser was disabled", "Type": 1}
    ]
    results = disable_users(users)
    expected_results = [
        {
            "UserProfile": {
                "ID": "1",
                "Username": "testuser",
                "Email": "test@example.com",
                "Status": "found",
            },
            "Brand": "Active Directory Query v2",
            "Instance": "inst1",
            "Disabled": True,
            "Result": "Success",
            "Message": "User testuser was disabled",
        }
    ]
    assert results == expected_results


def test_disable_users_no_found_users():
    """
    Given: A list of users where none have 'Status' as 'found'.
    When: disable_users is called.
    Then: It should return an empty list.
    """
    users: list[User] = [
        {
            "ID": "1",
            "Username": "testuser",
            "Email": "test@example.com",
            "Status": "not_found",
            "Brand": "AD",
            "Instance": "inst1",
        }
    ]
    results = disable_users(users)
    assert results == []


def test_disable_users_multiple_users_mixed_results(mock_execute_command):
    """
    Given: A list of users with mixed 'found' and 'not_found' statuses, and different brands.
    When: disable_users is called.
    Then: It should correctly process only 'found' users, calling the appropriate module functions
          and returning context entries for each, reflecting success or failure.
    """
    users: list[User] = [
        {
            "ID": "1",
            "Username": "aduser",
            "Email": "ad@example.com",
            "Status": "found",
            "Brand": "Active Directory Query v2",
            "Instance": "ad_inst",
        },
        {
            "ID": "2",
            "Username": "msgraphuser",
            "Email": "msgraph@example.com",
            "Status": "found",
            "Brand": "Microsoft Graph User",
            "Instance": "msgraph_inst",
        },
        {
            "ID": "3",
            "Username": "notfounduser",
            "Email": "notfound@example.com",
            "Status": "not_found",
            "Brand": "Okta v2",
            "Instance": "okta_inst",
        },
    ]

    def side_effect(cmd, args):
        if cmd == "ad-disable-account":
            return [{"Contents": f"User {args['username']} was disabled", "Type": 1}]
        elif cmd == "msgraph-user-account-disable":
            return [
                {
                    "HumanReadable": f'user: "{args["user"]}" account has been disabled successfully.',
                    "Type": 1,
                }
            ]
        return []

    mock_execute_command.side_effect = side_effect
    results = disable_users(users)

    expected_results = [
        {
            "UserProfile": {
                "ID": "1",
                "Username": "aduser",
                "Email": "ad@example.com",
                "Status": "found",
            },
            "Brand": "Active Directory Query v2",
            "Instance": "ad_inst",
            "Disabled": True,
            "Result": "Success",
            "Message": "User aduser was disabled",
        },
        {
            "UserProfile": {
                "ID": "2",
                "Username": "msgraphuser",
                "Email": "msgraph@example.com",
                "Status": "found",
            },
            "Brand": "Microsoft Graph User",
            "Instance": "msgraph_inst",
            "Disabled": True,
            "Result": "Success",
            "Message": 'user: "msgraphuser" account has been disabled successfully.',
        },
    ]
    assert len(results) == 2
    assert sorted(results, key=lambda x: x["UserProfile"]["ID"]) == sorted(
        expected_results, key=lambda x: x["UserProfile"]["ID"]
    )


def test_main_failure_no_user_disabled(mock_demisto, mock_execute_command, mock_return_results):
    """
    Given: `demisto.args` specifies a user.
    When: `main` function is called, and `get_users` succeeds but `disable_users` results in no user being truly 'Disabled'.
    Then: `demisto.return_results` should be called once with a `CommandResults` of `EntryType.ERROR`.
    """
    mock_demisto.args.return_value = {"user_name": "testuser"}
    mock_demisto.error = MagicMock()

    mock_execute_command.side_effect = [
        [
            {
                "Type": 1,
                "Contents": {
                    "UserData": [
                        {
                            "ID": "1",
                            "Username": "testuser",
                            "Email": "test@example.com",
                            "Status": "found",
                            "Brand": "Active Directory Query v2",
                            "Instance": "inst1",
                        }
                    ]
                },
                "HumanReadable": "User data HR",
            }
        ],
        [{"Contents": "Error: User testuser not disabled", "Type": 4}],
    ]

    main()

    mock_return_results.assert_called_once()
    command_results_call_args = mock_return_results.call_args_list[0].args[0]
    assert isinstance(command_results_call_args, CommandResults)
    assert command_results_call_args.entry_type == EntryType.ERROR
    assert command_results_call_args.content_format == EntryFormat.MARKDOWN
    assert "Disable User Failed" in command_results_call_args.readable_output
    assert (
        "Error: User testuser not disabled" in command_results_call_args.readable_output
    )
    mock_demisto.error.assert_not_called()
