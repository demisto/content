from unittest.mock import patch, MagicMock
from CommonServerPython import *
import pytest
from ExpirePassword import (
    run_command,
    get_module_command_func,
    run_active_directory_query_v2,
    run_microsoft_graph_user,
    run_okta_v2,
    run_gsuiteadmin,
    run_aws_iam,
    validate_input,
    get_users,
    expire_passwords,  # Renamed function
    main,
    UserData,
    ExpiredPasswordResult,  # Renamed type
)


@pytest.fixture
def mock_demisto():
    with patch("ExpirePassword.demisto") as mock_demisto_obj:
        yield mock_demisto_obj


@pytest.fixture
def mock_run_command():
    with patch("ExpirePassword.run_command") as mock_exec_cmd:
        yield mock_exec_cmd


@pytest.fixture
def mock_return_results():
    with patch("ExpirePassword.return_results") as mock_rr_cmd:
        yield mock_rr_cmd


@pytest.fixture
def mock_return_error():
    with patch("ExpirePassword.return_error") as mock_re_cmd:
        yield mock_re_cmd


# --- Utility Function Tests (Mostly Unchanged) ---


def test_run_command_success(mock_demisto):
    """
    Given: demisto.executeCommand returns results with various types and human-readables.
    When: run_command is called.
    Then: It should filter out non-Type 1 or 4 results.
    """
    mock_demisto.executeCommand.return_value = [
        {"Type": 1, "Contents": "Success", "HumanReadable": "HR1"},
        {"Type": 4, "Contents": "Error", "HumanReadable": None},
        {"Type": 14, "Contents": "Log", "HumanReadable": "HR3"},
    ]
    results, hr = run_command("test-cmd", {})
    assert len(results) == 2
    assert results[0]["Contents"] == "Success"
    assert results[1]["Contents"] == "Error"
    assert hr == "\n\n".join(
        (
            "#### Result for name=test-cmd args={} current instance=N/A\nHR1",
            "#### Error for name=test-cmd args={} current instance=N/A\nError",
        )
    )


def test_run_command_no_human_readable(mock_demisto):
    """
    Given: demisto.executeCommand returns results without human-readables.
    When: run_command is called.
    Then: It should filter results correctly.
    """
    mock_demisto.executeCommand.return_value = [
        {"Type": 1, "Contents": "Success"},
    ]
    results, hr = run_command("test-cmd", {})
    assert len(results) == 1
    assert hr == "#### Result for name=test-cmd args={} current instance=N/A\nSuccess"


# --- Module Mapping Tests ---


def test_get_module_command_func_valid_module():
    """
    Given: A valid module name.
    When: get_module_command_func is called with the module name.
    Then: It should return the correct corresponding function. (Updated list)
    """
    assert get_module_command_func("Active Directory Query v2") == run_active_directory_query_v2
    assert get_module_command_func("Microsoft Graph User") == run_microsoft_graph_user
    assert get_module_command_func("Okta v2") == run_okta_v2
    assert get_module_command_func("GSuiteAdmin") == run_gsuiteadmin
    assert get_module_command_func("AWS-IAM") == run_aws_iam
    # Removed Okta IAM and AWS-ILM IAM commands


def test_get_module_command_func_invalid_module():
    """
    Given: An invalid module name.
    When: get_module_command_func is called with the invalid module name.
    Then: It should raise a DemistoException.
    """
    with pytest.raises(DemistoException, match="Unable to find module: 'InvalidModule'"):
        get_module_command_func("InvalidModule")


# --- Integration Function Tests (Updated Logic and Output) ---


def test_run_active_directory_query_v2_success(mock_run_command):
    """
    Given: An AD user.
    When: run_active_directory_query_v2 is called and both 'never expire' clear and 'expire' succeed.
    Then: It should run two commands and return a Result='Success' object.
    """
    user: UserData = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "AD",
        "Instance": "inst1",
    }
    # First call: ad-modify-password-never-expire (Success)
    # Second call: ad-expire-password (Success)
    mock_run_command.side_effect = [
        ([{"Contents": "Password Never Expire cleared", "Type": 1}], "HR_CLEAR"),
        ([{"Contents": "Password expired successfully", "Type": 1}], "HR_EXPIRE"),
    ]

    result, hr = run_active_directory_query_v2(user, "inst1")

    expected: list[ExpiredPasswordResult] = [
        {"Result": "Success", "Message": "Password expiration successfully enforced (AD flag cleared and expiration set)"}
    ]
    assert result == expected
    assert "HR_CLEAR\n\nHR_EXPIRE" in hr

    # Verify both commands were called with correct arguments
    mock_run_command.assert_any_call(
        "ad-modify-password-never-expire", {"username": "testuser", "using": "inst1", "value": "false"}
    )
    mock_run_command.assert_called_with("ad-expire-password", {"username": "testuser", "using": "inst1"})


def test_run_active_directory_query_v2_pre_check_failure(mock_run_command):
    """
    Given: An AD user.
    When: run_active_directory_query_v2 is called and 'never expire' clear fails.
    Then: It should stop after the first command and return a Result='Failed' object.
    """
    user: UserData = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "AD",
        "Instance": "inst1",
    }
    # First call: ad-modify-password-never-expire (Failure)
    mock_run_command.return_value = ([{"Contents": "Failed to connect to AD", "Type": 4}], "HR_CLEAR_FAIL")

    result, hr = run_active_directory_query_v2(user, "inst1")

    expected: list[ExpiredPasswordResult] = [
        {"Result": "Failed", "Message": "Pre-check failed (AD flag clearance): Failed to connect to AD"}
    ]
    assert result == expected
    assert "HR_CLEAR_FAIL" in hr
    # Verify ad-expire-password was NOT called
    mock_run_command.assert_called_once_with(
        "ad-modify-password-never-expire", {"username": "testuser", "using": "inst1", "value": "false"}
    )


def test_run_microsoft_graph_user_success(mock_run_command):
    """
    Given: A Microsoft Graph user.
    When: run_microsoft_graph_user is called and succeeds.
    Then: It should return a Result='Success' object, using the correct command.
    """
    user: UserData = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "MSGraph",
        "Instance": "inst1",
    }
    mock_run_command.return_value = ([{"Contents": "Success", "Type": 1}], "")
    result, _ = run_microsoft_graph_user(user, "inst1")

    expected: list[ExpiredPasswordResult] = [{"Result": "Success", "Message": "Password reset successfully enforced"}]
    assert result == expected
    mock_run_command.assert_called_with("msgraph-user-force-reset-password", {"user": "testuser", "using": "inst1"})


def test_run_microsoft_graph_user_failure(mock_run_command):
    """
    Given: A Microsoft Graph user.
    When: run_microsoft_graph_user is called and fails.
    Then: It should return a Result='Failed' object.
    """
    user: UserData = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "MSGraph",
        "Instance": "inst1",
    }
    mock_run_command.return_value = ([{"Contents": "Error details", "Type": 4}], "")
    result, _ = run_microsoft_graph_user(user, "inst1")

    expected: list[ExpiredPasswordResult] = [{"Result": "Failed", "Message": "Error details"}]
    assert result == expected


def test_run_okta_v2_success(mock_run_command):
    """
    Given: An Okta v2 user.
    When: run_okta_v2 is called and succeeds.
    Then: It should return a Result='Success' object, using the correct command.
    """
    user: UserData = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "Okta v2",
        "Instance": "inst1",
    }
    mock_run_command.return_value = ([{"Contents": "Success", "Type": 1}], "")
    result, _ = run_okta_v2(user, "inst1")

    expected: list[ExpiredPasswordResult] = [{"Result": "Success", "Message": "Password expired successfully"}]
    assert result == expected
    mock_run_command.assert_called_with("okta-expire-password", {"username": "testuser", "using": "inst1"})


def test_run_gsuiteadmin_success(mock_run_command):
    """
    Given: A GSuiteAdmin user.
    When: run_gsuiteadmin is called and succeeds.
    Then: It should return a Result='Success' object, using the correct command/args.
    """
    user: UserData = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "GSuiteAdmin",
        "Instance": "inst1",
    }
    mock_run_command.return_value = ([{"Contents": "Success", "Type": 1}], "")
    result, _ = run_gsuiteadmin(user, "inst1")

    expected: list[ExpiredPasswordResult] = [{"Result": "Success", "Message": "Password reset successfully enforced"}]
    assert result == expected
    mock_run_command.assert_called_with(
        "gsuite-user-reset-password",
        {"user_key": "test@example.com", "suspended": "true", "using": "inst1"},
    )


def test_run_aws_iam_success(mock_run_command):
    """
    Given: An AWS-IAM user.
    When: run_aws_iam is called and succeeds.
    Then: It should return a Result='Success' object, using the correct command and required arguments.
    """
    user: UserData = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "AWS-IAM",
        "Instance": "inst1",
    }
    mock_run_command.return_value = ([{"Contents": "Success", "Type": 1}], "")
    result, _ = run_aws_iam(user, "inst1")

    expected: list[ExpiredPasswordResult] = [
        {
            "Result": "Success",
            "Message": "IAM user login profile updated successfully, requiring password change on next sign-in.",
        }
    ]
    assert result == expected
    # Verify correct command name and specific arguments (userName, passwordResetRequired: True)
    mock_run_command.assert_called_with(
        "aws-iam-update-login-profile",
        {"userName": "testuser", "using": "inst1", "passwordResetRequired": "True"},
    )


# --- Input and User Data Tests (Mostly Unchanged, just import/error match) ---


def test_validate_input_failure_no_args():
    """
    Given: Arguments with none of 'user_id', 'user_name', or 'user_email' specified.
    When: validate_input is called.
    Then: It should raise a ValueError with the correct message.
    """
    with pytest.raises(
        ValueError,
        match="At least one of the following arguments must be specified: user_id, user_name or user_email.",
    ):
        validate_input({})


def test_get_users_failure_no_integrations(mock_run_command):
    """
    Given: A mock run_command indicating no integrations were available.
    When: get_users is called.
    Then: It should raise an error with the appropriate message from the design.
    """
    mock_run_command.return_value = (
        [
            {
                "Type": 1,
                "HumanReadable": "### User(s) data\n**No entries.**\n",
                "EntryContext": None,
            }
        ],
        "",
    )
    with pytest.raises(DemistoException, match="No integrations were found for the brands"):
        get_users({"user_name": "testuser"})


def test_expire_passwords_single_user_success(mock_run_command):
    """
    Given: A list containing a single 'found' user.
    When: expire_passwords is called.
    Then: It should call the correct module's function and return a successful context entry (Result: Success).
    """
    users: list[UserData] = [
        {
            "ID": "1",
            "Username": "testuser",
            "Email": "test@example.com",
            "Status": "found",
            "Brand": "Okta v2",
            "Instance": "inst1",
        }
    ]
    # Okta v2 test setup requires only one mock run_command call
    mock_run_command.return_value = ([{"Contents": "Success", "Type": 1}], "")

    results, _ = expire_passwords(users)
    expected_results = [
        {
            "UserProfile": {
                "ID": "1",
                "Username": "testuser",
                "Email": "test@example.com",
            },
            "Brand": "Okta v2",
            "Instance": "inst1",
            "Result": "Success",
            "Message": "Password expired successfully",
        }
    ]
    assert results == expected_results


def test_expire_passwords_no_found_users():
    """
    Given: A list of users where none have 'Status' as 'found'.
    When: expire_passwords is called.
    Then: It should raise an error matching the design requirement.
    """
    users: list[UserData] = [
        {
            "ID": "1",
            "Username": "testuser",
            "Email": "test@example.com",
            "Status": "not_found",
            "Brand": "AD",
            "Instance": "inst1",
        }
    ]
    with pytest.raises(DemistoException, match="User\(s\) not found."):
        expire_passwords(users)


# --- Main Logic Tests (Updated Logic) ---


def test_main_failure_no_success(mock_demisto, mock_run_command, mock_return_results):
    """
    Given: `demisto.args` specifies a user.
    When: `main` is called, and all `expire_passwords` actions result in a 'Failed' result.
    Then: `demisto.return_results` should be called once with a CommandResults of EntryType.ERROR.
    """
    mock_demisto.args.return_value = {"user_name": "testuser", "verbose": False}
    mock_demisto.error = MagicMock()

    # 1. get_users success
    # 2. expire_passwords failure (via Okta v2 mock)
    mock_run_command.side_effect = [
        (
            [
                {
                    "Type": 1,
                    "Contents": [
                        {
                            "ID": "1",
                            "Username": "testuser",
                            "Email": "test@example.com",
                            "Status": "found",
                            "Brand": "Okta v2",
                            "Instance": "inst1",
                        }
                    ],
                    "HumanReadable": "User data HR",
                    "EntryContext": [{}],
                }
            ],
            "",
        ),
        # Okta command fails
        ([{"Contents": "Error: User testuser failed to expire", "Type": 4}], ""),
    ]

    main()

    mock_return_results.assert_called_once()
    command_results_call_args = mock_return_results.call_args_list[0].args[0]
    assert isinstance(command_results_call_args, CommandResults)
    assert command_results_call_args.entry_type == EntryType.ERROR
    assert "Expire Password: All integrations failed." in command_results_call_args.readable_output
    assert "Error: User testuser failed to expire" in command_results_call_args.readable_output
    mock_demisto.error.assert_not_called()
