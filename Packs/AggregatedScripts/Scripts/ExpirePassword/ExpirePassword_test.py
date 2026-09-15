from unittest.mock import patch, MagicMock
from CommonServerPython import *
import pytest
from ExpirePassword import (
    run_command,
    run_active_directory_query_v2,
    check_ad_password_never_expires,
    run_microsoft_graph_user,
    run_okta_v2,
    run_gsuiteadmin,
    run_aws_iam,
    expire_passwords,
    main,
    UserData,
    ExpiredPasswordResult,
    get_instance_from_result,
    get_response_message,
    build_result,
    # Import constants for proper testing
    SUCCESS_MESSAGES,
    OKTA_PASSWORD_EXPIRED_MARKER,
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


# --- Utility Function Tests ---


def test_get_instance_from_result():
    """
    Given: A command result with metadata containing instance information.
    When: get_instance_from_result is called.
    Then: It should extract the instance name correctly.
    """
    res_with_instance = {"Metadata": {"instance": "test-instance"}}
    assert get_instance_from_result(res_with_instance) == "test-instance"

    res_without_metadata = {"Contents": "some content"}
    assert get_instance_from_result(res_without_metadata) == ""

    res_without_instance = {"Metadata": {"other": "value"}}
    assert get_instance_from_result(res_without_instance) == ""


def test_get_response_message():
    """
    Given: Command results with different message locations.
    When: get_response_message is called.
    Then: It should extract the message from HumanReadable, Contents, or use default.
    """
    res_with_hr = {"HumanReadable": "HR message", "Contents": "Contents message"}
    assert get_response_message(res_with_hr) == "HR message"

    res_with_contents = {"Contents": "Contents message"}
    assert get_response_message(res_with_contents) == "Contents message"

    res_empty = {}
    assert get_response_message(res_empty) == "Command failed"
    assert get_response_message(res_empty, "Custom default") == "Custom default"


def test_build_result():
    """
    Given: Command result and success condition.
    When: build_result is called.
    Then: It should create a properly formatted ExpiredPasswordResult.
    """
    res = {"Metadata": {"instance": "test-inst"}}

    success_result = build_result(res, True, "Success msg", "Failure msg")
    expected_success = ExpiredPasswordResult(Result="Success", Message="Success msg", Instance="test-inst")
    assert success_result == expected_success

    failure_result = build_result(res, False, "Success msg", "Failure msg")
    expected_failure = ExpiredPasswordResult(Result="Failed", Message="Failure msg", Instance="test-inst")
    assert failure_result == expected_failure


def test_run_command_success(mock_demisto):
    """
    Given: demisto.executeCommand returns results with various types and human-readables.
    When: run_command is called.
    Then: It should filter out non-Type 1 or 4 results.
    """
    mock_demisto.executeCommand.return_value = [
        {"Type": 1, "Contents": "Success", "HumanReadable": "HR1"},
        {"Type": 4, "Contents": "Error", "HumanReadable": None},
        {"Type": 3, "Contents": "File", "HumanReadable": "HR3"},
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


# --- Integration Function Tests (Updated Logic and Output) ---


def test_check_ad_password_never_expires_flag_true(mock_run_command):
    """
    Given: An AD user with DONT_EXPIRE_PASSWORD flag set to True.
    When: check_ad_password_never_expires is called.
    Then: It should return True for the flag value.
    """
    mock_run_command.return_value = (
        [
            {
                "Type": 1,
                "EntryContext": {
                    "ActiveDirectory.Users(obj.dn == val.dn)": [
                        {
                            "dn": "CN=testuser,DC=example,DC=com",
                            "sAMAccountName": ["testuser"],
                            "userAccountControlFields": {
                                "DONT_EXPIRE_PASSWORD": True,
                                "ACCOUNTDISABLE": False,
                            },
                        }
                    ]
                },
                "Metadata": {"instance": "inst1"},
            }
        ],
        "HR_GET_USER",
    )

    flag, res, hr = check_ad_password_never_expires("testuser", "inst1")

    assert flag is True
    assert len(res) == 1
    assert hr == "HR_GET_USER"
    mock_run_command.assert_called_once_with("ad-get-user", {"username": "testuser", "using": "inst1"})


def test_check_ad_password_never_expires_flag_false(mock_run_command):
    """
    Given: An AD user with DONT_EXPIRE_PASSWORD flag set to False.
    When: check_ad_password_never_expires is called.
    Then: It should return False for the flag value.
    """
    mock_run_command.return_value = (
        [
            {
                "Type": 1,
                "EntryContext": {
                    "ActiveDirectory.Users": [
                        {
                            "dn": "CN=testuser,DC=example,DC=com",
                            "sAMAccountName": ["testuser"],
                            "userAccountControlFields": {
                                "DONT_EXPIRE_PASSWORD": False,
                                "ACCOUNTDISABLE": False,
                            },
                        }
                    ]
                },
                "Metadata": {"instance": "inst1"},
            }
        ],
        "HR_GET_USER",
    )

    flag, res, hr = check_ad_password_never_expires("testuser", "inst1")

    assert flag is False
    assert len(res) == 1
    assert hr == "HR_GET_USER"


def test_run_active_directory_query_v2_success_flag_false(mock_run_command):
    """
    Given: An AD user with DONT_EXPIRE_PASSWORD flag set to False.
    When: run_active_directory_query_v2 is called.
    Then: It should check the flag, then expire the password and return Result='Success'.
    """
    user: UserData = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "Active Directory Query v2",
        "Instance": "inst1",
    }
    # First call: ad-get-user (flag is False)
    # Second call: ad-expire-password (Success)
    mock_run_command.side_effect = [
        (
            [
                {
                    "Type": 1,
                    "EntryContext": {"ActiveDirectory.Users": [{"userAccountControlFields": {"DONT_EXPIRE_PASSWORD": False}}]},
                    "Metadata": {"instance": "inst1"},
                }
            ],
            "HR_GET_USER",
        ),
        ([{"Contents": SUCCESS_MESSAGES["ad_password_expired"], "Type": 1, "Metadata": {"instance": "inst1"}}], "HR_EXPIRE"),
    ]

    result, hr = run_active_directory_query_v2(user, "inst1")

    expected: list[ExpiredPasswordResult] = [
        {"Result": "Success", "Message": SUCCESS_MESSAGES["ad_password_expired"], "Instance": "inst1"}
    ]
    assert result == expected
    assert "HR_GET_USER\n\nHR_EXPIRE" in hr

    # Verify both commands were called
    mock_run_command.assert_any_call("ad-get-user", {"username": "testuser", "using": "inst1"})
    mock_run_command.assert_called_with("ad-expire-password", {"username": "testuser", "using": "inst1"})


def test_run_active_directory_query_v2_flag_true_returns_failure(mock_run_command):
    """
    Given: An AD user with DONT_EXPIRE_PASSWORD flag set to True.
    When: run_active_directory_query_v2 is called.
    Then: It should return Result='Failed' with informative message and NOT call ad-expire-password.
    """
    user: UserData = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "Active Directory Query v2",
        "Instance": "inst1",
    }
    # Only ad-get-user is called (flag is True)
    mock_run_command.return_value = (
        [
            {
                "Type": 1,
                "EntryContext": {"ActiveDirectory.Users": [{"userAccountControlFields": {"DONT_EXPIRE_PASSWORD": True}}]},
                "Metadata": {"instance": "inst1"},
            }
        ],
        "HR_GET_USER",
    )

    result, hr = run_active_directory_query_v2(user, "inst1")

    expected: list[ExpiredPasswordResult] = [
        {
            "Result": "Failed",
            "Message": (
                "Cannot expire password for user testuser due to user policy. "
                "The 'Password Never Expire' flag is set to true. "
                "To expire the password, please change this setting to false using the command "
                "'ad-modify-password-never-expire'."
            ),
            "Instance": "inst1",
        }
    ]
    assert result == expected
    assert hr == "HR_GET_USER"
    # Verify ad-expire-password was NOT called (only one call to ad-get-user)
    mock_run_command.assert_called_once_with("ad-get-user", {"username": "testuser", "using": "inst1"})


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
        "Instance": "",
    }
    expected_msg = SUCCESS_MESSAGES["msgraph_user"].format(username="testuser")
    mock_run_command.return_value = ([{"HumanReadable": expected_msg, "Type": 1, "Metadata": {"instance": "inst1"}}], "")
    result, _ = run_microsoft_graph_user(user, "inst1")

    expected: list[ExpiredPasswordResult] = [{"Result": "Success", "Message": expected_msg, "Instance": "inst1"}]
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
    mock_run_command.return_value = ([{"HumanReadable": "Error details", "Type": 4, "Metadata": {"instance": "inst1"}}], "")
    result, _ = run_microsoft_graph_user(user, "inst1")

    expected: list[ExpiredPasswordResult] = [{"Result": "Failed", "Message": "Error details", "Instance": "inst1"}]
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
    success_msg = f"User status changed to {OKTA_PASSWORD_EXPIRED_MARKER}"
    mock_run_command.return_value = ([{"HumanReadable": success_msg, "Type": 1, "Metadata": {"instance": "inst1"}}], "")
    result, _ = run_okta_v2(user, "inst1")

    expected: list[ExpiredPasswordResult] = [
        {"Result": "Success", "Message": "Password expired successfully.", "Instance": "inst1"}
    ]
    assert result == expected
    mock_run_command.assert_called_with("okta-expire-password", {"username": "testuser", "using": "inst1"})


def test_run_okta_v2_failure(mock_run_command):
    """
    Given: An Okta v2 user.
    When: run_okta_v2 is called and fails (no PASSWORD_EXPIRED marker).
    Then: It should return a Result='Failed' object.
    """
    user: UserData = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "Okta v2",
        "Instance": "inst1",
    }
    failure_msg = "Failed to execute okta-expire-password command. User not found in Okta"
    mock_run_command.return_value = ([{"HumanReadable": failure_msg, "Type": 4, "Metadata": {"instance": "inst1"}}], "")
    result, _ = run_okta_v2(user, "inst1")

    expected: list[ExpiredPasswordResult] = [{"Result": "Failed", "Message": failure_msg, "Instance": "inst1"}]
    assert result == expected


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
    mock_run_command.return_value = (
        [{"Contents": {"changePasswordAtNextLogin": True}, "Type": 1, "Metadata": {"instance": "inst1"}}],
        "",
    )
    result, _ = run_gsuiteadmin(user, "inst1")

    expected: list[ExpiredPasswordResult] = [
        {"Result": "Success", "Message": "Password reset successfully enforced", "Instance": "inst1"}
    ]
    assert result == expected
    mock_run_command.assert_called_with(
        "gsuite-user-reset-password",
        {"user_key": "test@example.com", "using": "inst1"},
    )


def test_run_gsuiteadmin_failure(mock_run_command):
    """
    Given: A GSuiteAdmin user.
    When: run_gsuiteadmin is called and fails (changePasswordAtNextLogin is False or missing).
    Then: It should return a Result='Failed' object.
    """
    user: UserData = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "GSuiteAdmin",
        "Instance": "inst1",
    }
    mock_run_command.return_value = (
        [
            {
                "Contents": {"changePasswordAtNextLogin": False},
                "HumanReadable": "Failed to reset",
                "Type": 4,
                "Metadata": {"instance": "inst1"},
            }
        ],
        "",
    )
    result, _ = run_gsuiteadmin(user, "inst1")

    expected: list[ExpiredPasswordResult] = [{"Result": "Failed", "Message": "Failed to reset", "Instance": "inst1"}]
    assert result == expected


def test_run_active_directory_query_v2_expire_command_failure(mock_run_command):
    """
    Given: An AD user where flag check succeeds (False) but expire command fails.
    When: run_active_directory_query_v2 is called.
    Then: It should return a Result='Failed' object for the expire command.
    """
    user: UserData = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "Active Directory Query v2",
        "Instance": "inst1",
    }
    # First call: ad-get-user (flag is False), second call: ad-expire-password fails
    mock_run_command.side_effect = [
        (
            [
                {
                    "Type": 1,
                    "EntryContext": {"ActiveDirectory.Users": [{"userAccountControlFields": {"DONT_EXPIRE_PASSWORD": False}}]},
                    "Metadata": {"instance": "inst1"},
                }
            ],
            "HR_GET_USER",
        ),
        ([{"Contents": "Failed to expire password", "Type": 4, "Metadata": {"instance": "inst1"}}], "HR_EXPIRE_FAIL"),
    ]

    result, hr = run_active_directory_query_v2(user, "inst1")

    expected: list[ExpiredPasswordResult] = [{"Result": "Failed", "Message": "Failed to expire password", "Instance": "inst1"}]
    assert result == expected
    assert "HR_GET_USER\n\nHR_EXPIRE_FAIL" in hr


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
        "Brand": "AWS - IAM",
        "Instance": "inst1",
    }
    expected_msg = SUCCESS_MESSAGES["aws_iam"].format(username="testuser")
    mock_run_command.return_value = ([{"HumanReadable": expected_msg, "Type": 1, "Metadata": {"instance": "inst1"}}], "")
    result, _ = run_aws_iam(user, "inst1")

    expected: list[ExpiredPasswordResult] = [{"Result": "Success", "Message": expected_msg, "Instance": "inst1"}]
    assert result == expected
    # Verify correct command name and specific arguments (userName, passwordResetRequired: True)
    mock_run_command.assert_called_with(
        "aws-iam-update-login-profile",
        {"userName": "testuser", "using": "inst1", "passwordResetRequired": "True"},
    )


def test_run_aws_iam_failure(mock_run_command):
    """
    Given: An AWS-IAM user.
    When: run_aws_iam is called and fails (wrong success message).
    Then: It should return a Result='Failed' object.
    """
    user: UserData = {
        "ID": "1",
        "Username": "testuser",
        "Email": "test@example.com",
        "Status": "found",
        "Brand": "AWS - IAM",
        "Instance": "inst1",
    }
    failure_msg = "Access denied to IAM"
    mock_run_command.return_value = ([{"HumanReadable": failure_msg, "Type": 4, "Metadata": {"instance": "inst1"}}], "")
    result, _ = run_aws_iam(user, "inst1")

    expected: list[ExpiredPasswordResult] = [{"Result": "Failed", "Message": failure_msg, "Instance": "inst1"}]
    assert result == expected


# --- User Data Tests ---


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
    # Mock response must contain OKTA_PASSWORD_EXPIRED_MARKER for success
    success_msg = f"User status changed to {OKTA_PASSWORD_EXPIRED_MARKER}"
    mock_run_command.return_value = ([{"HumanReadable": success_msg, "Type": 1, "Metadata": {"instance": "inst1"}}], "")

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
            "Message": "Password expired successfully.",
        }
    ]
    assert results == expected_results


def test_expire_passwords_no_found_users():
    """
    Given: A list of users where none have 'Status' as 'found'.
    When: expire_passwords is called.
    Then: It should return empty results (no exception raised in current implementation).
    """
    users: list[UserData] = [
        {
            "ID": "1",
            "Username": "testuser",
            "Email": "test@example.com",
            "Status": "not_found",
            "Brand": "Active Directory Query v2",
            "Instance": "inst1",
        }
    ]
    results, hr = expire_passwords(users)
    assert results == []
    assert hr == ""


def test_expire_passwords_mixed_success_failure(mock_run_command):
    """
    Given: Multiple users with different integration brands, some succeed and some fail.
    When: expire_passwords is called.
    Then: It should process all users and return mixed results without stopping on failures.
    """
    users: list[UserData] = [
        {
            "ID": "1",
            "Username": "user1",
            "Email": "user1@example.com",
            "Status": "found",
            "Brand": "Okta v2",
            "Instance": "okta-inst",
        },
        {
            "ID": "2",
            "Username": "user2",
            "Email": "user2@example.com",
            "Status": "found",
            "Brand": "Microsoft Graph User",
            "Instance": "msgraph-inst",
        },
        {
            "ID": "3",
            "Username": "user3",
            "Email": "user3@example.com",
            "Status": "found",
            "Brand": "AWS - IAM",
            "Instance": "aws-inst",
        },
    ]

    # Mock responses: Okta succeeds, MSGraph fails, AWS succeeds
    mock_run_command.side_effect = [
        # Okta success
        (
            [
                {
                    "HumanReadable": f"User status changed to {OKTA_PASSWORD_EXPIRED_MARKER}",
                    "Type": 1,
                    "Metadata": {"instance": "okta-inst"},
                }
            ],
            "Okta HR",
        ),
        # MSGraph failure
        ([{"HumanReadable": "Graph API error", "Type": 4, "Metadata": {"instance": "msgraph-inst"}}], "MSGraph HR"),
        # AWS success
        (
            [
                {
                    "HumanReadable": SUCCESS_MESSAGES["aws_iam"].format(username="user3"),
                    "Type": 1,
                    "Metadata": {"instance": "aws-inst"},
                }
            ],
            "AWS HR",
        ),
    ]

    results, hr = expire_passwords(users)

    expected_results = [
        {
            "UserProfile": {"ID": "1", "Username": "user1", "Email": "user1@example.com"},
            "Brand": "Okta v2",
            "Result": "Success",
            "Message": "Password expired successfully.",
            "Instance": "okta-inst",
        },
        {
            "UserProfile": {"ID": "2", "Username": "user2", "Email": "user2@example.com"},
            "Brand": "Microsoft Graph User",
            "Result": "Failed",
            "Message": "Graph API error",
            "Instance": "msgraph-inst",
        },
        {
            "UserProfile": {"ID": "3", "Username": "user3", "Email": "user3@example.com"},
            "Brand": "AWS - IAM",
            "Result": "Success",
            "Message": SUCCESS_MESSAGES["aws_iam"].format(username="user3"),
            "Instance": "aws-inst",
        },
    ]

    assert results == expected_results
    assert "Okta HR" in hr
    assert "MSGraph HR" in hr
    assert "AWS HR" in hr


def test_expire_passwords_multiple_results_per_integration(mock_run_command):
    """
    Given: A single user but integration returns multiple results.
    When: expire_passwords is called.
    Then: It should handle multiple results from a single integration call.
    """
    users: list[UserData] = [
        {
            "ID": "1",
            "Username": "testuser",
            "Email": "test@example.com",
            "Status": "found",
            "Brand": "Active Directory Query v2",
            "Instance": "ad-inst",
        }
    ]

    # Mock AD returning multiple results (flag check + expire command)
    mock_run_command.side_effect = [
        # ad-get-user (flag is False)
        (
            [
                {
                    "Type": 1,
                    "EntryContext": {"ActiveDirectory.Users": [{"userAccountControlFields": {"DONT_EXPIRE_PASSWORD": False}}]},
                    "Metadata": {"instance": "ad-inst"},
                }
            ],
            "HR1",
        ),
        # ad-expire-password returns multiple results
        (
            [
                {"Contents": SUCCESS_MESSAGES["ad_password_expired"], "Type": 1, "Metadata": {"instance": "ad-inst"}},
                {"Contents": SUCCESS_MESSAGES["ad_password_expired"], "Type": 1, "Metadata": {"instance": "ad-inst-backup"}},
            ],
            "HR2",
        ),
    ]

    results, hr = expire_passwords(users)

    # Should get one result per command result from ad-expire-password
    assert len(results) == 2
    assert all(result["Result"] == "Success" for result in results)
    assert all(result["Message"] == SUCCESS_MESSAGES["ad_password_expired"] for result in results)
    assert results[0]["Instance"] == "ad-inst"
    assert results[1]["Instance"] == "ad-inst-backup"


# --- Main Logic Tests ---


def test_main_failure_no_success(mock_demisto, mock_run_command, mock_return_results):
    """
    Given: `demisto.args` specifies a user.
    When: `main` is called, and all `expire_passwords` actions result in a 'Failed' result.
    Then: `demisto.return_results` should be called once with a CommandResults of EntryType.ERROR.
    """
    mock_demisto.args.return_value = {"user_name": "testuser", "verbose": "false"}
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
        (
            [
                {
                    "HumanReadable": "Failed to execute okta-expire-password command. Error: User testuser failed to expire",
                    "Type": 4,
                    "Metadata": {"instance": "inst1"},
                }
            ],
            "",
        ),
    ]

    main()

    mock_return_results.assert_called_once()
    command_results_call_args = mock_return_results.call_args_list[0].args[0]
    assert isinstance(command_results_call_args, CommandResults)
    assert command_results_call_args.entry_type == EntryType.ERROR
    assert "Expire Password: All integrations failed." in command_results_call_args.readable_output
    assert "Error: User testuser failed to expire" in command_results_call_args.readable_output
    mock_demisto.error.assert_not_called()


def test_main_partial_success(mock_demisto, mock_run_command, mock_return_results):
    """
    Given: Multiple users with mixed success/failure results.
    When: main is called.
    Then: It should return success (not error) since at least one integration succeeded.
    """
    mock_demisto.args.return_value = {"user_name": "testuser", "verbose": "false"}
    mock_demisto.error = MagicMock()

    # Mock get_users returning multiple users
    mock_run_command.side_effect = [
        (
            [
                {
                    "Type": 1,
                    "Contents": [
                        {
                            "ID": "1",
                            "Username": "user1",
                            "Email": "user1@example.com",
                            "Status": "found",
                            "Brand": "Okta v2",
                            "Instance": "okta-inst",
                        },
                        {
                            "ID": "2",
                            "Username": "user2",
                            "Email": "user2@example.com",
                            "Status": "found",
                            "Brand": "Microsoft Graph User",
                            "Instance": "msgraph-inst",
                        },
                    ],
                    "HumanReadable": "User data HR",
                    "EntryContext": [{}],
                }
            ],
            "",
        ),
        # Okta succeeds
        (
            [
                {
                    "HumanReadable": f"User status changed to {OKTA_PASSWORD_EXPIRED_MARKER}",
                    "Type": 1,
                    "Metadata": {"instance": "okta-inst"},
                }
            ],
            "",
        ),
        # MSGraph fails
        ([{"HumanReadable": "Graph API error", "Type": 4, "Metadata": {"instance": "msgraph-inst"}}], ""),
    ]

    main()

    mock_return_results.assert_called_once()
    command_results_call_args = mock_return_results.call_args_list[0].args[0]
    assert isinstance(command_results_call_args, CommandResults)
    # Should be success since at least one integration succeeded
    assert command_results_call_args.entry_type != EntryType.ERROR
    assert "Expire Password" in command_results_call_args.readable_output
    mock_demisto.error.assert_not_called()


def test_main_all_success(mock_demisto, mock_run_command, mock_return_results):
    """
    Given: Multiple users, all succeed.
    When: main is called.
    Then: It should return success with all results.
    """
    mock_demisto.args.return_value = {"user_name": "testuser", "verbose": "true"}
    mock_demisto.error = MagicMock()

    mock_run_command.side_effect = [
        (
            [
                {
                    "Type": 1,
                    "Contents": [
                        {
                            "ID": "1",
                            "Username": "user1",
                            "Email": "user1@example.com",
                            "Status": "found",
                            "Brand": "Okta v2",
                            "Instance": "okta-inst",
                        }
                    ],
                    "HumanReadable": "User data HR",
                    "EntryContext": [{}],
                }
            ],
            "Get users HR",
        ),
        # Okta succeeds
        (
            [
                {
                    "HumanReadable": f"User status changed to {OKTA_PASSWORD_EXPIRED_MARKER}",
                    "Type": 1,
                    "Metadata": {"instance": "okta-inst"},
                }
            ],
            "Okta HR",
        ),
    ]

    main()

    mock_return_results.assert_called_once()
    command_results_call_args = mock_return_results.call_args_list[0].args[0]
    assert isinstance(command_results_call_args, CommandResults)
    assert command_results_call_args.entry_type != EntryType.ERROR
    # Verbose mode should include HR from get_users and expire_passwords
    assert "Get users HR" in command_results_call_args.readable_output
    assert "Okta HR" in command_results_call_args.readable_output
    mock_demisto.error.assert_not_called()


def test_main_exception_handling(mock_demisto, mock_return_error):
    """
    Given: An exception occurs during execution (inside the try block).
    When: main is called.
    Then: It should call return_error with the exception message.
    """
    mock_demisto.args.return_value = {"user_name": "testuser"}  # Valid args
    mock_demisto.error = MagicMock()  # Create explicit mock for demisto.error()

    # Patch validate_input to raise exception inside the try block
    with patch("ExpirePassword.validate_input", side_effect=Exception("Test exception")):
        main()

    # Verify error handling was called correctly
    mock_return_error.assert_called_once()
    error_msg = mock_return_error.call_args[0][0]
    assert "Failed to execute ExpirePassword. Error: Test exception" in error_msg
    mock_demisto.error.assert_called_once()  # Verify demisto.error() was called for logging
