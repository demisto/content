import pytest
from CommonServerPython import DemistoException  # Removed CommandResults
import json

import BlockUserAppAccessWithCAPolicy


SCRIPT_NAME = "BlockUserAppAccessWithCAPolicy"


def test_get_policy_name_when_custom_provided():
    """
    Given:
        - app name 'MyApp'
        - policy name 'Custom Policy Name'
    When:
        - Calling get_policy_name function
    Then:
        - Ensure the result equals the custom policy name
    """
    assert BlockUserAppAccessWithCAPolicy.get_policy_name("MyApp", "Custom Policy Name") == "Custom Policy Name"


def test_get_policy_name_when_none_provided():
    """
    Given:
        - app name 'MyApp'
        - no custom policy name
    When:
        - Calling get_policy_name function
    Then:
        - Ensure the result uses the default prefix
    """
    assert BlockUserAppAccessWithCAPolicy.get_policy_name("MyApp", None) == "Cortex App Block Access - MyApp"


def test_resolve_user_object_id_when_guid():
    """
    Given:
        - A user identifier in GUID format
    When:
        - Calling resolve_user_object_id
    Then:
        - Should return the GUID as-is
    """
    guid = "12345678-abcd-1234-abcd-1234567890ab"
    assert BlockUserAppAccessWithCAPolicy.resolve_user_object_id(guid) == guid


def test_resolve_user_object_id_when_upn(mocker):
    """
    Given:
        - A user identifier in UPN format
    When:
        - Calling resolve_user_object_id
    Then:
        - Should resolve to the user's object ID via command execution
    """
    mocker.patch(
        "BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error",
        return_value={"id": "user-object-id-1234"},
    )
    assert BlockUserAppAccessWithCAPolicy.resolve_user_object_id("user@example.com") == "user-object-id-1234"


# --- Tests for _parse_error_message ---
def test__parse_error_message_parsing_json_error():
    """
    Given:
        - Command result with embedded API error JSON string (Error in API call)
    When:
        - Calling _parse_error_message
    Then:
        - Should parse and extract a formatted error code and message
    """
    res = {"Contents": 'Error in API call [403] - { "error": { "code": "Forbidden", "message": "Not allowed" } }'}
    assert BlockUserAppAccessWithCAPolicy._parse_error_message(res) == "Forbidden: Not allowed"


def test__parse_error_message_unparsed_string():
    """
    Given:
        - Command result with a string error message not containing JSON or "Error in API call"
    When:
        - Calling _parse_error_message
    Then:
        - Should return the raw string as-is
    """
    res = {"Contents": "Some simple error occurred"}
    assert BlockUserAppAccessWithCAPolicy._parse_error_message(res) == "Some simple error occurred"


def test__parse_error_message_json_parse_fails(mocker):
    """
    Given:
        - Command result with "Error in API call" but malformed JSON (ValueError for index or JSONDecodeError)
    When:
        - Calling _parse_error_message
    Then:
        - Should return the unparsed API error message
    """
    # Test case for json.JSONDecodeError
    mocker.patch("json.loads", side_effect=json.JSONDecodeError("Expecting value", "raw", 0))
    res = {"Contents": 'Error in API call [400] - { "error": "malformed json"'}
    assert BlockUserAppAccessWithCAPolicy._parse_error_message(res) == f"Unparsed API error: {res['Contents']}"

    # Test case for ValueError (if .index() fails)
    mocker.patch("json.loads", side_effect=lambda x: json.loads(x))  # Reset json.loads
    res_no_json_part = {"Contents": "Error in API call [400] - Malformed string not json"}
    assert (
        BlockUserAppAccessWithCAPolicy._parse_error_message(res_no_json_part)
        == f"Unparsed API error: {res_no_json_part['Contents']}"
    )


def test__parse_error_message_raw_json_error_string():
    """
    Given:
        - Command result with a string that is a direct JSON error object (not prefixed)
    When:
        - Calling _parse_error_message
    Then:
        - Should parse and extract the error code and message
    """
    res = {"Contents": '{ "error": { "code": "BadRequest", "message": "Invalid request" } }'}
    assert BlockUserAppAccessWithCAPolicy._parse_error_message(res) == "BadRequest: Invalid request"


def test__parse_error_message_raw_dict_error():
    """
    Given:
        - Command result where 'Contents' is directly a dictionary with an 'error' key
    When:
        - Calling _parse_error_message
    Then:
        - Should extract the error code and message from the dictionary
    """
    res = {"Contents": {"error": {"code": "Unauthorized", "message": "Access denied"}}}
    assert BlockUserAppAccessWithCAPolicy._parse_error_message(res) == "Unauthorized: Access denied"


def test__parse_error_message_fallback_no_contents():
    """
    Given:
        - Command result with no 'Contents' but 'ReadableContents'
    When:
        - Calling _parse_error_message
    Then:
        - Should return 'ReadableContents'
    """
    res = {"ReadableContents": "Something went wrong readable."}
    assert BlockUserAppAccessWithCAPolicy._parse_error_message(res) == "Something went wrong readable."


def test__parse_error_message_fallback_empty_res():
    """
    Given:
        - An empty dictionary as result (no Contents, no ReadableContents)
    When:
        - Calling _parse_error_message
    Then:
        - Should return "Unknown error"
    """
    res = {}
    assert BlockUserAppAccessWithCAPolicy._parse_error_message(res) == "Unknown error"


def test__parse_error_message_unexpected_exception(mocker):
    """
    Given:
        - An unexpected exception occurs within _parse_error_message
        (e.g., if res.get('Contents') returns a complex object that str() fails on or other unexpected structure)
    When:
        - Calling _parse_error_message
    Then:
        - Should return a generic error extraction message
    """
    # Mock demisto.debug to prevent actual logging during test
    mocker.patch.object(BlockUserAppAccessWithCAPolicy.demisto, "debug")

    # Simulate an unexpected exception *within* the parsing logic itself.
    # For example, if raw_contents is an object that raises an error when converted to string or loaded as JSON.
    class UnstringifiableObject:
        def __str__(self):
            raise ValueError("Forced str() conversion error")

    res = {"Contents": UnstringifiableObject()}
    result = BlockUserAppAccessWithCAPolicy._parse_error_message(res)
    assert "Error extracting error message: Forced str() conversion error" in result


# --- Tests for _execute_command_and_handle_error ---
def test__execute_command_and_handle_error_success(mocker):
    """
    Given:
        - A successful demisto.executeCommand call
    When:
        - Calling _execute_command_and_handle_error
    Then:
        - Should return the 'Contents' of the result
    """
    mocker.patch(
        "BlockUserAppAccessWithCAPolicy.demisto.executeCommand",
        return_value=[{"Contents": {"key": "value"}}],
    )
    mocker.patch("BlockUserAppAccessWithCAPolicy.is_error", return_value=False)

    result = BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error("command", {}, "Error Prefix")
    assert result == {"key": "value"}


def test__execute_command_and_handle_error_failure(mocker):
    """
    Given:
        - A failed demisto.executeCommand call
    When:
        - Calling _execute_command_and_handle_error
    Then:
        - Should raise DemistoException with the appropriate message
    """
    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.executeCommand", return_value=[{"Contents": "Error"}])
    mocker.patch("BlockUserAppAccessWithCAPolicy.is_error", return_value=True)
    mocker.patch("BlockUserAppAccessWithCAPolicy._parse_error_message", return_value="bad error")

    with pytest.raises(DemistoException, match="Error Prefix: bad error"):
        BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error("command", {}, "Error Prefix")


def test__execute_command_and_handle_error_empty_res(mocker):
    """
    Given:
        - demisto.executeCommand returns an empty list or None
    When:
        - Calling _execute_command_and_handle_error
    Then:
        - Should raise DemistoException with 'Empty response'
    """
    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.executeCommand", return_value=[])

    with pytest.raises(DemistoException, match="Error Prefix: Empty response for command."):
        BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error("command", {}, "Error Prefix")

    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.executeCommand", return_value=None)
    with pytest.raises(DemistoException, match="Error Prefix: Empty response for command."):
        BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error("command", {}, "Error Prefix")


def test__execute_command_and_handle_error_invalid_res_structure(mocker):
    """
    Given:
        - demisto.executeCommand returns a list with non-dict first element or an empty first element.
    When:
        - Calling _execute_command_and_handle_error
    Then:
        - Should raise DemistoException or return empty dict if not error.
    """
    # Case 1: First element is not a dict
    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.executeCommand", return_value=["not a dict"])
    with pytest.raises(
        DemistoException, match="Error Prefix: Unexpected type for command result contents: Expected dict, got str."
    ):
        BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error("command", {}, "Error Prefix")

    # Case 2: First element is None (empty first element)
    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.executeCommand", return_value=[None])
    with pytest.raises(DemistoException, match="Error Prefix: Empty first element in command result for command."):
        BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error("command", {}, "Error Prefix")

    # Case 3: First element is an empty dict, but not an error.
    # The script should now correctly handle [{}] returning {} because `res[0] is None`
    # is the specific check for empty first element error, not `not res[0]`.
    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.executeCommand", return_value=[{}])
    mocker.patch("BlockUserAppAccessWithCAPolicy.is_error", return_value=False)
    result = BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error("command", {}, "Error Prefix")
    assert result == {}  # Assert it returns an empty dict, as that's what `get("Contents", {})` would produce


# --- Tests for resolve_app_object_id ---
def test_resolve_app_object_id_valid_response_dict(mocker):
    """
    Given:
        - App name that matches one entry in the service principal list, response is a dict with MSGraphApplication
    When:
        - Calling resolve_app_object_id
    Then:
        - Should return the appId of the matching app
    """
    mocker.patch(
        "BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error",
        return_value={"MSGraphApplication": [{"displayName": "MyApp", "appId": "app-id-123"}]},
    )
    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.info")

    result = BlockUserAppAccessWithCAPolicy.resolve_app_object_id("MyApp")
    assert result == "app-id-123"


def test_resolve_app_object_id_app_not_found(mocker):
    """
    Given:
        - App name that does not exist in the service principal list
    When:
        - Calling resolve_app_object_id
    Then:
        - Should raise DemistoException with list of available apps
    """
    mocker.patch(
        "BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error",
        return_value={"MSGraphApplication": [{"displayName": "OtherApp"}]},
    )
    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.info")

    with pytest.raises(DemistoException, match="Application 'MyApp' not found"):
        BlockUserAppAccessWithCAPolicy.resolve_app_object_id("MyApp")


def test_resolve_app_object_id_res_is_list(mocker):
    """
    Given:
        - App name and _execute_command_and_handle_error returns a list directly
    When:
        - Calling resolve_app_object_id
    Then:
        - Should return the appId
    """
    mocker.patch(
        "BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error",
        return_value=[{"displayName": "AnotherApp", "appId": "list-app-id-456"}],
    )
    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.info")
    result = BlockUserAppAccessWithCAPolicy.resolve_app_object_id("AnotherApp")
    assert result == "list-app-id-456"


def test_resolve_app_object_id_unexpected_res_type(mocker):
    """
    Given:
        - _execute_command_and_handle_error returns an unexpected type (e.g., string)
    When:
        - Calling resolve_app_object_id
    Then:
        - Should raise DemistoException for unexpected format
    """
    # This case will be caught by _execute_command_and_handle_error first,
    # as its return value is then processed by resolve_app_object_id.
    # So, we expect the exception from _execute_command_and_handle_error.
    mocker.patch(
        "BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error",
        side_effect=DemistoException(
            "Failed to list service principals: Invalid command result structure (not a list) "
            "for msgraph-apps-service-principal-list."
        ),
    )
    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.info")

    with pytest.raises(DemistoException, match="Failed to list service principals: Invalid command result structure"):
        BlockUserAppAccessWithCAPolicy.resolve_app_object_id("AnyApp")


def test_resolve_app_object_id_missing_app_id(mocker):
    """
    Given:
        - App found but its 'appId' key is missing or None
    When:
        - Calling resolve_app_object_id
    Then:
        - Should raise DemistoException
    """
    mocker.patch(
        "BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error",
        return_value={"MSGraphApplication": [{"displayName": "AppWithoutID", "appId": None}]},
    )
    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.info")

    with pytest.raises(DemistoException, match="Application 'AppWithoutID' found, but its 'appId' is missing."):
        BlockUserAppAccessWithCAPolicy.resolve_app_object_id("AppWithoutID")


# --- Tests for fetch_policy_by_name ---
def test_fetch_policy_by_name_found(mocker):
    """
    Given:
        - A CA policy with matching displayName exists (contents as dict with 'value')
    When:
        - Calling fetch_policy_by_name
    Then:
        - Should return the policy dict
    """
    mocker.patch(
        "BlockUserAppAccessWithCAPolicy.demisto.executeCommand",
        return_value=[{"Contents": {"value": [{"displayName": "My Policy"}]}}],
    )
    mocker.patch("BlockUserAppAccessWithCAPolicy.is_error", return_value=False)

    result = BlockUserAppAccessWithCAPolicy.fetch_policy_by_name("My Policy")
    assert result["displayName"] == "My Policy"


def test_fetch_policy_by_name_not_found(mocker):
    """
    Given:
        - No CA policy with the given name exists
    When:
        - Calling fetch_policy_by_name
    Then:
        - Should return None
    """
    mocker.patch(
        "BlockUserAppAccessWithCAPolicy.demisto.executeCommand",
        return_value=[{"Contents": {"value": [{"displayName": "Other Policy"}]}}],
    )
    mocker.patch("BlockUserAppAccessWithCAPolicy.is_error", return_value=False)

    assert BlockUserAppAccessWithCAPolicy.fetch_policy_by_name("Nonexistent Policy") is None


def test_fetch_policy_by_name_empty_or_invalid_response(mocker):
    """
    Given:
        - demisto.executeCommand returns an empty list, None, or a non-list
    When:
        - Calling fetch_policy_by_name
    Then:
        - Should raise DemistoException
    """
    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.executeCommand", return_value=[])
    with pytest.raises(DemistoException, match="Failed to retrieve Conditional Access policies: Empty or invalid response."):
        BlockUserAppAccessWithCAPolicy.fetch_policy_by_name("Any Policy")

    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.executeCommand", return_value=None)
    with pytest.raises(DemistoException, match="Failed to retrieve Conditional Access policies: Empty or invalid response."):
        BlockUserAppAccessWithCAPolicy.fetch_policy_by_name("Any Policy")

    # Corrected the expected error message for this specific scenario,
    # as fetch_policy_by_name has its own validation that triggers first.
    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.executeCommand", return_value="not a list")
    with pytest.raises(DemistoException, match="Failed to retrieve Conditional Access policies: Empty or invalid response."):
        BlockUserAppAccessWithCAPolicy.fetch_policy_by_name("Any Policy")


def test_fetch_policy_by_name_contents_is_list(mocker):
    """
    Given:
        - demisto.executeCommand returns 'Contents' directly as a list of policies
    When:
        - Calling fetch_policy_by_name
    Then:
        - Should return the matching policy
    """
    mocker.patch(
        "BlockUserAppAccessWithCAPolicy.demisto.executeCommand",
        return_value=[{"Contents": [{"displayName": "Direct List Policy"}]}],
    )
    mocker.patch("BlockUserAppAccessWithCAPolicy.is_error", return_value=False)

    result = BlockUserAppAccessWithCAPolicy.fetch_policy_by_name("Direct List Policy")
    assert result["displayName"] == "Direct List Policy"


def test_fetch_policy_by_name_unexpected_contents_structure(mocker):
    """
    Given:
        - demisto.executeCommand returns 'Contents' in an unexpected format (e.g., string)
    When:
        - Calling fetch_policy_by_name
    Then:
        - Should raise DemistoException
    """
    mocker.patch(
        "BlockUserAppAccessWithCAPolicy.demisto.executeCommand",
        return_value=[{"Contents": "unexpected_string"}],
    )
    mocker.patch("BlockUserAppAccessWithCAPolicy.is_error", return_value=False)

    with pytest.raises(DemistoException, match="Unexpected structure in Conditional Access policy response."):
        BlockUserAppAccessWithCAPolicy.fetch_policy_by_name("Any Policy")


# --- Tests for create_policy ---
def test_create_policy_success(mocker):
    """
    Given:
        - A valid app_id, user_id and policy_name
    When:
        - Calling create_policy
    Then:
        - Should return a success message
        - _execute_command_and_handle_error should be called with correct arguments
    """
    mock_execute = mocker.patch("BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error", return_value={})

    app_id = "app-123"
    user_id = "user-456"
    policy_name = "Test Policy"
    result = BlockUserAppAccessWithCAPolicy.create_policy(app_id, user_id, policy_name)

    assert result == f"Conditional Access policy '{policy_name}' created and applied to user."
    expected_policy_json_substring = f'"displayName": "{policy_name}"'
    mock_execute.assert_called_once()
    assert mock_execute.call_args[0][0] == "msgraph-identity-ca-policy-create"
    assert expected_policy_json_substring in mock_execute.call_args[0][1]["policy"]


# --- Tests for update_policy ---
def test_update_policy_success(mocker):
    """
    Given:
        - An existing policy without the user
    When:
        - Calling update_policy
    Then:
        - Should add the user to the policy and return a success message
    """
    mock_execute = mocker.patch("BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error", return_value={})
    policy = {
        "id": "policy-id-123",
        "displayName": "Existing Policy",
        "conditions": {"users": {"includeUsers": []}},  # Ensure it's empty to add a new user
    }
    user_id = "user-new"
    result = BlockUserAppAccessWithCAPolicy.update_policy(policy, user_id)

    assert result == f"User added to existing CA policy '{policy['displayName']}'."
    mock_execute.assert_called_once()
    assert mock_execute.call_args[0][0] == "msgraph-identity-ca-policy-update"
    assert mock_execute.call_args[0][1]["policy_id"] == "policy-id-123"
    updated_policy_data = json.loads(mock_execute.call_args[0][1]["policy"])
    assert "user-new" in updated_policy_data["conditions"]["users"]["includeUsers"]
    assert len(updated_policy_data["conditions"]["users"]["includeUsers"]) == 1  # Only one user now


def test_update_policy_user_already_blocked(mocker):
    """
    Given:
        - An existing policy that already includes the user
    When:
        - Calling update_policy
    Then:
        - Should return a message indicating no action was taken
        - No update command should be executed
    """
    mock_execute = mocker.patch("BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error", return_value={})
    policy = {
        "id": "policy-id-123",
        "displayName": "Existing Policy",
        "conditions": {"users": {"includeUsers": ["user-already-there"]}},
    }
    user_id = "user-already-there"
    result = BlockUserAppAccessWithCAPolicy.update_policy(policy, user_id)

    assert result == f"User is already blocked in policy '{policy['displayName']}'. No action taken."
    mock_execute.assert_not_called()


# --- Tests for main function ---
def test_main_existing_policy_updates(mocker):
    """
    Given:
        - main is called with valid arguments
        - An existing policy is found
    When:
        - main is executed
    Then:
        - update_policy should be called
        - return_results should be called with success message
    """
    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.args", return_value={"username": "testuser", "app_name": "TestApp"})
    mocker.patch("BlockUserAppAccessWithCAPolicy.resolve_user_object_id", return_value="user-id-123")
    # E501 fix: Breaking the dictionary across multiple lines
    mocker.patch(
        "BlockUserAppAccessWithCAPolicy.fetch_policy_by_name",
        return_value={
            "id": "policy-id",
            "displayName": "Cortex App Block Access - TestApp",
            "conditions": {"users": {"includeUsers": []}},
        },
    )
    mock_update_policy = mocker.patch("BlockUserAppAccessWithCAPolicy.update_policy", return_value="User updated message")
    mock_return_results = mocker.patch("BlockUserAppAccessWithCAPolicy.return_results")
    mocker.patch("BlockUserAppAccessWithCAPolicy.resolve_app_object_id")  # Mock, though not used in this branch

    BlockUserAppAccessWithCAPolicy.main()  # Call main from the module
    mock_update_policy.assert_called_once()
    mock_return_results.assert_called_once_with("User updated message")


def test_main_new_policy_created(mocker):
    """
    Given:
        - main is called with valid arguments
        - No existing policy is found
    When:
        - main is executed
    Then:
        - create_policy should be called
        - return_results should be called with success message
    """
    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.args", return_value={"username": "testuser", "app_name": "NewApp"})
    mocker.patch("BlockUserAppAccessWithCAPolicy.resolve_user_object_id", return_value="user-id-abc")
    mocker.patch("BlockUserAppAccessWithCAPolicy.fetch_policy_by_name", return_value=None)
    mock_resolve_app_id = mocker.patch("BlockUserAppAccessWithCAPolicy.resolve_app_object_id", return_value="app-id-xyz")
    mock_create_policy = mocker.patch("BlockUserAppAccessWithCAPolicy.create_policy", return_value="Policy created message")
    mock_return_results = mocker.patch("BlockUserAppAccessWithCAPolicy.return_results")

    BlockUserAppAccessWithCAPolicy.main()  # Call main from the module
    mock_resolve_app_id.assert_called_once()
    mock_create_policy.assert_called_once()
    mock_return_results.assert_called_once_with("Policy created message")


def test_main_user_id_resolution_failure(mocker):
    """
    Given:
        - main is called
        - resolve_user_object_id returns None
    When:
        - main is executed
    Then:
        - DemistoException should be raised and caught
        - return_error should be called
    """
    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.args", return_value={"username": "nonexistent_user"})
    mocker.patch("BlockUserAppAccessWithCAPolicy.resolve_user_object_id", return_value=None)
    mock_return_error = mocker.patch("BlockUserAppAccessWithCAPolicy.return_error")

    BlockUserAppAccessWithCAPolicy.main()  # Call main from the module
    mock_return_error.assert_called_once_with(
        "Error blocking app access: Could not resolve user ID from username: nonexistent_user"
    )


def test_main_general_exception_handling(mocker):
    """
    Given:
        - An unexpected exception occurs during main execution (e.g., in resolve_app_object_id)
    When:
        - main is executed
    Then:
        - The exception should be caught
        - return_error should be called with the exception message
    """
    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.args", return_value={"username": "testuser", "app_name": "TestApp"})
    mocker.patch("BlockUserAppAccessWithCAPolicy.resolve_user_object_id", return_value="user-id-123")
    mocker.patch(
        "BlockUserAppAccessWithCAPolicy.fetch_policy_by_name", side_effect=ValueError("Simulated error")
    )  # Force an exception
    mock_return_error = mocker.patch("BlockUserAppAccessWithCAPolicy.return_error")

    BlockUserAppAccessWithCAPolicy.main()  # Call main from the module
    mock_return_error.assert_called_once_with("Error blocking app access: Simulated error")
