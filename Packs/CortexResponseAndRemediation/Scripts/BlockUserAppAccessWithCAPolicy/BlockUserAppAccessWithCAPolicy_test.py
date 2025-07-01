import pytest
from CommonServerPython import DemistoException

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
    from BlockUserAppAccessWithCAPolicy import get_policy_name

    assert get_policy_name("MyApp", "Custom Policy Name") == "Custom Policy Name"


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
    from BlockUserAppAccessWithCAPolicy import get_policy_name

    assert get_policy_name("MyApp", None) == "Cortex App Block Access - MyApp"


def test_resolve_user_object_id_when_guid():
    """
    Given:
        - A user identifier in GUID format
    When:
        - Calling resolve_user_object_id
    Then:
        - Should return the GUID as-is
    """
    from BlockUserAppAccessWithCAPolicy import resolve_user_object_id

    guid = "12345678-abcd-1234-abcd-1234567890ab"
    assert resolve_user_object_id(guid) == guid


def test_resolve_user_object_id_when_upn(mocker):
    """
    Given:
        - A user identifier in UPN format
    When:
        - Calling resolve_user_object_id
    Then:
        - Should resolve to the user's object ID via command execution
    """
    from BlockUserAppAccessWithCAPolicy import resolve_user_object_id

    mocker.patch("BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error", return_value={"id": "user-object-id-1234"})
    assert resolve_user_object_id("user@example.com") == "user-object-id-1234"


def test_get_error_parsing_json_error():
    """
    Given:
        - Command result with embedded API error JSON string
    When:
        - Calling _parse_demisto_error_message (formerly get_error)
    Then:
        - Should parse and extract a formatted error code and message
    """
    # Changed import to the new function name
    from BlockUserAppAccessWithCAPolicy import _parse_demisto_error_message

    res = {"Contents": 'Error in API call [403] - { "error": { "code": "Forbidden", "message": "Not allowed" } }'}
    assert _parse_demisto_error_message(res) == "Forbidden: Not allowed"


def test_get_error_unparsed_string():
    """
    Given:
        - Command result with a string error message not containing JSON
    When:
        - Calling _parse_demisto_error_message (formerly get_error)
    Then:
        - Should return the raw string as-is
    """
    # Changed import to the new function name
    from BlockUserAppAccessWithCAPolicy import _parse_demisto_error_message

    res = {"Contents": "Some simple error occurred"}
    assert _parse_demisto_error_message(res) == "Some simple error occurred"


def test_execute_command_and_handle_error_success(mocker):
    """
    Given:
        - A successful demisto.executeCommand call
    When:
        - Calling _execute_command_and_handle_error
    Then:
        - Should return the 'Contents' of the result
    """
    from BlockUserAppAccessWithCAPolicy import _execute_command_and_handle_error

    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.executeCommand", return_value=[{"Contents": {"key": "value"}}])
    mocker.patch("BlockUserAppAccessWithCAPolicy.is_error", return_value=False)

    result = _execute_command_and_handle_error("command", {}, "Error Prefix")
    assert result == {"key": "value"}


def test_execute_command_and_handle_error_failure(mocker):
    """
    Given:
        - A failed demisto.executeCommand call
    When:
        - Calling _execute_command_and_handle_error
    Then:
        - Should raise DemistoException with the appropriate message
    """
    from BlockUserAppAccessWithCAPolicy import _execute_command_and_handle_error

    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.executeCommand", return_value=[{"Contents": "Error"}])
    mocker.patch("BlockUserAppAccessWithCAPolicy.is_error", return_value=True)
    # Mock the new error parsing function
    mocker.patch("BlockUserAppAccessWithCAPolicy._parse_demisto_error_message", return_value="bad error")

    with pytest.raises(DemistoException, match="Error Prefix: bad error"):
        _execute_command_and_handle_error("command", {}, "Error Prefix")


def test_resolve_app_object_id_valid_response_dict(mocker):
    """
    Given:
        - App name that matches one entry in the service principal list
    When:
        - Calling resolve_app_object_id
    Then:
        - Should return the appId of the matching app
    """
    from BlockUserAppAccessWithCAPolicy import resolve_app_object_id

    mocker.patch(
        "BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error",
        return_value={"MSGraphApplication": [{"displayName": "MyApp", "appId": "app-id-123"}]},
    )
    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.info")

    result = resolve_app_object_id("MyApp")
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
    from BlockUserAppAccessWithCAPolicy import resolve_app_object_id

    mocker.patch(
        "BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error",
        return_value={"MSGraphApplication": [{"displayName": "OtherApp"}]},
    )
    mocker.patch("BlockUserAppAccessWithCAPolicy.demisto.info")

    with pytest.raises(DemistoException, match="Application 'MyApp' not found"):
        resolve_app_object_id("MyApp")


def test_fetch_policy_by_name_found(mocker):
    """
    Given:
        - A CA policy with matching displayName exists
    When:
        - Calling fetch_policy_by_name
    Then:
        - Should return the policy dict
    """
    from BlockUserAppAccessWithCAPolicy import fetch_policy_by_name

    mocker.patch(
        "BlockUserAppAccessWithCAPolicy.demisto.executeCommand",
        return_value=[{"Contents": {"value": [{"displayName": "My Policy"}]}}],
    )
    mocker.patch("BlockUserAppAccessWithCAPolicy.is_error", return_value=False)

    result = fetch_policy_by_name("My Policy")
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
    from BlockUserAppAccessWithCAPolicy import fetch_policy_by_name

    mocker.patch(
        "BlockUserAppAccessWithCAPolicy.demisto.executeCommand",
        return_value=[{"Contents": {"value": [{"displayName": "Other Policy"}]}}],
    )
    mocker.patch("BlockUserAppAccessWithCAPolicy.is_error", return_value=False)

    assert fetch_policy_by_name("Nonexistent Policy") is None


def test_create_policy_success(mocker):
    """
    Given:
        - A valid app_id, user_id and policy_name
    When:
        - Calling create_policy
    Then:
        - Should return a success message
    """
    from BlockUserAppAccessWithCAPolicy import create_policy

    mocker.patch("BlockUserAppAccessWithCAPolicy._execute_command_and_handle_error", return_value={})

    result = create_policy("app-123", "user-456", "Test Policy")
    assert result == "Conditional Access policy 'Test Policy' created and applied to user."
