import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import re
from typing import Any

DEFAULT_POLICY_NAME_PREFIX = "Cortex App Block Access"


def _execute_command_and_handle_error(command: str, args: dict[str, Any], error_message_prefix: str) -> dict[str, Any]:
    """
    Executes a command and raises a DemistoException if it fails.

    Args:
        command (str): The command to execute.
        args (dict[str, Any]): Arguments for the command.
        error_message_prefix (str): Message prefix for errors.

    Returns:
        dict[str, Any]: Parsed contents of the command result.
    """
    res = demisto.executeCommand(command, args)
    if not res:
        raise DemistoException(f"{error_message_prefix}: Empty response for {command}.")
    if not isinstance(res, list) or not res:  # res is now guaranteed not None, check if it's an empty list or not a list
        raise DemistoException(f"{error_message_prefix}: Invalid command result structure (not a list) for {command}.")
    # Fix for previous error: Explicitly check for None, not just falsy.
    if res[0] is None:  # Check if the first element of the list is explicitly None
        raise DemistoException(f"{error_message_prefix}: Empty first element in command result for {command}.")

    # Now res is guaranteed to be a non-empty list, and res[0] is not None.
    if is_error(res):
        # Using the renamed internal error parsing function
        raise DemistoException(f"{error_message_prefix}: {_parse_error_message(res[0])}")

    # Ensure res[0] is a dict before calling .get()
    if not isinstance(res[0], dict):
        raise DemistoException(
            f"{error_message_prefix}: Unexpected type for command result contents: Expected dict, got {type(res[0]).__name__}."
        )

    return res[0].get("Contents", {})


def resolve_app_object_id(app_name: str) -> str:
    """
    Resolves the client ID (appId) of an Azure AD application based on its display name.

    Args:
        app_name (str): The display name of the application to look up.

    Returns:
        str: The client ID (appId) of the matching application.

    Raises:
        DemistoException: If the application is not found or if the response structure is invalid.
    """

    demisto.info(f"[DEBUG] Fetching app ID for: {app_name}")
    res = _execute_command_and_handle_error(
        "msgraph-apps-service-principal-list", {"limit": 0}, "Failed to list service principals"
    )

    demisto.info(f"[DEBUG] Service principal list response: {json.dumps(res, indent=2)[:1000]}")

    apps: list[Any] = []
    if isinstance(res, dict):
        apps = res.get("MSGraphApplication", [])
    elif isinstance(res, list):
        apps = res
    else:
        demisto.info(f"[DEBUG] Unexpected service principal list structure: {res}")
        raise DemistoException("Unexpected format in service principal list response.")

    matching_apps = [a for a in apps if a.get("displayName") == app_name]
    if not matching_apps:
        available_names = [a.get("displayName") for a in apps]
        raise DemistoException(f"Application '{app_name}' not found. Available apps: {available_names}")

    app_id = matching_apps[0].get("appId")
    if not app_id:  # Ensure appId is not None as function returns str
        raise DemistoException(f"Application '{app_name}' found, but its 'appId' is missing.")
    return app_id


def _parse_error_message(res: dict[str, Any]) -> str:
    """
    Parses an error message from a command result.
    This function handles specific formatting of errors returned by certain commands.

    Args:
        res (dict[str, Any]): Result from a command.

    Returns:
        str: Human-readable error message.
    """
    raw_contents = res.get("Contents")
    try:
        if isinstance(raw_contents, str):
            # Case 1: "Error in API call" followed by JSON
            if "Error in API call" in raw_contents:
                try:
                    json_start_index = raw_contents.index("{", raw_contents.index("Error in API call"))
                    err = json.loads(raw_contents[json_start_index:])
                    return f"{err.get('error', {}).get('code', '')}: {err.get('error', {}).get('message', '')}"
                except (json.JSONDecodeError, ValueError):  # ValueError for .index() if substring not found
                    demisto.debug(f"Failed to parse detailed JSON from API error string: {raw_contents}")
                    return f"Unparsed API error: {raw_contents}"
            # Case 2: Raw string that is a JSON error object
            try:
                parsed_contents = json.loads(raw_contents)
                if isinstance(parsed_contents, dict) and "error" in parsed_contents:
                    error = parsed_contents["error"]
                    return f"{error.get('code', 'Error')}: {error.get('message', 'No message')}"
            except json.JSONDecodeError:
                pass  # Not a JSON string, fall through to raw_contents or ReadableContents
            return raw_contents  # If it's a plain string, return as is

        # Case 3: Contents is already a dict with an 'error' key
        elif isinstance(raw_contents, dict) and "error" in raw_contents:
            error = raw_contents["error"]
            return f"{error.get('code', 'Error')}: {error.get('message', 'No message')}"

        # Fallback for other cases (e.g., None, non-error dict, or if nothing else matched)
        # Use ReadableContents if Contents is empty or None
        return str(raw_contents or res.get("ReadableContents", "Unknown error"))
    except Exception as ex:
        # Catch any unexpected exceptions during the parsing process itself
        demisto.debug(f"Exception during error details extraction in _parse_error_message: {ex}")
        return f"Error extracting error message: {str(ex)}"


def resolve_user_object_id(identifier: str) -> str | None:
    """
    Resolves a UPN or GUID to a user object ID in Azure AD.

    Args:
        identifier (str): A UPN or user object ID.

    Returns:
        str | None: Resolved Azure AD object ID, or None if not found/resolved.
    """
    guid_pattern = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$", re.I)
    if guid_pattern.match(identifier):
        return identifier

    user = _execute_command_and_handle_error("msgraph-user-get", {"user": identifier}, "Failed to resolve UPN to object ID")
    return user.get("id")


def get_policy_name(app_name: str, policy_name: str | None) -> str:
    """
    Returns the full policy name. Uses default format if policy_name is not provided.

    Args:
        app_name (str): Application name.
        policy_name (str | None): Provided policy name or None.

    Returns:
        str: Final policy name.
    """
    return policy_name or f"{DEFAULT_POLICY_NAME_PREFIX} - {app_name}"


def fetch_policy_by_name(policy_name: str) -> dict[str, Any] | None:
    """
    Retrieves an existing Conditional Access policy by display name.

    Args:
        policy_name (str): Policy display name to search for.

    Returns:
        dict[str, Any] | None: Matching policy object if found, else None.
    """
    res = demisto.executeCommand("msgraph-identity-ca-policies-list", {})
    if not res or not isinstance(res, list) or not res[0]:
        raise DemistoException("Failed to retrieve Conditional Access policies: Empty or invalid response.")

    if is_error(res):
        # Using the renamed internal error parsing function
        raise DemistoException(f"Failed to list CA policies: {_parse_error_message(res[0])}")

    contents = res[0].get("Contents", {})
    if isinstance(contents, list):
        policies = contents
    elif isinstance(contents, dict):
        policies = contents.get("value", [])
    else:
        raise DemistoException("Unexpected structure in Conditional Access policy response.")

    for policy in policies:
        if policy.get("displayName") == policy_name:
            return policy
    return None


def create_policy(app_id: str, user_id: str, policy_name: str) -> str:
    """
    Creates a new Conditional Access policy that blocks a user from an app.

    Args:
        app_id (str): App ID to block access to.
        user_id (str): Azure AD object ID of the user.
        policy_name (str): Display name for the new policy.

    Returns:
        str: Result message.
    """
    policy = {
        "displayName": policy_name,
        "state": "enabled",
        "conditions": {"users": {"includeUsers": [user_id]}, "applications": {"includeApplications": [app_id]}},
        "grantControls": {"operator": "OR", "builtInControls": ["block"]},
    }
    _execute_command_and_handle_error(
        "msgraph-identity-ca-policy-create", {"policy": json.dumps(policy)}, "Failed to create CA policy"
    )
    return f"Conditional Access policy '{policy_name}' created and applied to user."


def update_policy(policy: dict[str, Any], user_id: str) -> str:
    """
    Updates an existing Conditional Access policy to include the specified user.

    Args:
        policy (dict[str, Any]): Existing CA policy.
        user_id (str): Azure AD object ID of the user to add.

    Returns:
        str: Result message.
    """
    existing_users = policy.get("conditions", {}).get("users", {}).get("includeUsers", [])
    if user_id in existing_users:
        return f"User is already blocked in policy '{policy.get('displayName')}'. No action taken."

    # Using list() for safety, though set() conversion prevents duplicates effectively
    updated_users = list(set(existing_users + [user_id]))  # prevent duplicates
    policy_id = policy.get("id")

    patch_payload = {"conditions": {"users": {"includeUsers": updated_users}}}

    _execute_command_and_handle_error(
        "msgraph-identity-ca-policy-update",
        {"policy_id": policy_id, "policy": json.dumps(patch_payload)},
        "Failed to update CA policy",
    )

    return f"User added to existing CA policy '{policy.get('displayName')}'."


def main():
    """
    Main function for blocking a user's access to an Azure application
    using Conditional Access policies in Microsoft Graph.
    """
    try:
        args = demisto.args()
        username = args["username"]
        app_name = args.get("app_name", "UnknownApp")
        policy_name = get_policy_name(app_name, args.get("policy_name"))

        user_id = resolve_user_object_id(username)
        if not user_id:
            raise DemistoException(f"Could not resolve user ID from username: {username}")

        existing_policy = fetch_policy_by_name(policy_name)

        if existing_policy:
            message = update_policy(existing_policy, user_id)
        else:
            app_id = resolve_app_object_id(app_name)
            message = create_policy(app_id, user_id, policy_name)

        return_results(message)

    except Exception as e:
        return_error(f"Error blocking app access: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
