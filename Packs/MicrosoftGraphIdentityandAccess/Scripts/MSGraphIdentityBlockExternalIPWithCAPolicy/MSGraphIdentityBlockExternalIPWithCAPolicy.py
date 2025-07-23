import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import json
import ipaddress
import time
from typing import Any


# --- Constants ---
GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"  # Azure Global Administrator role ID
DEFAULT_NAMED_LOCATION_NAME = "Cortex Blocked IPs"
DEFAULT_POLICY_NAME = "Cortex - Block Malicious IPs"

# --- Helper Functions ---


def is_private_ip(ip: str) -> bool:
    """
    Checks if the given IP address is a private (RFC 1918) IP address.

    Args:
        ip (str): The IP address string to check.

    Returns:
        bool: True if the IP is private, False otherwise or if the IP is invalid.
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        demisto.debug(f"Invalid IP address format encountered: {ip}")
        return False


def get_azure_command_error_details(res: dict[str, Any]) -> str:
    """
    Extracts a readable error message from an Azure command result.
    This function attempts to parse the 'Contents' field of a command result for
    structured JSON error information (e.g., from MS Graph API calls).
    If no
    structured error is found, it falls back to the raw contents or a generic message.
    Args:
        res (dict[str, Any]): The result object from a command, typically res[0] from executeCommand.
    Returns:
        str: A human-readable string containing the error code and message, or the raw error string.
    """
    raw_contents = res.get("Contents")
    try:
        if isinstance(raw_contents, str):
            if "Error in API call" in raw_contents:
                try:
                    json_start_index = raw_contents.index("{", raw_contents.index("Error in API call"))
                    error_json = json.loads(raw_contents[json_start_index:])
                    return (
                        f"{error_json.get('error', {}).get('code', 'Error')}: "
                        f"{error_json.get('error', {}).get('message', 'No message')}"
                    )
                except (json.JSONDecodeError, ValueError):
                    demisto.debug(f"Failed to parse detailed JSON from API error string: {raw_contents}")
                    return f"Unparsed API error: {raw_contents}"
            try:
                parsed_contents = json.loads(raw_contents)
                if isinstance(parsed_contents, dict) and "error" in parsed_contents:
                    error = parsed_contents["error"]
                    return f"{error.get('code', 'Error')}: {error.get('message', 'No message')}"
            except json.JSONDecodeError:
                pass
        if isinstance(raw_contents, dict) and "error" in raw_contents:
            error = raw_contents["error"]
            return f"{error.get('code', 'Error')}: {error.get('message', 'No message')}"

        return str(raw_contents or res.get("ReadableContents", "Unknown error"))
    except Exception as ex:
        demisto.debug(f"Exception during error details extraction: {ex}")
        return f"Error extracting error message: {str(ex)}"


def _execute_command_and_handle_error(command: str, args: dict[str, Any], error_message_prefix: str) -> dict[str, Any]:
    """
    Executes a command and raises a DemistoException if it fails.
    This function abstracts the common pattern of executing a command and
    checking its result for errors, providing a consistent error handling mechanism.
    Args:
        command (str): The name of the command to execute (e.g., 'msgraph-identity-ip-named-locations-list').
        args (dict[str, Any]): A dictionary of arguments to pass to the command.
        error_message_prefix (str): A string prefix to prepend to any DemistoException messages,
                                    indicating the context of the error.
    Returns:
        dict[str, Any]: The parsed 'Contents' dictionary from the command's successful result.
    Raises:
        DemistoException: If the command execution fails, returns an empty/invalid response structure,
                          or indicates an error via `is_error(res)`.
    """
    res = demisto.executeCommand(command, args)
    if not res or not isinstance(res, list) or not res[0]:
        raise DemistoException(f"{error_message_prefix}: Empty or invalid command result for {command}.")
    if is_error(res):
        error_details = get_azure_command_error_details(res[0])
        raise DemistoException(f"{error_message_prefix}: {error_details}")
    demisto.debug(f"Successfully executed {command}. Result: {res[0].get('Contents')}")
    return res[0].get("Contents", {})


def get_named_ip_location(named_location_name: str) -> dict[str, Any] | None:
    """
    Retrieves an existing Azure AD named IP location based on its display name.

    Args:
        named_location_name (str): The display name of the named IP location to search for.
    Returns:
        dict[str, Any] | None: A dictionary representing the found named IP location if it exists,
                               otherwise None.
    Raises:
        DemistoException: If listing named IP locations fails.
    """
    filter_query = f"$filter=displayName eq '{named_location_name}'"
    contents = _execute_command_and_handle_error(
        "msgraph-identity-ip-named-locations-list", {"odata_query": filter_query}, "Failed to list named IP locations"
    )
    if isinstance(contents, dict) and "value" in contents:
        existing_locations = contents.get("value", [])
    elif isinstance(contents, list):
        existing_locations = contents
    else:
        existing_locations = []
    return existing_locations[0] if existing_locations else None


def update_existing_named_location(
    named_location_id: str, named_location_name: str, existing_cidrs: list[str], new_ip_cidr: str
) -> str:
    """
    Adds a new IP CIDR (Classless Inter-Domain Routing) to an existing Azure AD named IP location.
    The function checks if the new IP CIDR is already present in the existing list to avoid duplicates.
    It then updates the named location in Azure AD.

    Args:
        named_location_id (str): The unique ID of the existing named IP location to update.
        named_location_name (str): The display name of the named IP location.
        existing_cidrs (list[str]): A list of existing CIDR strings already configured in the named location.
        new_ip_cidr (str): The new IP CIDR string (e.g., "1.2.3.4/32") to add.
    Returns:
        str: A message indicating what action was taken (updated or no update needed).

    Raises:
        DemistoException: If the update operation to Azure AD fails.
    """
    if new_ip_cidr not in existing_cidrs:
        existing_cidrs.append(new_ip_cidr)
        update_args = {
            "ip_id": named_location_id,
            "display_name": named_location_name,
            "ips": ",".join(existing_cidrs),
            "is_trusted": False,
        }
        _execute_command_and_handle_error(
            "msgraph-identity-ip-named-locations-update", update_args, "Failed to update named location"
        )
        demisto.debug(f"Added {new_ip_cidr} to existing named location '{named_location_name}'.")
        return f"IP {new_ip_cidr.split('/')[0]} was successfully added to the existing named location '{named_location_name}'."
    else:
        demisto.debug(f"IP {new_ip_cidr} already exists in named location '{named_location_name}'. No update needed.")
        return (
            f"IP {new_ip_cidr.split('/')[0]} is already covered by the named location '{named_location_name}'. No action "
            f"was needed."
        )


def create_new_named_ip_location(named_location_name: str, ip: str) -> str:
    """
    Creates a new Azure AD named IP location with the specified IP address.
    After creation, the script waits for a short period to allow Azure to propagate the new location,
    which is recommended before associating it with Conditional Access policies.
    Args:
        named_location_name (str): The desired display name for the new named IP location.
        ip (str): The IP address (e.g., "1.2.3.4") to be included in the new named location as a /32 CIDR.
    Returns:
        str: The unique ID of the newly created named IP location.
    Raises:
        DemistoException: If the creation of the named location fails or does not return a valid ID.
    """
    create_args = {"display_name": named_location_name, "ips": f"{ip}/32", "is_trusted": False}
    contents = _execute_command_and_handle_error(
        "msgraph-identity-ip-named-locations-create", create_args, "Failed to create named location"
    )
    named_location_id = contents.get("id")
    if not named_location_id:
        raise DemistoException("Named location creation did not return a valid ID.")
    demisto.debug(f"Created new named location '{named_location_name}' with ID '{named_location_id}'.")
    return named_location_id


def create_conditional_access_policy(policy_name: str, named_location_id: str) -> None:
    """
    Creates a new Azure AD Conditional Access policy to block access from a specified named location.
    The policy is configured to apply to all users (excluding Global Administrators) and all applications,
    blocking access when originating from the specified named location.
    Args:
        policy_name (str): The desired display name for the new Conditional Access policy.
        named_location_id (str): The unique ID of the named IP location that this policy will block.
    Returns:
        None

    Raises:
        DemistoException: If the creation of the Conditional Access policy fails.
    """
    policy_json = {
        "displayName": policy_name,
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"], "excludeRoles": [GLOBAL_ADMIN_ROLE_ID]},
            "applications": {"includeApplications": ["All"]},
            "clientAppTypes": ["all"],
            "locations": {"includeLocations": [named_location_id]},
        },
        "grantControls": {"operator": "OR", "builtInControls": ["block"]},
        "sessionControls": {
            "applicationEnforcedRestrictions": None,
            "cloudAppSecurity": None,
            "persistentBrowser": None,
            "signInFrequency": None,
            "disableResilienceDefaults": False,
        },
    }
    demisto.debug(f"Attempting to create CA policy with JSON: {json.dumps(policy_json, indent=2)}")
    _execute_command_and_handle_error(
        "msgraph-identity-ca-policy-create", {"policy": json.dumps(policy_json)}, "Failed to create CA policy"
    )
    demisto.debug(f"Successfully created Conditional Access policy '{policy_name}'.")


def block_external_ip_with_ca_policy_main_logic(ip: str, named_location_name: str, policy_name: str) -> str:
    """
    Orchestrates the blocking of an external IP address using Azure Conditional Access policies.
    This function checks if the IP is private, retrieves or updates a named IP location in Azure AD,
    and then either updates an existing Conditional Access policy or creates a new one to block
    access from the specified IP.
    Args:
        ip (str): The external IP address to block.
        named_location_name (str): The name of the Azure AD named IP location to use/create.
        policy_name (str): The name of the Conditional Access policy to use/create.
    Returns:
        str: A message indicating the successful processing and blocking status of the IP.
    Raises:
        DemistoException: If the input IP is missing, private, or if any Azure AD operation fails.
    """
    result_message = ""
    if not ip:
        raise DemistoException("Missing required argument: 'ip'.")
    if is_private_ip(ip):
        raise DemistoException(f"The IP {ip} appears to be internal/private and will not be blocked.")
    named_location = get_named_ip_location(named_location_name)
    named_location_id: str | None = None
    if named_location:
        named_location_id = named_location.get("id")
        ip_ranges = named_location.get("ipRanges", [])
        cidrs = [r.get("cidrAddress") for r in ip_ranges if r.get("cidrAddress")]
        if named_location_id:
            result_message = update_existing_named_location(named_location_id, named_location_name, cidrs, f"{ip}/32")
    else:
        named_location_id = create_new_named_ip_location(named_location_name, ip)
        # Wait for Azure to propagate the named location (recommended for CA policies)
        time.sleep(30) # pylint: disable=sleep-exists
        create_conditional_access_policy(policy_name, named_location_id)
        result_message = (
            f"A new named location '{named_location_name}' was created for IP {ip} and "
            f"a new Conditional Access policy '{policy_name}' was created to block access from this IP."
        )
    return result_message


def main():
    """
    Main function for the script to block an external IP address using Azure Conditional Access.
    This is the entry point that retrieves arguments, orchestrates the blocking logic,
    and handles top-level exceptions, returning results or errors.
    """
    try:
        args = demisto.args()
        ip = args.get("ip")
        named_location_name = args.get("named_location_name", DEFAULT_NAMED_LOCATION_NAME)
        policy_name = args.get("policy_name", DEFAULT_POLICY_NAME)
        result_message = block_external_ip_with_ca_policy_main_logic(ip, named_location_name, policy_name)
        return_results(
            CommandResults(
                readable_output=result_message,
                outputs_prefix="MSGraphIdentityBlockExternalIPWithCAPolicy",
                outputs={"IP": ip, "Status": "Blocked", "NamedLocation": named_location_name},
            )
        )
    except Exception as e:
        return_error(f"Error executing script: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
