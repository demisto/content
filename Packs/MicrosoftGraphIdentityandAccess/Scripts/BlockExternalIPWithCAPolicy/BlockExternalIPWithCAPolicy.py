import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json
import ipaddress
import time
from typing import Dict, Any, List, Union, Tuple


# --- Constants ---
GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"  # Azure Global Administrator role ID
DEFAULT_NAMED_LOCATION_NAME = "Cortex Blocked IPs"
DEFAULT_POLICY_NAME = "Cortex - Block Malicious IPs"


# --- Helper Functions ---

def is_private_ip(ip: str) -> bool:
    """
    Checks if the given IP address is a private IP address.

    Args:
        ip (str): The IP address to check.

    Returns:
        bool: True if the IP is private, False otherwise.
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        demisto.debug(f"Invalid IP address format encountered: {ip}")
        return False

def get_azure_command_error_details(res: Dict[str, Any]) -> str:
    """
    Extracts a readable error message from an Azure command result.
    This function specifically parses the 'Contents' field for error details.

    Args:
        res (Dict[str, Any]): The result dictionary from a demisto.executeCommand call.

    Returns:
        str: A formatted error message.
    """
    raw_contents = res.get("Contents")
    try:
        if isinstance(raw_contents, str):
            # Prioritize parsing structured error messages like "Error in API call: {JSON}"
            if "Error in API call" in raw_contents:
                try:
                    json_start_index = raw_contents.index("{", raw_contents.index("Error in API call"))
                    error_json = json.loads(raw_contents[json_start_index:])
                    return f"{error_json.get('error', {}).get('code', 'Error')}: {error_json.get('error', {}).get('message', 'No message')}"
                except (json.JSONDecodeError, ValueError) as e:
                    demisto.debug(f"Failed to parse detailed JSON from API error string: {raw_contents}")
                    return f"Unparsed API error: {raw_contents}"

            # Check if the entire string content is a parsable JSON dict with an 'error' key
            try:
                parsed_contents = json.loads(raw_contents)
                if isinstance(parsed_contents, dict) and 'error' in parsed_contents:
                    error = parsed_contents['error']
                    return f"{error.get('code', 'Error')}: {error.get('message', 'No message')}"
            except json.JSONDecodeError:
                pass # Not a full JSON string, proceed to simple string handling

            # If not a structured error, return the simple string content
            return raw_contents
        elif isinstance(raw_contents, dict) and "error" in raw_contents:
            # Direct dictionary with 'error' key
            error = raw_contents["error"]
            return f"{error.get('code', 'Error')}: {error.get('message', 'No message')}"

        # Fallback for other cases (e.g., Contents is None, empty dict, or unexpected type)
        return str(raw_contents or res.get("ReadableContents", "Unknown error"))
    except Exception as ex:
        # Catch any unexpected errors during the error extraction process itself
        demisto.debug(f"Exception during error details extraction: {ex}")
        return f"Error extracting error message: {str(ex)}"


def _execute_command_and_handle_error(command: str, args: Dict[str, Any], error_message_prefix: str) -> Dict[str, Any]:
    """
    Executes a Demisto command and checks for errors.
    If an error (Type 4) occurs, it calls return_error with a formatted message.

    Args:
        command (str): The command name to execute.
        args (Dict[str, Any]): Arguments for the command.
        error_message_prefix (str): A prefix for the error message if the command fails.

    Returns:
        Dict[str, Any]: The 'Contents' of the command result if successful.

    Raises:
        DemistoException: If the command returns an error (Type 4) or an invalid/empty result.
    """
    res = demisto.executeCommand(command, args)

    if not res or not isinstance(res, list) or not res[0]:
        # DemistoException (from CommonServerPython) is assumed to be global
        raise DemistoException(f"{error_message_prefix}: Empty or invalid command result for {command}.")

    # is_error (from CommonServerPython) is assumed to be global
    if is_error(res):
        error_details = get_azure_command_error_details(res[0])
        # DemistoException (from CommonServerPython) is assumed to be global
        raise DemistoException(f"{error_message_prefix}: {error_details}")

    demisto.debug(f"Successfully executed {command}. Result: {res[0].get('Contents')}")
    return res[0].get('Contents', {})


def get_named_ip_location(named_location_name: str) -> Union[Dict[str, Any], None]:
    """
    Retrieves an existing named IP location by display name.

    Args:
        named_location_name (str): The display name of the named IP location.

    Returns:
        Union[Dict[str, Any], None]: The named location dictionary if found, otherwise None.
    """
    filter_query = f"$filter=displayName eq '{named_location_name}'"
    contents = _execute_command_and_handle_error(
        'msgraph-identity-ip-named-locations-list',
        {'odata_query': filter_query},
        "Failed to list named IP locations"
    )

    if isinstance(contents, dict) and 'value' in contents:
        existing_locations = contents.get('value', [])
    elif isinstance(contents, list): # Handle cases where 'Contents' is directly a list of locations
        existing_locations = contents
    else:
        existing_locations = []

    return existing_locations[0] if existing_locations else None

def update_existing_named_location(named_location_id: str, named_location_name: str, existing_cidrs: List[str], new_ip_cidr: str) -> None:
    """
    Adds a new IP CIDR to an existing named IP location if not already present.

    Args:
        named_location_id (str): The ID of the named IP location.
        named_location_name (str): The display name of the named IP location.
        existing_cidrs (List[str]): List of existing CIDR addresses in the location.
        new_ip_cidr (str): The new IP address in CIDR format (e.g., "1.1.1.1/32").
    """
    if new_ip_cidr not in existing_cidrs:
        existing_cidrs.append(new_ip_cidr)
        update_args = {
            "ip_id": named_location_id,
            "display_name": named_location_name,
            "ips": ",".join(existing_cidrs),
            "is_trusted": False
        }
        _execute_command_and_handle_error(
            'msgraph-identity-ip-named-locations-update',
            update_args,
            "Failed to update named location"
        )
        demisto.debug(f"Added {new_ip_cidr} to existing named location '{named_location_name}'.")
    else:
        demisto.debug(f"IP {new_ip_cidr} already exists in named location '{named_location_name}'. No update needed.")

def create_new_named_ip_location(named_location_name: str, ip: str) -> str:
    """
    Creates a new named IP location and returns its ID.

    Args:
        named_location_name (str): The display name for the new named IP location.
        ip (str): The initial IP address to add to the new location.

    Returns:
        str: The ID of the newly created named IP location.

    Raises:
        DemistoException: If named location creation fails or doesn't return a valid ID.
    """
    create_args = {
        "display_name": named_location_name,
        "ips": f"{ip}/32",
        "is_trusted": False
    }
    contents = _execute_command_and_handle_error(
        'msgraph-identity-ip-named-locations-create',
        create_args,
        "Failed to create named location"
    )

    named_location_id = contents.get('id')
    if not named_location_id:
        raise DemistoException("Named location creation did not return a valid ID.")

    demisto.debug(f"Created new named location '{named_location_name}' with ID '{named_location_id}'.")
    time.sleep(30)  # Wait for Azure to propagate the named location (recommended for CA policies)
    return named_location_id

def create_conditional_access_policy(policy_name: str, named_location_id: str) -> None:
    """
    Creates a Conditional Access policy to block access from the specified named location.

    Args:
        policy_name (str): The display name for the new Conditional Access policy.
        named_location_id (str): The ID of the named IP location to block.

    Raises:
        DemistoException: If the CA policy creation fails.
    """
    policy_json = {
        "displayName": policy_name,
        "state": "enabled",
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeRoles": [GLOBAL_ADMIN_ROLE_ID] # Exclude Global Administrators
            },
            "applications": {
                "includeApplications": ["All"]
            },
            "clientAppTypes": ["all"],
            "locations": {
                "includeLocations": [named_location_id]
            }
            # Other conditions intentionally omitted if not explicitly required by policy
            # signInRiskLevels, userRiskLevels, platforms, deviceStates, devices, etc.
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["block"]
            # customAuthenticationFactors, termsOfUse, authenticationStrength
        },
        "sessionControls": {
            "applicationEnforcedRestrictions": None,
            "cloudAppSecurity": None,
            "persistentBrowser": None,
            "signInFrequency": None,
            "disableResilienceDefaults": False
        }
    }

    demisto.debug(f"Attempting to create CA policy with JSON: {json.dumps(policy_json, indent=2)}")
    _execute_command_and_handle_error(
        'msgraph-identity-ca-policy-create',
        {'policy': json.dumps(policy_json)},
        "Failed to create CA policy"
    )
    demisto.debug(f"Successfully created Conditional Access policy '{policy_name}'.")


def block_external_ip_with_ca_policy_main_logic(ip: str, named_location_name: str, policy_name: str) -> str:
    """
    Orchestrates the blocking of an external IP address via Azure Conditional Access.

    Args:
        ip (str): The external IP address to block.
        named_location_name (str): The name of the Azure named IP location to use or create.
        policy_name (str): The name of the Conditional Access policy to create.

    Returns:
        str: A message indicating the outcome of the operation.

    Raises:
        DemistoException: If any required argument is missing or if the IP is private/internal.
    """
    if not ip:
        raise DemistoException("Missing required argument: 'ip'.")
    if is_private_ip(ip):
        raise DemistoException(f"The IP {ip} appears to be internal/private and will not be blocked.")

    named_location = get_named_ip_location(named_location_name)
    named_location_id = None

    if named_location:
        named_location_id = named_location.get('id')
        ip_ranges = named_location.get('ipRanges', [])
        cidrs = [r.get('cidrAddress') for r in ip_ranges if r.get('cidrAddress')]
        update_existing_named_location(named_location_id, named_location_name, cidrs, f"{ip}/32")
    else:
        # Create a new named location
        named_location_id = create_new_named_ip_location(named_location_name, ip)
        # Only create CA policy if a new named location was created
        create_conditional_access_policy(policy_name, named_location_id)

    return f"IP {ip} has been processed and blocked if necessary."


def main():
    """
    This function is the entry point for the XSOAR script.
    It retrieves arguments, calls the main logic, and handles exceptions.
    """
    try:
        # Get arguments from Demisto
        args = demisto.args()
        ip = args.get('ip')
        named_location_name = args.get('named_location_name', DEFAULT_NAMED_LOCATION_NAME)
        policy_name = args.get('policy_name', DEFAULT_POLICY_NAME)

        # Call the core logic
        result_message = block_external_ip_with_ca_policy_main_logic(ip, named_location_name, policy_name)

        # Return successful results
        # CommandResults (from CommonServerPython) is assumed to be global
        return_results(CommandResults(
            readable_output=result_message,
            outputs_prefix="BlockExternalIPWithCAPolicy",
            outputs={"IP": ip, "Status": "Blocked", "NamedLocation": named_location_name} # Example outputs
        ))

    except DemistoException as de:
        # Handle exceptions raised by Demisto functions or custom logic
        # return_error (from CommonServerPython) is assumed to be global
        return_error(f"Error executing script: {de!s}")
    except Exception as e:
        # Catch any other unexpected Python exceptions
        # return_error (from CommonServerPython) is assumed to be global
        return_error(f"An unexpected error occurred: {e!s}")


""" ENTRY POINT """
# The __builtin__ check is for backwards compatibility. __main__ and builtins are standard.
if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
