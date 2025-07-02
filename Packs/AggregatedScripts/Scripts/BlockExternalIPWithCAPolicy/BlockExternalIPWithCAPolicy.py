import demistomock as demisto  # noqa: F401
from CommonServerPython import * # noqa: F401

import json
import ipaddress
import time
# Removed List and Union from typing import, as we'll use built-in list and X | Y syntax.
# Optional is still needed for Python < 3.10 if not using from __future__ import annotations
from typing import Any, Optional

# --- Constants ---
GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"  # Azure Global Administrator role ID
DEFAULT_NAMED_LOCATION_NAME = "Cortex Blocked IPs"
DEFAULT_POLICY_NAME = "Cortex - Block Malicious IPs"

# --- Helper Functions ---

def is_private_ip(ip: str) -> bool:
    """
    Checks if the given IP address is a private IP address.
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        demisto.debug(f"Invalid IP address format encountered: {ip}")
        return False

def get_azure_command_error_details(res: dict[str, Any]) -> str:
    """
    Extracts a readable error message from an Azure command result.
    Tries to parse the 'Contents' field for JSON structured error info.
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
                if isinstance(parsed_contents, dict) and 'error' in parsed_contents:
                    error = parsed_contents['error']
                    return f"{error.get('code', 'Error')}: {error.get('message', 'No message')}"
            except json.JSONDecodeError:
                pass
            return raw_contents
        elif isinstance(raw_contents, dict) and "error" in raw_contents:
            error = raw_contents["error"]
            return f"{error.get('code', 'Error')}: {error.get('message', 'No message')}"
        return str(raw_contents or res.get("ReadableContents", "Unknown error"))
    except Exception as ex:
        demisto.debug(f"Exception during error details extraction: {ex}")
        return f"Error extracting error message: {str(ex)}"

def _execute_command_and_handle_error(command: str, args: dict[str, Any], error_message_prefix: str) -> dict[str, Any]:
    """
    Executes a Demisto command and checks for errors.
    Raises an exception if command execution fails.
    """
    res = demisto.executeCommand(command, args)
    if not res or not isinstance(res, list) or not res[0]:
        raise DemistoException(f"{error_message_prefix}: Empty or invalid command result for {command}.")
    if is_error(res):
        error_details = get_azure_command_error_details(res[0])
        raise DemistoException(f"{error_message_prefix}: {error_details}")
    demisto.debug(f"Successfully executed {command}. Result: {res[0].get('Contents')}")
    return res[0].get('Contents', {})

# Fix 1: Change Optional[dict[str, Any]] to dict[str, Any] | None
def get_named_ip_location(named_location_name: str) -> dict[str, Any] | None:
    """
    Retrieves an existing named IP location by display name.
    """
    filter_query = f"$filter=displayName eq '{named_location_name}'"
    contents = _execute_command_and_handle_error(
        'msgraph-identity-ip-named-locations-list',
        {'odata_query': filter_query},
        "Failed to list named IP locations"
    )
    if isinstance(contents, dict) and 'value' in contents:
        existing_locations = contents.get('value', [])
    elif isinstance(contents, list):
        existing_locations = contents
    else:
        existing_locations = []
    return existing_locations[0] if existing_locations else None

# Fix 2: Change List[str] to list[str]
def update_existing_named_location(named_location_id: str, named_location_name: str, existing_cidrs: list[str], new_ip_cidr: str) -> None:
    """
    Adds a new IP CIDR to an existing named IP location if not already present.
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
    time.sleep(30)  # Wait for Azure to propagate the named location (recommended for CA policies)  # pylint: disable=E9003
    return named_location_id

def create_conditional_access_policy(policy_name: str, named_location_id: str) -> None:
    """
    Creates a Conditional Access policy to block access from the specified named location.
    """
    policy_json = {
        "displayName": policy_name,
        "state": "enabled",
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeRoles": [GLOBAL_ADMIN_ROLE_ID]
            },
            "applications": {
                "includeApplications": ["All"]
            },
            "clientAppTypes": ["all"],
            "locations": {
                "includeLocations": [named_location_id]
            }
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["block"]
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

# Fix 3: Change Optional[str] to str | None
def block_external_ip_with_ca_policy_main_logic(ip: str, named_location_name: str, policy_name: str) -> str:
    """
    Orchestrates the blocking of an external IP address via Azure Conditional Access.
    """
    if not ip:
        raise DemistoException("Missing required argument: 'ip'.")
    if is_private_ip(ip):
        raise DemistoException(f"The IP {ip} appears to be internal/private and will not be blocked.")
    named_location = get_named_ip_location(named_location_name)
    named_location_id: str | None = None # Fix 4: Use str | None for type annotation
    if named_location:
        named_location_id = named_location.get('id')
        ip_ranges = named_location.get('ipRanges', [])
        cidrs = [r.get('cidrAddress') for r in ip_ranges if r.get('cidrAddress')]
        if named_location_id:
            update_existing_named_location(named_location_id, named_location_name, cidrs, f"{ip}/32")
    else:
        named_location_id = create_new_named_ip_location(named_location_name, ip)
        create_conditional_access_policy(policy_name, named_location_id)
    return f"IP {ip} has been processed and blocked if necessary."

def main():
    """
    Entry point of the XSOAR script. Handles args and exception logging.
    """
    try:
        args = demisto.args()
        ip = args.get('ip')
        named_location_name = args.get('named_location_name', DEFAULT_NAMED_LOCATION_NAME)
        policy_name = args.get('policy_name', DEFAULT_POLICY_NAME)
        result_message = block_external_ip_with_ca_policy_main_logic(ip, named_location_name, policy_name)
        return_results(CommandResults(
            readable_output=result_message,
            outputs_prefix="BlockExternalIPWithCAPolicy",
            outputs={"IP": ip, "Status": "Blocked", "NamedLocation": named_location_name}
        ))
    except Exception as e:
        return_error(f"Error executing script: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()