import ipaddress
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any, cast  # Import 'cast' for mypy

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
        # Check if the IP is private, specifically handling IPv4 for common scenarios.
        # ipaddress.ip_address will return either IPv4Address or IPv6Address.
        # .is_private applies to both, but comparisons need to be type-consistent.
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        demisto.debug(f"Invalid IP address format encountered: {ip}")
        return False


def ip_in_range(ip: str, ip_range: str) -> bool:
    """
    Checks if a given IPv4 address falls within a specified IPv4 range (CIDR, dash-separated range, or single IP).

    Args:
        ip (str): The IPv4 address string to check.
        ip_range (str): The IPv4 range string (e.g., '192.168.1.0/24', '10.0.0.1-10.0.0.10', '1.1.1.1').

    Returns:
        bool: True if the IPv4 is within the IPv4 range, False otherwise or if inputs are invalid
              or if IP versions are mismatched.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)

        # Pre-check for IPv6 here if main is not strictly enforcing IPv4, though main now does.
        # This is primarily for mypy to infer the type consistently.
        if ip_obj.version != 4:
            demisto.debug(f"Non-IPv4 address '{ip}' passed to ip_in_range. Script expects IPv4.")
            return False

        # Cast to IPv4Address for mypy's benefit, now that we've checked the version
        ip_obj = cast(ipaddress.IPv4Address, ip_obj)

        if "-" in ip_range:
            start_ip_str, end_ip_str = ip_range.split("-")
            start_ip = ipaddress.ip_address(start_ip_str)
            end_ip = ipaddress.ip_address(end_ip_str)

            if start_ip.version != 4 or end_ip.version != 4:
                demisto.debug(f"Non-IPv4 range '{ip_range}' detected. Script expects IPv4 ranges.")
                return False

            # Cast for mypy
            start_ip = cast(ipaddress.IPv4Address, start_ip)
            end_ip = cast(ipaddress.IPv4Address, end_ip)

            return start_ip <= ip_obj <= end_ip
        elif "/" in ip_range:
            ip_network_obj = ipaddress.ip_network(ip_range, strict=False)

            if ip_network_obj.version != 4:
                demisto.debug(f"Non-IPv4 network '{ip_range}' detected. Script expects IPv4 networks.")
                return False

            # Cast for mypy
            ip_network_obj = cast(ipaddress.IPv4Network, ip_network_obj)

            return ip_obj in ip_network_obj
        else:  # Single IP
            single_ip_obj = ipaddress.ip_address(ip_range)

            if single_ip_obj.version != 4:
                demisto.debug(f"Non-IPv4 single IP '{ip_range}' detected. Script expects IPv4 IPs.")
                return False

            # Cast for mypy
            single_ip_obj = cast(ipaddress.IPv4Address, single_ip_obj)

            return ip_obj == single_ip_obj
    except Exception as e:
        demisto.debug(f"Error checking IP '{ip}' against range '{ip_range}': {e}")
        return False


def _format_error_message(error_dict: dict[str, Any]) -> str:
    """
    Formats a dictionary containing an 'error' key into a readable error string.

    This helper function centralizes the logic for extracting and formatting
    the error code and message from a command's result. It gracefully handles
    cases where the 'error', 'code', or 'message' keys might be missing
    by providing default values.

    Args:
        error_dict (dict[str, Any]): The dictionary containing the error details.
                                     It is expected to have a top-level 'error' key.

    Returns:
        str: A formatted string in the format "<code>: <message>".
    """
    error = error_dict.get("error", {})
    return f"{error.get('code', 'Error')}: {error.get('message', 'No message')}"


def _get_command_error_details(res: dict[str, Any]) -> str:
    """
    Extracts a readable error message from a command result.

    This function abstracts the process of parsing different error message formats
    returned by commands, such as JSON strings, dictionary objects, or
    plain text. It uses the _format_error_message helper to centralize
    the final formatting of detailed error messages.

    Args:
        res (dict[str, Any]): The raw result object from a command, typically res[0] from executeCommand.

    Returns:
        str: A human-readable string containing the error code and message, or a
             generic error string if parsing fails.
    """
    raw_contents = res.get("Contents")
    try:
        if isinstance(raw_contents, str):
            if "Error in API call" in raw_contents:
                try:
                    json_start_index = raw_contents.index("{", raw_contents.index("Error in API call"))
                    err = json.loads(raw_contents[json_start_index:])
                    if isinstance(err, dict) and "error" in err:
                        return _format_error_message(err)
                except (json.JSONDecodeError, ValueError):
                    demisto.debug(f"Failed to parse detailed JSON from API error string: {raw_contents}")
                    return f"Unparsed API error: {raw_contents}"
            try:
                parsed_contents = json.loads(raw_contents)
                if isinstance(parsed_contents, dict) and "error" in parsed_contents:
                    return _format_error_message(parsed_contents)
            except json.JSONDecodeError:
                pass
        elif isinstance(raw_contents, dict) and "error" in raw_contents:
            return _format_error_message(raw_contents)

        return str(raw_contents or res.get("ReadableContents", "Unknown error"))
    except Exception as ex:
        demisto.debug(f"Exception during error details extraction in _get_command_error_details: {ex}")
        return f"Error extracting error message: {str(ex)}"


def _execute_command(command: str, args: dict[str, Any], error_message_prefix: str) -> Any:
    """
    Executes a command and handles potential errors.

    This function abstracts the common pattern of executing a command and
    checking its result for errors, providing a consistent error handling mechanism.

    Args:
        command (str): The name of the command to execute (e.g., 'okta-list-zones').
        args (dict[str, Any]): A dictionary of arguments to pass to the command.
        error_message_prefix (str): A string prefix to prepend to any exceptions,
                                    indicating the context of the error.

    Returns:
        Any: The parsed 'Contents' from the command's successful result.

    Raises:
        DemistoException: If the command execution fails, returns an empty/invalid response structure,
                          or indicates an error via `isError()`.
    """
    res = demisto.executeCommand(command, args)
    if not res or not isinstance(res, list) or not res[0]:
        raise DemistoException(f"{error_message_prefix}: Empty or invalid command result for {command}.")

    if isError(res[0]):
        error_details = _get_command_error_details(res[0])
        raise DemistoException(f"{error_message_prefix}: {error_details}")

    demisto.debug(f"Successfully executed {command}. Result: {res[0].get('Contents')}")
    return res[0].get("Contents")


def get_blocked_ip_zone_info() -> dict[str, Any]:
    """
    Retrieves the 'BlockedIpZone' information from Okta zones.

    This function calls the 'okta-list-zones' command to fetch all Okta zones
    and then specifically looks for the zone named "BlockedIpZone". It extracts
    its ID and the list of associated gateways.

    Returns:
        dict[str, Any]: A dictionary containing 'zone_id' and 'zone_gateways' (list of strings) if the zone is found.

    Raises:
        DemistoException: If listing Okta zones fails, if the "BlockedIpZone" is not found,
                          or if the response format from Okta is unexpected.
    """
    res_zones = _execute_command("okta-list-zones", {}, "Failed to list Okta zones")

    zones: list[dict[str, Any]] = []
    if isinstance(res_zones, dict):
        zones = res_zones.get("result", [])
    elif isinstance(res_zones, list):
        zones = res_zones
    else:
        raise DemistoException("Unexpected format in okta-list-zones response.")

    zone_id = None
    zone_gateways = []

    for zone in zones:
        if zone.get("name") == "BlockedIpZone":
            zone_id = zone.get("id")
            gateways = zone.get("gateways", [])
            for gateway in gateways:
                if gateway.get("type") in ["CIDR", "RANGE"]:
                    zone_gateways.append(gateway.get("value"))
            break

    if not zone_id:
        raise DemistoException("BlockedIpZone not found in Okta zones.")

    return {"zone_id": zone_id, "zone_gateways": zone_gateways}


def update_blocked_ip_zone(zone_id: str, zone_gateways: list[str], ip_to_add: str) -> None:
    """
    Appends a new IP CIDR to the 'BlockedIpZone' in Okta.

    This function checks if the IP is already covered by an existing gateway in the zone.
    If not, it adds the new IP as a /32 CIDR to the list of gateways and updates the Okta zone.

    Args:
        zone_id (str): The ID of the 'BlockedIpZone' to update.
        zone_gateways (list[str]): The current list of gateway IP ranges/CIDRs associated with the zone.
        ip_to_add (str): The IP address string to add (e.g., "1.2.3.4"); it will be converted to a /32 CIDR.

    Returns:
        None: A message indicating whether the IP was added or already exists will be returned via `return_results`.

    Raises:
        DemistoException: If the update operation to Okta fails.
    """
    ip_cidr = f"{ip_to_add}/32"

    for gw in zone_gateways:
        if ip_in_range(ip_to_add, gw):
            return_results(f"IP {ip_to_add} is already covered by entry: {gw}")
            return

    zone_gateways.append(ip_cidr)
    update_args = {
        "zoneID": zone_id,
        "gateways": ",".join(zone_gateways),
        "gatewayIPs": ip_cidr,  # Used by some Okta update methods to specify the new IP to append
        "type": "IP",
        "name": "BlockedIpZone",
        "status": "ACTIVE",
        "updateType": "APPEND",
    }

    _execute_command("okta-update-zone", update_args, "Failed to update BlockedIpZone")
    return_results(f"IP {ip_to_add} added to BlockedIpZone.")


def main():
    """
    Main function for blocking an IP address in Okta by adding it to a 'BlockedIpZone'.

    This is the primary entry point of the script. It retrieves the IP address from arguments,
    performs initial validation (e.g., checks for missing, private, or non-IPv4 IPs),
    fetches the Okta 'BlockedIpZone' information, and then updates the zone to include the IP.
    All exceptions are caught and reported via `return_error`.
    """
    try:
        ip = demisto.args().get("ip")
        # Added a check to ensure the input IP is IPv4 before proceeding
        try:
            if ipaddress.ip_address(ip).version != 4:
                return_error(f"The IP {ip} is not an IPv4 address. This script currently supports only IPv4.")
                return
        except ValueError:
            return_error(f"The input '{ip}' is not a valid IP address.")
            return

        if is_private_ip(ip):
            return_error(f"The IP {ip} is private/internal and should not be added.")
            return

        zone_info = get_blocked_ip_zone_info()
        zone_id = zone_info["zone_id"]
        zone_gateways = zone_info["zone_gateways"]

        update_blocked_ip_zone(zone_id, zone_gateways, ip)

    except Exception as e:
        return_error(f"Error blocking IP in Okta zone: {str(e)}", e)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
