import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import ipaddress
from typing import Any, List, Union, Dict, Optional # Explicitly import necessary types


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


def ip_in_range(ip: str, ip_range: str) -> bool:
    """
    Checks if a given IP address falls within a specified IP range (CIDR, dash-separated range, or single IP).

    Args:
        ip (str): The IP address string to check.
        ip_range (str): The IP range string (e.g., '192.168.1.0/24', '10.0.0.1-10.0.0.10', '1.1.1.1').

    Returns:
        bool: True if the IP is within the range, False otherwise or if inputs are invalid.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        if '-' in ip_range:
            start_ip_str, end_ip_str = ip_range.split('-')
            start_ip = ipaddress.ip_address(start_ip_str)
            end_ip = ipaddress.ip_address(end_ip_str)
            return start_ip <= ip_obj <= end_ip
        elif '/' in ip_range:
            return ip_obj in ipaddress.ip_network(ip_range, strict=False)
        else:
            return ip_obj == ipaddress.ip_address(ip_range)
    except Exception as e:
        demisto.debug(f"Error checking IP '{ip}' against range '{ip_range}': {e}")
        return False


def _get_command_error_details(res: Dict[str, Any]) -> str:
    """
    Extracts a readable error message from a Demisto command result.
    This function handles specific formatting of errors returned by certain commands.

    Args:
        res (dict[str, Any]): The raw result object from a Demisto command.

    Returns:
        str: A human-readable error message.
    """
    contents = res.get("Contents", "")
    try:
        if isinstance(contents, dict) and "error" in contents:
            return f"{contents['error'].get('code', 'Error')}: {contents['error'].get('message', 'No message')}"
        return str(contents or res.get("ReadableContents", "Unknown error"))
    except Exception as e:
        demisto.debug(f"Failed to parse error details: {e}")
        return f"Failed to parse error: {str(e)}"


def _execute_demisto_command(command: str, args: Dict[str, Any], error_message_prefix: str) -> Any:
    """
    Executes a Demisto command and handles potential errors.

    Args:
        command (str): The name of the Demisto command to execute.
        args (Dict[str, Any]): A dictionary of arguments for the command.
        error_message_prefix (str): A prefix for the error message if the command fails.

    Returns:
        Any: The contents of the command result if successful.

    Raises:
        DemistoException: If the command execution fails or returns an invalid structure.
    """
    res = demisto.executeCommand(command, args)
    if not res or not isinstance(res, list) or not res[0]:
        raise DemistoException(f"{error_message_prefix}: Empty or invalid command result for {command}.")

    if isError(res[0]):
        error_details = _get_command_error_details(res[0])
        raise DemistoException(f"{error_message_prefix}: {error_details}")

    demisto.debug(f"Successfully executed {command}. Result: {res[0].get('Contents')}")
    return res[0].get("Contents")


def get_blocked_ip_zone_info() -> Dict[str, Any]:
    """
    Retrieves the 'BlockedIpZone' information from Okta zones.

    Returns:
        Dict[str, Any]: A dictionary containing 'zone_id' and 'zone_gateways' if found.

    Raises:
        DemistoException: If listing Okta zones fails or 'BlockedIpZone' is not found,
                          or if the response format is unexpected.
    """
    res_zones = _execute_demisto_command("okta-list-zones", {}, "Failed to list Okta zones")

    zones: List[Dict[str, Any]] = []
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
            break  # Found the zone, no need to continue iterating

    if not zone_id:
        raise DemistoException("BlockedIpZone not found in Okta zones.")

    return {"zone_id": zone_id, "zone_gateways": zone_gateways}


def update_blocked_ip_zone(zone_id: str, zone_gateways: List[str], ip_to_add: str) -> None:
    """
    Appends a new IP CIDR to the 'BlockedIpZone' in Okta.

    Args:
        zone_id (str): The ID of the 'BlockedIpZone'.
        zone_gateways (List[str]): The list of existing gateway IPs in the zone.
        ip_to_add (str): The IP address to add (will be converted to /32 CIDR).

    Raises:
        DemistoException: If updating the Okta zone fails.
    """
    ip_cidr = f"{ip_to_add}/32"

    for gw in zone_gateways:
        if ip_in_range(ip_to_add, gw):
            return_results(f"IP {ip_to_add} is already covered by entry: {gw}")
            return  # Exit early if IP is already covered

    zone_gateways.append(ip_cidr)
    update_args = {
        "zoneID": zone_id,
        "gateways": ",".join(zone_gateways),  # Ensure all gateways are passed back
        "gatewayIPs": ip_cidr,  # This might be for specific append, but passing all is safer
        "updateType": "APPEND",
        "type": "IP",
        "name": "BlockedIpZone",
        "status": "ACTIVE"
    }

    _execute_demisto_command("okta-update-zone", update_args, "Failed to update BlockedIpZone")
    return_results(f"IP {ip_to_add} added to BlockedIpZone.")


def main():
    """
    Main function for blocking an IP address in Okta by adding it to a 'BlockedIpZone'.
    """
    try:
        ip = demisto.args().get("ip")
        if not ip:
            return_error("Missing required argument: ip")

        if is_private_ip(ip):
            return_error(f"The IP {ip} is private/internal and should not be added.")

        zone_info = get_blocked_ip_zone_info()
        zone_id = zone_info["zone_id"]
        zone_gateways = zone_info["zone_gateways"]

        update_blocked_ip_zone(zone_id, zone_gateways, ip)

    except Exception as e:
        return_error(f"Error blocking IP in Okta zone: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
