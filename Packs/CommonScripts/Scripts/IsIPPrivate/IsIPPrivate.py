import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from ipaddress import IPv4Address, IPv4Network


DELIMITER = ","


def is_ip_internal(ip: str, ranges: List[str]) -> bool:
    try:
        return any((IPv4Address(ip) in IPv4Network(cidr.split(DELIMITER)[0] if DELIMITER in cidr else cidr) for cidr in ranges))
    except ValueError as ve:
        return return_error(f"One or more IP ranges or IPs are invalid. Please make sure the list is in the correct structure."
                            f"Error: {ve}")


def get_ip_tag(ip: str, ranges: List[str]) -> str:
    for cidr in ranges:
        tag = None
        if DELIMITER in cidr:
            cidr, tag = cidr.split(DELIMITER)[0], cidr.split(DELIMITER)[1].strip()
        try:
            if IPv4Address(ip) in IPv4Network(cidr):
                return tag or ''
        except ValueError:
            if ip == cidr:
                return tag or ''
    return ''


def main():
    args = demisto.args()
    ranges_list_name = args.get("PrivateIPsListName", "PrivateIPs")
    ip_addresses_to_check = argToList(args.get("IPAddresses"))

    # Get the list of private IP ranges from the XSOAR list:
    private_ranges = demisto.executeCommand("getList", {"listName": ranges_list_name})[0]['Contents']
    if "Item not found" in private_ranges:
        return_error(f"The list name {ranges_list_name} does not exist.")

    # Split ranges from XSOAR list to be a list:
    if private_ranges:
        try:
            private_ranges = private_ranges.split("\n")
        except Exception:
            return_error(
                "Could not parse the private ranges list. "
                "Please make sure that the list contains ranges written in CIDR notation, separated by new lines.")
    else:
        private_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]  # No ranges in list, use default ranges
        demisto.debug(f"The list {ranges_list_name} was empty. Using the default private ranges as fall-back.")

    # Create list of IPs with private property and tag
    ip_list = [{"Address": ip, "Private": is_ip_internal(ip, private_ranges), "Tag": get_ip_tag(ip, private_ranges)} for
               ip in ip_addresses_to_check]

    # Create entry context and human-readable results
    entry_context = {"IP(val.Address == obj.Address)": ip_list}
    md_table = tableToMarkdown(name="IP Addresses", t=ip_list, headers=["Address", "Private", "Tag"])
    entry_to_return = {
        "Type": entryTypes['note'],
        "Contents": ip_list,
        "ContentsFormat": "text",
        "HumanReadable": md_table,
        "EntryContext": entry_context,
        "Tags": ['IP_Private_Ranges']
    }

    for ip in ip_list:
        address = ip.get("Address")
        private = ip.get("Private")
        args_exists_check = {
            "indicator": address
        }
        args_create_new_indicator = {
            "value": ip.get("Address"),
            "internal": ip.get("Private"),
            "customFields": {
                "tags": [ip.get("Tag", "")],
            }
        }
        args_set_existing_indicator = {
            "value": address,
            "internal": private
        }
        args_append_tag = {
            "field": "tags",
            "indicatorsValues": address,
            "fieldValue": ip.get("Tag", "")
        }

        # Check if indicator exists:
        is_exist_res = demisto.executeCommand("CheckIndicatorValue", args_exists_check)
        indicator_exists = is_exist_res[0].get("Contents", {})[0].get("Exists")

        # If indicator doesn't exist, create it:
        if indicator_exists:
            # Update it with internal property:
            demisto.executeCommand("setIndicator", args_set_existing_indicator)
            # Append new tag:
            # The reason we don't add tags in the setIndicator funtion is because we don't want to override existing tags.
            demisto.executeCommand("appendIndicatorField", args_append_tag)
        else:
            demisto.executeCommand("createNewIndicator", args_create_new_indicator)

    # Return results
    return_results(entry_to_return)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
