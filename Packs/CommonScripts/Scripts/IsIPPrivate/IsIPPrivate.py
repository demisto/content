from ipaddress import IPv4Address, IPv4Network
from time import sleep

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

DELIMETER = ","
POLLING_TIME = 2  # Time in seconds to wait for indicator indexing


def check_ip_internal(ip, ranges):
    try:
        return any((IPv4Address(ip) in IPv4Network(cidr.split(DELIMETER)[0] if DELIMETER in cidr else cidr) for cidr in ranges))
    except ValueError:
        demisto.log("One or more IP ranges or IPs are invalid. Please make sure the list is in the correct structure.")
        return True


def get_ip_tag(ip, ranges):
    for cidr in ranges:
        tag = None
        if DELIMETER in cidr:
            cidr, tag = cidr.split(DELIMETER)[0], cidr.split(DELIMETER)[1].strip()
        try:
            if IPv4Address(ip) in IPv4Network(cidr):
                return tag
        except ValueError:
            if ip == cidr:
                return tag
    return None


def create_markdown_table(ip_list):
    ip_list = sorted(ip_list, key=lambda x: not x['Private'])
    markdown_string = "| Address | Private | Tag |\n| --- | --- | --- |\n"
    for ip in ip_list:
        markdown_string += f"| {ip['Address']} | {ip['Private']} | {ip['Tag']}|\n"
    return markdown_string


ranges_list_name = demisto.args().get("PrivateIPsListName", "PrivateIPs")
ip_addresses_to_check = argToList(demisto.args().get("IPAddresses", None))

# Get the list of private IP ranges from the XSOAR list:
private_ranges = demisto.executeCommand("getList", {"listName": ranges_list_name})[0]['Contents']
if "Item not found" in private_ranges:
    return_error(f"The list name {ranges_list_name} does not exist.")

# Split ranges from XSOAR list to be a list:
if private_ranges:
    try:
        private_ranges = private_ranges.split("\n")
    except Exception as ex:
        return_error(
            "Could not parse the private ranges list. Please make sure that the list contains ranges written in CIDR notation, separated by new lines.")
else:
    private_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]  # No ranges in list, use default ranges

# Create list of IPs with private property and tag
ip_list = [{"Address": ip, "Private": check_ip_internal(ip, private_ranges), "Tag": get_ip_tag(ip, private_ranges)} for
           ip in ip_addresses_to_check]

# Create entry context and human-readable results
entry_context = {"IP(val.Address == obj.Address)": ip_list}
md_table = create_markdown_table(ip_list)
entry_to_return = {
    "Type": entryTypes['note'],
    "Contents": ip_list,
    "ContentsFormat": "text",
    "HumanReadable": md_table,
    "EntryContext": entry_context,
    "Tags": ['IP_Private_Ranges']
}

for ip in ip_list:
    args_exists_check = {
        "indicator": ip.get("Address")
    }

    args_create_new_indicator = {
        "value": ip.get("Address"),
        "internal": ip.get("Private")
    }

    args_set_existing_indicator = {
        "value": ip.get("Address"),
        "internal": ip.get("Private")
    }

    args_append_tag = {
        "field": "tags",
        "indicatorsValues": ip.get("Address"),
        "fieldValue": ip.get("Tag", "")
    }

    # Check if indicator exists:
    is_exist_res = demisto.executeCommand("CheckIndicatorValue", args_exists_check)
    indicator_exists = is_exist_res[0].get("Contents", {})[0].get("Exists")

    # If indicator doesn't exist, create it:
    if not indicator_exists:
        demisto.executeCommand("createNewIndicator", args_create_new_indicator)
        while not indicator_exists:  # Looping because it takes time for the indicator to be created
            is_exist_res = demisto.executeCommand("CheckIndicatorValue", args_exists_check)
            indicator_exists = is_exist_res[0].get("Contents", {})[0].get("Exists")
            sleep(POLLING_TIME)

    # Once indicator exists, update it with internal property:
    demisto.executeCommand("setIndicator", args_set_existing_indicator)

    # Finally - append new tag
    # The reason we don't add tags in the createNewIndicator or setIndicator funtions is because we don't want to override existing tags.
    demisto.executeCommand("appendIndicatorField", args_append_tag)

# Return results
demisto.results(entry_to_return)
