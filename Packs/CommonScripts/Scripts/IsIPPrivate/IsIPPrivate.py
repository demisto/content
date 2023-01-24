from ipaddress import IPv4Address, IPv4Network

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def check_ip_internal(ip, ranges):
    for cidr in ranges:
        if IPv4Address(ip) in IPv4Network(cidr):
            return True
    return False


def create_markdown_table(ip_list):
    ip_list = sorted(ip_list, key=lambda x: x['Private'] == False)
    markdown_string = "| Address | Private |\n| --- | --- |\n"
    for ip in ip_list:
        markdown_string += f"| {ip['Address']} | {ip['Private']} |\n"
    return markdown_string


ranges_list_name = demisto.args().get("PrivateIPRangeList", None)
ip_addresses_to_check = argToList(demisto.args().get("IPAddresses", None))

# Get the list of private IP ranges from the XSOAR list:
private_ranges = demisto.executeCommand("getList", {"listName": "PrivateIPRanges"})[0]['Contents']

# Split ranges from XSOAR list to be a list:
if private_ranges:
    try:
        private_ranges = private_ranges.split("\n")
    except Exception as ex:
        demisto.error(
            "Could not parse the private ranges list. Please make sure that the list contains ranges written in CIDR notation, separated by new lines.")
else:
    private_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]  # No ranges in list, use default ranges

# Create list of IPs with private property
ip_list = []
for ip in ip_addresses_to_check:
    isInRange = check_ip_internal(ip, private_ranges)
    ip_list.append({"Address": ip, "Private": True if isInRange else False})

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

# Return results
demisto.results(entry_to_return)
