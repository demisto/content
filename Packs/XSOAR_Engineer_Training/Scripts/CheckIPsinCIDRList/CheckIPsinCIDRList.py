import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from netaddr import IPAddress, IPNetwork


def main():
    # get ips from the ips arg.
    ip_address = demisto.args().get('ips')

    # get the xsoar list with the ips/cidrs, and change it to an array.
    list_name = demisto.args().get('listname')
    cidr_range_list = [x.strip() for x in demisto.executeCommand('getList', {'listName': list_name})[0]['Contents'].split(',')]

    # handle if the list doesn't exist.
    if isError(cidr_range_list[0]):
        return_error('List not found')

    # check if ips is an array, or single value, change to array if a single IP was provided.
    if not isinstance(ip_address, list):
        ip_address = [ip_address]

    # check the ips against the cidr list
    in_range = []
    for ip in ip_address:
        for cidr in cidr_range_list:
            if IPAddress(ip) in IPNetwork(cidr):
                in_range.append({"Address": ip, "In": cidr})
                break

    # return only the IPs found to context.
    if in_range:
        readable = f"Found {len(in_range)} addresses in provided ranges"
        results = CommandResults(readable_output=readable, outputs=in_range, outputs_prefix="InCIDR")
        return_results(results)
    else:
        demisto.results("No IPs in ranges provided")


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
