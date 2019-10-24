import demistomock as demisto
# borrowed from https://stackoverflow.com/questions/819355/how-can-i-check-if-an-ip-is-in-a-network-in-python

import socket
import struct
import re


def csv_string_to_list(v):
    if type(v) == str:
        return v.lower().replace(' ', '').replace("'", '').replace('\n', '').split(',')
    elif type(v) == list:
        y = [val.lower() for val in v]
        return y
    else:
        return v.lower().replace(' ', '').replace("'", '').replace('\n', '')


def make_mask(n):
    "return a mask of n bits as a long integer"
    return (2 << n - 1) - 1


def dotted_quad_to_num(ip):
    "convert decimal dotted quad string to long integer"
    return struct.unpack('<L', socket.inet_aton(ip))[0]


def network_mask(ip, bits):
    "Convert a network address to a long integer"
    return dotted_quad_to_num(ip) & make_mask(bits)


def address_in_network(ip, net):
    "Is an address in a network"
    return ip & net == net


def cidr_to_tuple(cidr):
    res = re.search(r'^(\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3})/(\d{1,2})$', cidr)
    if not res and re.search(r'^(\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3})$', cidr):
        # plain ip, return a mask of 32 bits
        return cidr, 32
    elif not res:
        # not an ip we recognise
        return None
    else:
        # valid ip and mask
        ip = res.group(1)
        mask = int(res.group(2))
        return ip, mask


def main():
    ADDRESS_LIST = csv_string_to_list(demisto.args()['value'])
    CIDR_LIST = csv_string_to_list(demisto.args()['cidr_ranges'])

    included_addresses = []

    for addr in ADDRESS_LIST:
        address = dotted_quad_to_num(addr)
        for cidr_range in CIDR_LIST:
            cidr_tuple = cidr_to_tuple(cidr_range)
            cidr_network = network_mask(*cidr_tuple)

            if cidr_network and address_in_network(address, cidr_network):
                included_addresses.append(addr)

    if len(included_addresses) == 0:
        demisto.results(None)
    else:
        demisto.results(included_addresses)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
