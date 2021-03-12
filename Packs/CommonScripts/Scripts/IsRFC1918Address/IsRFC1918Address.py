import demistomock as demisto

from netaddr import IPAddress, IPNetwork


def main():
    args = demisto.args()

    ip_address = args.get('value', 'left')

    cidr_range_list = argToList(args.get('right'))
    if not cidr_range_list:
        cidr_range_list = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']

    for cidr in cidr_range_list:
        if IPAddress(ip_address) in IPNetwork(cidr):
            demisto.results(True)
            return

    demisto.results(False)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
