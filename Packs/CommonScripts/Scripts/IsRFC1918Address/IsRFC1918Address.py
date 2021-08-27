import demistomock as demisto
from CommonServerPython import *

from netaddr import IPAddress, IPNetwork


def main():
    try:
        args = demisto.args()
        ip_address = args.get('value')
        if not ip_address:
            ip_address = args.get('left')
        if not ip_address:
            raise Exception('Please enter an IPv4 Address either in the value or in the left arguments.')

        cidr_range_list = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']

        for cidr in cidr_range_list:
            if IPAddress(ip_address) in IPNetwork(cidr):
                demisto.results(True)
                return

        demisto.results(False)
    except Exception as err:
        return_error(str(err))


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
