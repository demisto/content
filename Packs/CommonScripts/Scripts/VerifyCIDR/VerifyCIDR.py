import demistomock as demisto
from CommonServerPython import *
import ipaddress


''' STANDALONE FUNCTION '''


def is_valid_cidr(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr)
        return True
    except ValueError:
        return False


''' MAIN FUNCTION '''


def main():
    try:
        input_cidr = demisto.args().get('input')
        input_cidr = argToList(input_cidr)

        valid_cidr = []

        for item in input_cidr:
            if is_valid_cidr(item):
                valid_cidr.append(item)
            else:
                valid_cidr.append('')

        if valid_cidr:
            return_results(valid_cidr)
        else:
            return_results('')

    except Exception as e:
        return_error(f'Failed to execute VerifyCIDR. Error: {str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
