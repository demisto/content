import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import ipaddress


def is_valid_ipv4_address(address: str):
    try:
        ipaddress.IPv4Address(address)
        return True
    except ValueError:
        return False


""" MAIN FUNCTION """


def main():
    try:
        the_input = demisto.args().get("input")
        the_input = argToList(the_input)
        entries_list = []

        for item in the_input:
            if is_valid_ipv4_address(item):
                entries_list.append(item)
            else:
                continue

        if entries_list:
            return_results(entries_list)
        else:
            return_results("")
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute BaseScript. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
