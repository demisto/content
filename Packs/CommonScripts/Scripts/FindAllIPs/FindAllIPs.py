import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re


def main():
    pattern = r'[0-9]+(?:\.[0-9]+){3}'
    text = demisto.getArg("text")
    ip = re.findall(pattern, text)  # creates a list of IPs
    if ip:
        demisto.setContext('IPsFound', ip)
        demisto.results(ip)
    else:
        demisto.results("No IPs have been found")


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
