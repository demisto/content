from pprint import pformat

import demistomock as demisto


def main():
    value = demisto.args()["value"]
    demisto.results(pformat(value))


if __name__ in ["__builtin__", "builtins"]:
    main()
