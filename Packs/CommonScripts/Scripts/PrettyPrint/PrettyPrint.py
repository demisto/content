import demistomock as demisto
from pprint import pformat


def main():
    value = demisto.args()['value']
    demisto.results(pformat(value))


if __name__ in ["__builtin__", "builtins"]:
    main()
