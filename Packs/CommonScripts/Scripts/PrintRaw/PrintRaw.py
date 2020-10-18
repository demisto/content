import demistomock as demisto


def main():
    value = demisto.args().get('value')
    demisto.results(repr(value))


if __name__ in ["__builtin__", "builtins"]:
    main()
