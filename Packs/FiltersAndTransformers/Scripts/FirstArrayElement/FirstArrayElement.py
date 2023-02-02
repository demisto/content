import demistomock as demisto


def main():
    value = demisto.args()['value']

    if isinstance(value, list) and value:
        value = value[0]

    demisto.results(value)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
