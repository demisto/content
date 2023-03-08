import demistomock as demisto


def main():
    value = demisto.args()['value']

    if type(value) is list and len(value) > 0:
        value = value[-1]

    demisto.results(value)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
