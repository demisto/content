import demistomock as demisto


def main():
    args = demisto.args()
    value = args.get("value")
    if value and isinstance(value, list):
        demisto.results(value)
    elif value:
        demisto.results([value])
    else:
        demisto.results([])


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
