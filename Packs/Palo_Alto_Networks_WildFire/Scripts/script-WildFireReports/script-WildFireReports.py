import demistomock as demisto


def main():
    args = demisto.args()
    demisto.executeCommand("wildfire-get-report", args)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
