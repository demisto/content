import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def file_reputation():
    results = demisto.executeCommand('file', {'file': demisto.get(demisto.args(), 'file')})

    for item in results:
        if isError(item):
            item['Contents'] = item['Brand'] + ' returned an error.\n' + str(item['Contents'])

    demisto.results(results)


def main():
    file_reputation()


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
