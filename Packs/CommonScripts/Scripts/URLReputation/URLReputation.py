import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def url_reputation():
    results = demisto.executeCommand('url', {'url': demisto.get(demisto.args(), 'url')})

    for item in results:
        if isError(item):
            item['Contents'] = item['Brand'] + ' returned an error.\n' + str(item['Contents'])

    demisto.results(results)


def main():
    url_reputation()


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
