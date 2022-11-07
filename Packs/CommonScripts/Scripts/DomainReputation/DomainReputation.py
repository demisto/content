import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def domain_reputation():
    results = demisto.executeCommand('domain', {'domain': demisto.get(demisto.args(), 'domain')})

    for item in results:
        if isError(item):
            item['Contents'] = item['Brand'] + ' returned an error.\n' + str(item['Contents'])

    demisto.results(results)


def main():
    domain_reputation()


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
