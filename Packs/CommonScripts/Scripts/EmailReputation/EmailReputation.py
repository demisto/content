import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def email_reputation():
    results = demisto.executeCommand('email', {'email': demisto.get(demisto.args(), 'email')})

    for item in results:
        if isError(item):
            item['Contents'] = item['Brand'] + ' returned an error.\n' + str(item['Contents'])

    demisto.results(results)


def main():
    email_reputation()


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
