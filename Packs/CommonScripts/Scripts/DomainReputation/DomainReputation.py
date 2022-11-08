import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def domain_reputation():
    results = demisto.executeCommand('domain', {'domain': demisto.get(demisto.args(), 'domain')})

    for item in results:
        if isError(item) and is_valid_error(item):  # call to is_valid_error is a temporary fix to ignore offset 1 error
            item['Contents'] = item['Brand'] + ' returned an error.\n' + str(item['Contents'])

    demisto.results(results)


# remove this method once XSUP-18208 is fixed in ExecutionMetrics / Server
def is_valid_error(item) -> bool:
    if item['Brand'] == 'VirusTotal (API v3)' and item['Contents'] == "'Offset': 1":
        return False
    return True


def main():
    domain_reputation()


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
