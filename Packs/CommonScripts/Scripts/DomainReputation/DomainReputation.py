import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def domain_reputation():
    results = demisto.executeCommand('domain', {'domain': demisto.get(demisto.args(), 'domain')})

    for item in results:
        if isError(item):
            if is_offset_error(item):  # call to is_offset_error is a temporary fix to ignore offset 1 error
                results.remove(item)
            else:
                item['Contents'] = item['Brand'] + ' returned an error.\n' + str(item['Contents'])

    demisto.results(results)


def is_offset_error(item) -> bool:
    '''error msg: 'Offset: 1' will not be displayed to Users
       This method is temporary and will be removed
       once XSUP-18208 issue is fixed.'''
    if item['Contents'] and 'Offset' in item['Contents']:
        return True
    return False


def main():
    domain_reputation()


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
