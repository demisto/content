import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    list_name = demisto.args()['listName']
    res = demisto.executeCommand("getList", {"listName": list_name})
    res = res[0]
    if res['Type'] == entryTypes['error'] and "Item not found" in res['Contents']:
        demisto.results('no')
    else:
        demisto.results('yes')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
