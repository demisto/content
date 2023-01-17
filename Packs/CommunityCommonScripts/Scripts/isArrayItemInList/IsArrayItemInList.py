import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

array = demisto.args().get('inputArray')
list_name = demisto.args().get('listName')

res = demisto.executeCommand("getList", {"listName": list_name})[0]

for item in array:
    if str(item) in res['Contents']:
        demisto.results('yes')
        break
