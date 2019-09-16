import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

lst = demisto.executeCommand("getList", {"listName": demisto.args()["listname"]})

if isError(lst[0]):
    demisto.results(lst)
    sys.exit(0)

notwhitelisted = []
whitlisted = []
hr = ""
items = demisto.args().get("values", "")
ignore_case = demisto.args().get("ignorecase", "").lower() == "yes"

if not isinstance(items, list):
    items = items.split(",")

if not lst[0]["Contents"]:

    for item in items:
        notwhitelisted.append(item)

    ec = {"List.In": whitlisted, "List.NotIn": notwhitelisted}

    demisto.results({"ContentsFormat": formats["text"],
                     "Type": entryTypes["note"],
                     "Contents": 'The list ' + demisto.args()["listname"] + ' is empty',
                     "EntryContext": ec})
    sys.exit(0)

lst = lst[0]["Contents"].split(",")

search_flag = re.IGNORECASE if ignore_case else 0

# fill whitlisted array with all the the values that match the regex items in listname argument
for item in items:
    found = ''
    for list_item in lst:
        if not list_item:
            continue
        if re.search(list_item, item, search_flag):
            found = item
            break
    if found != '':
        hr = hr + found + " is in the list\n"
        whitlisted.append(found)

# fill notwhitelisted array with all the the values that not in whitlisted
for item in items:
    if item not in whitlisted:
        hr = hr + item + " is not part of the list\n"
        notwhitelisted.append(item)

ec = {"List.In": whitlisted, "List.NotIn": notwhitelisted}
contents = {"inList": whitlisted, "notInList": notwhitelisted}
demisto.results({"ContentsFormat": formats["json"],
                 "Type": entryTypes["note"],
                 "Contents": contents,
                 "HumanReadable": hr,
                 "HumanReadableFormat": formats["markdown"],
                 "EntryContext": ec})

sys.exit(0)
