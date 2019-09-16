import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

lst = demisto.executeCommand("getList", {"listName": demisto.args()["listname"]})

if isError(lst[0]):
    demisto.results(lst)
    sys.exit(0)

notwhitelisted = []  # type: list
whitlisted = []  # type: list
hr = ""
ignore_case = demisto.args().get("ignorecase", "").lower() == "yes"

items = demisto.args().get("values", "")
if not isinstance(items, list):
    items = items.split(",")

if not lst[0]["Contents"]:
    for item in items:
        notwhitelisted.append(item)

    ec = {"List.In": whitlisted, "List.NotIn": notwhitelisted}

    demisto.results(
        {
            "ContentsFormat": formats["text"],
            "Type": entryTypes["note"],
            "Contents": 'The list ' + demisto.args()["listname"] + ' is empty',
            "EntryContext": ec
        }
    )
    sys.exit(0)

lst = lst[0]["Contents"].split(",")
search_flag = re.IGNORECASE if ignore_case else 0

# fill whitelisted array with all the the values that match the regex items in listname argument
for item in items:
    for list_item in lst:
        if list_item and re.search(item, list_item, search_flag):
            hr += item + " is in the list\n"
            whitlisted.append(item)

# fill notwhitelisted array with all the the values that not in whitelisted
for item in items:
    if item not in whitlisted:
        hr += item + " is not part of the list\n"
        notwhitelisted.append(item)

ec = {"List.In": whitlisted, "List.NotIn": notwhitelisted}
contents = {"inList": whitlisted, "notInList": notwhitelisted}
demisto.results(
    {
        "ContentsFormat": formats["json"],
        "Type": entryTypes["note"],
        "Contents": contents,
        "HumanReadable": hr,
        "HumanReadableFormat": formats["markdown"],
        "EntryContext": ec
    }
)

sys.exit(0)
