from datetime import datetime, timedelta

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# get current time
now = datetime.now()

# args
listname = demisto.getArg("listname")

# update list name to start with 'OOO', so we can't overwrite other lists with this
if not listname.startswith("OOO"):
    listname = f"OOO {listname}"

# get the current list
ooo_list = demisto.executeCommand("getList", {"listName": listname})[0]["Contents"]

# check if the list exists, if not create it:
if "Item not found" in ooo_list:
    demisto.results(demisto.executeCommand("createList", {"listName": listname, "listData": []}))
    ooo_list = demisto.executeCommand("getList", {"listName": listname})[0]["Contents"]

# check status of the list, and add/remove the user from it.
if not ooo_list or ooo_list == [] or ooo_list == "":
    listData = []
else:
    listData = json.loads(ooo_list)

# loop the list, removing any where the offuntil is in the past
remove = []
for i in listData:
    off_until = datetime.strptime(i['offuntil'], "%Y-%m-%d")
    if off_until < now:
        remove.append(i['user'])

# remove the users from the list.
listData = [i for i in listData if i['user'] not in remove]

# set the list, return results
demisto.executeCommand("setList", {"listName": listname, "listData": json.dumps(listData)})
demisto.results(f"Removed Users from Out of Office List {listname}: {str(remove)}")
