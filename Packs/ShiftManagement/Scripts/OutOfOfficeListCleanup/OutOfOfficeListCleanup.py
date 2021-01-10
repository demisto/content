from CommonServerPython import *

# get current time
now = datetime.now()

# args
list_name = demisto.getArg("listname")

# update list name to start with 'OOO', so we can't overwrite other lists with this
if not list_name.startswith("OOO"):
    list_name = f"OOO {list_name}"

# get the current list
ooo_list = demisto.executeCommand("getList", {"listName": list_name})[0]["Contents"]

# check if the list exists, if not create it:
if "Item not found" in ooo_list:
    demisto.results(demisto.executeCommand("createList", {"listName": list_name, "listData": []}))
    ooo_list = demisto.executeCommand("getList", {"listName": list_name})[0]["Contents"]

# check status of the list, and add/remove the user from it.
if not ooo_list or ooo_list == [] or ooo_list == "":
    list_data = []
else:
    list_data = json.loads(ooo_list)

# loop the list, removing any where the offuntil is in the past
remove = []
for i in list_data:
    off_until = datetime.strptime(i['offuntil'], "%Y-%m-%d")
    if off_until < now:
        remove.append(i['user'])

# remove the users from the list.
list_data = [i for i in list_data if i['user'] not in remove]

# set the list, return results
demisto.executeCommand("setList", {"listName": list_name, "listData": json.dumps(list_data)})
demisto.results(f"Removed Users from Out of Office List {list_name}: {str(remove)}")
