import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# args
list_name = demisto.getArg("listname")
oncall = demisto.getArg("oncall")
roles = demisto.getArg("roles")

# update list name to start with 'OOO', so we can't overwrite other lists with this
if not list_name.startswith("OOO"):
    list_name = f"OOO {list_name}"


# get the out of office list, and the current xsoar users
list_info = demisto.executeCommand("getList", {"listName": list_name})[0]['Contents']

# check if the list exists, if not create it:
if "Item not found" in list_info:
    demisto.results(demisto.executeCommand("createList", {"listName": list_name, "listData": []}))
    list_info = json.loads(demisto.executeCommand("getList", {"listName": list_name})[0]["Contents"])
else:
    list_info = json.loads(list_info)

list_info = [i['user'] for i in list_info]


# get xsoar users
userinfo = demisto.executeCommand("getUsers", {"roles": roles, "onCall": oncall})


if isError(userinfo[0]):
    return_results(userinfo[0])

# build list of users that we can assign to
userinfo = userinfo[0]['Contents']
nonOOOlist = []
nonOOOlist = [x['username'] for x in userinfo if x['username'] not in list_info]


# Assign users to the Incident, if there is anyone to assign
if not nonOOOlist:
    return_error(message="No users to assign.")
else:
    # set the first user to be the owner
    owner = nonOOOlist[0]
    nonOOOlist.pop(0)
    demisto.executeCommand("setOwner", {"owner": owner})

    # set the rest of the users as participans
    for user in nonOOOlist:
        demisto.executeCommand("AssignAnalystToIncident", {"username": user})

    if nonOOOlist:
        return_results(f'Done, assigned {owner} as owner and {", ".join(nonOOOlist)} as prticipans.')
    else:
        return_results('Done, assigned {owner} as owner.')
