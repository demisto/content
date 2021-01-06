import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# check if we have any users on call to assign to
users_on_call = demisto.executeCommand("getUsers", {"onCall": "true"})[0]['Contents']

# if we don't have on shift users, return error, else reassign the provided incident id's to the on shift analysts
if not users_on_call:
    return_error("No users on shift")

# get the out of office list, and the current xsoar users
listname = demisto.getArg("listname")
listinfo = json.loads(demisto.executeCommand("getList", {"listName": listname})[0]['Contents'])
listinfo = [i['user'] for i in listinfo]

# Build list of available users
nonOOOlist = []
nonOOOlist = [x['username'] for x in users_on_call if x['username'] not in listinfo]

# Assign on call users to the Incidents, if there is anyone to assign
if not nonOOOlist:
    return_error(message="No on call users to assign")
else:
    incident_id = demisto.args().get('incident_id')
    demisto.results(demisto.executeCommand("executeCommandAt", {"command": "AssignAnalystToIncidentOOO", "arguments": {
                    "oncall": "true", "listname": listname}, "incidents": incident_id}))
