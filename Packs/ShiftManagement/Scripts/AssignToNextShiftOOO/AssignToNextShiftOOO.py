from CommonServerPython import *

# check if we have any users on call to assign to
users_on_call = demisto.executeCommand("getUsers", {"onCall": "true"})[0]['Contents']

# if we don't have on shift users, return error, else reassign the provided incident id's to the on shift analysts
if not users_on_call:
    return_error("No users on shift")

# get the out of office list, and the current xsoar users
list_name = demisto.getArg("listname")
list_info = json.loads(demisto.executeCommand("getList", {"listName": list_name})[0]['Contents'])
list_info = [i['user'] for i in list_info]

# Build list of available users
non_OOO_list = []
non_OOO_list = [x['username'] for x in users_on_call if x['username'] not in list_info]

# Assign on call users to the Incidents, if there is anyone to assign
if not non_OOO_list:
    return_error(message="No on call users to assign")
else:
    incident_ids = demisto.args().get('incidentIds')
    demisto.results(demisto.executeCommand("executeCommandAt", {"command": "AssignAnalystToIncidentOOO", "arguments": {
                    "oncall": "true", "listname": list_name}, "incidents": incident_ids}))
