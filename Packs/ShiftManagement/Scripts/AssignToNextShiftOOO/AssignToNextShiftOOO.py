from CommonServerPython import *


def main():
    # check if we have any users on call to assign to
    users_on_call = demisto.executeCommand("getUsers", {"onCall": "true"})
    if is_error(users_on_call):
        return_error(f'Failed to get users on call: {str(get_error(users_on_call))}')
    users_on_call = users_on_call[0]['Contents']

    # if we don't have on shift users, return error, else reassign the provided incident id's to the on shift analysts
    if not users_on_call:
        return_error("No users on shift")

    list_name = demisto.getArg("listname")

    # get OOO users
    ooo_list = demisto.executeCommand("GetUsersOOO", {"listname": list_name})
    if is_error(ooo_list):
        return_error(f'Failed to get users out of office: {str(get_error(ooo_list))}')
    list_info = ooo_list[0].get('EntryContext').get('ShiftManagment.OOOUsers')
    list_info = [i['username'] for i in list_info]

    # Build list of available users
    non_OOO_list = [x['username'] for x in users_on_call if x['username'] not in list_info]

    # Assign on call users to the Incidents, if there is anyone to assign
    if not non_OOO_list:
        return_error(message="No on call users to assign")
    else:
        incident_ids = demisto.args().get('incidentIds')
        demisto.results(demisto.executeCommand("executeCommandAt", {"command": "AssignAnalystToIncidentOOO", "arguments": {
                        "oncall": "true", "listname": list_name}, "incidents": incident_ids}))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
