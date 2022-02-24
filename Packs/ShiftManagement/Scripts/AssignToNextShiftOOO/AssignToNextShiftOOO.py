import random
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

    # Get Away Users
    away_users_response = demisto.executeCommand("GetAwayUsers", {})
    if is_error(away_users_response) or not away_users_response:
        return_error(f'Failed to get away users: {str(get_error(away_users_response))}')
    away_users: List[Dict] = away_users_response[0].get('EntryContext', {}).get('AwayUsers', [])
    away_user_names: List[str] = [away_user['username'] for away_user in away_users] if away_users else []
    # Build list of available users
    non_OOO_list = [x['username'] for x in users_on_call if
                    x['username'] not in list_info and x['username'] not in away_user_names]

    # Assign on call users to the Incidents, if there is anyone to assign
    if not non_OOO_list:
        return_error(message="No on call users to assign")
    else:
        incident_ids = argToList(demisto.args().get('incidentIds'))

        for incident_id in incident_ids:
            rand_user = random.choice(non_OOO_list)
            demisto.results(demisto.executeCommand("setIncident", {"id": str(incident_id), "owner": rand_user}))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
