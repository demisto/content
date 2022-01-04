import random
from CommonServerPython import *


def main():
    # args
    list_name = demisto.getArg("listname")
    oncall = demisto.getArg("oncall")
    roles = demisto.getArg("roles")
    assign_all = argToBoolean(demisto.getArg("assignAll"))

    # get xsoar users
    userinfo = demisto.executeCommand("getUsers", {"roles": roles, "onCall": oncall})
    if is_error(userinfo):
        return_error(f'Failed to get users: {str(get_error(userinfo))}')

    # get OOO users
    ooo_list = demisto.executeCommand("GetUsersOOO", {"listname": list_name})
    if isError(ooo_list):
        return_error(f'Failed to get users out of office: {str(get_error(ooo_list))}')
    list_info = ooo_list[0].get('EntryContext').get('ShiftManagment.OOOUsers')
    list_info = [i['username'] for i in list_info]

    # Get Away Users
    away_users_response = demisto.executeCommand("GetAwayUsers", {})
    if is_error(away_users_response) or not away_users_response:
        return_error(f'Failed to get away users: {str(get_error(away_users_response))}')
    away_users: List[Dict] = away_users_response[0].get('EntryContext', {}).get('AwayUsers', [])
    away_user_names: List[str] = [away_user['username'] for away_user in away_users] if away_users else []
    # Build list of users that we can assign to
    userinfo = userinfo[0]['Contents']

    non_OOO_list = [x['username'] for x in userinfo if
                    x['username'] not in list_info and x['username'] not in away_user_names]

    # Assign user to the Incident, if there is anyone to assign
    if not non_OOO_list:
        return_error(message="No users to assign")

    elif assign_all:
        # set the first user to be the owner
        owner = non_OOO_list[0]
        non_OOO_list.pop(0)
        set_owner_res = demisto.executeCommand("setOwner", {"owner": owner})
        if isError(set_owner_res):
            return_error(f'Failed to set {owner} as owner: {str(get_error(set_owner_res))}')
        # set the rest of the users as participans
        for user in non_OOO_list:
            assign_res = demisto.executeCommand("AssignAnalystToIncident", {"username": user})
            if isError(assign_res):
                return_error(f'Failed to assign {user} to incident: {str(get_error(assign_res))}')

        if non_OOO_list:
            return_results(f'Done, assigned {owner} as owner and {", ".join(non_OOO_list)} as prticipans.')
        else:
            return_results(f'Done, assigned {owner} as owner.')
    else:
        rand_user = random.choice(non_OOO_list)
        set_owner_res = demisto.executeCommand("setOwner", {"owner": rand_user})
        if isError(set_owner_res):
            return_error(f'Failed to set {rand_user} as owner: {str(get_error(set_owner_res))}')
        return_results(f"Done, assigned {rand_user} as owner")


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
