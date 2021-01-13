import random
from CommonServerPython import *


def main():
    # args
    list_name = demisto.getArg("listname")
    oncall = demisto.getArg("oncall")
    roles = demisto.getArg("roles")
    assign_all = False if demisto.args().get('assignAll') == 'false' else True

    # get xsoar users
    userinfo = demisto.executeCommand("getUsers", {"roles": roles, "onCall": oncall})

    if isError(userinfo[0]):
        return_results(userinfo[0])

    # get OOO users
    ooo_list = demisto.executeCommand("GetUsersOOO", {"listname": list_name})
    if isError(ooo_list[0]):
        return_error(f'Error occurred while trying to get OOO users: {ooo_list[0].get("Contents")}')
    list_info = ooo_list[0].get('EntryContext').get('ShiftManagment.OOOUsers')
    list_info = [i['username'] for i in list_info]

    # Build list of users that we can assign to
    userinfo = userinfo[0]['Contents']

    non_OOO_list = [x['username'] for x in userinfo if x['username'] not in list_info]

    # Assign user to the Incident, if there is anyone to assign
    if not non_OOO_list:
        return_error(message="No users to assign")

    elif assign_all:
        # set the first user to be the owner
        owner = non_OOO_list[0]
        non_OOO_list.pop(0)
        demisto.executeCommand("setOwner", {"owner": owner})

        # set the rest of the users as participans
        for user in non_OOO_list:
            demisto.executeCommand("AssignAnalystToIncident", {"username": user})

        if non_OOO_list:
            return_results(f'Done, assigned {owner} as owner and {", ".join(non_OOO_list)} as prticipans.')
        else:
            return_results(f'Done, assigned {owner} as owner.')
    else:
        rand_user = random.choice(non_OOO_list)
        demisto.executeCommand("setOwner", {"owner": rand_user})
        return_results(f"Done, assigned {rand_user} as owner")


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
