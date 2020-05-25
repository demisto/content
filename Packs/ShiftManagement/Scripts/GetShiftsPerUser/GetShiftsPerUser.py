import operator
from functools import reduce
from typing import Dict, List

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *



def main():
    user_id = demisto.args().get('userId', False)
    if not user_id:
        get_users_response: List = demisto.executeCommand("getUsers",
                                                          {"current": True})
        if is_error(get_users_response):
            return_error(
                f'Failed to get users: {str(get_error(get_users_response))}')
        contents = get_users_response[0]
        if contents and len(contents.get("Contents")) == 1:
            user_id = contents.get("Contents")[0].get("id")
        else:
            return_error(f'Failed to get users: User object is empty')

    get_roles_response: List = demisto.executeCommand('getRoles', {})
    if is_error(get_roles_response):
        return_error(f'Failed to get roles: {str(get_error(get_roles_response))}')

    shifts_per_user: Dict[str, int] = {}
    get_users_response: List = demisto.executeCommand('getUsers', {})
    if is_error(get_users_response):
        return_error(f'Failed to get users: {str(get_error(get_users_response))}')

    users = get_users_response[0]['Contents']
    user = [u for u in users if u.get("id", False) == user_id]
    if len(user) == 0:
        return_error(f'Failed to find user: {str(user_id)}')

    user = user[0]
    user_roles = user.get("allRoles", [])
    if len(user_roles) == 0:
        demisto.error(f'Failed to find roles for user: {str(user_id)}')
        demisto.results([])

    roles = get_roles_response[0]['Contents']
    shifts_of_user = [r.get("shifts") for r in roles if r.get("shifts", False) and r.get("name") in user_roles]
    if len(shifts_of_user) == 0:
        demisto.error(f'Failed to find shifts for user: {str(user_id)}')
        demisto.results([])

    demisto.results(json.dumps(shifts_of_user))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
