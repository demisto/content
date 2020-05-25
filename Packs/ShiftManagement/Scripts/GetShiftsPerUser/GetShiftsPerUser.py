import operator
from functools import reduce
from typing import Dict, List

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *





def main():
    user_id = demisto.args()['userId']
    get_roles_response: List = demisto.executeCommand('getRoles', {})
    if is_error(get_roles_response):
        return_error(f'Failed to get roles: {str(get_error(get_roles_response))}')

    shifts_per_user: Dict[str, int] = {}
    get_users_response: List = demisto.executeCommand('getUsers', {})
    if is_error(get_roles_response):
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
