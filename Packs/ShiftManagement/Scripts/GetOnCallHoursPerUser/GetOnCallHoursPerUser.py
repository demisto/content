import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import List, Dict


def count_hours_in_shift(shift: Dict) -> int:
    from_day = shift.get('fromDay', 0)
    to_day = shift.get('toDay', 0)
    from_hour = shift.get('fromHour', 0)
    to_hour = shift.get('toHour', 0)
    hours_in_shift = 0
    for day in range(from_day, to_day + 1):
        if day == from_day:
            if day == to_day:
                hours_in_shift += (to_hour - from_hour)
            else:
                hours_in_shift += (24 - from_hour)
        elif day == to_day:
            hours_in_shift += to_hour
        else:
            hours_in_shift += 24
    return hours_in_shift


def main():
    get_roles_response: List = demisto.executeCommand('getRoles', {})
    if is_error(get_roles_response):
        demisto.error(f'Failed to get roles: {str(get_error(get_roles_response))}')
    else:
        hours_per_user: Dict[str, int] = {}
        roles = get_roles_response[0]['Contents']
        for role in roles:
            get_users_response: List = demisto.executeCommand('getUsers', {'roles': role.get('name')})
            if is_error(get_roles_response):
                demisto.error(f'Failed to get users: {str(get_error(get_users_response))}')
            else:
                role_on_call_hours = 0
                shifts = role.get('shifts') or []
                for shift in shifts:
                    role_on_call_hours += count_hours_in_shift(shift)

                role_users = get_users_response[0]['Contents']
                for user in role_users:
                    username = user.get('name')
                    if username in hours_per_user:
                        hours_per_user[username] += role_on_call_hours
                    else:
                        hours_per_user[username] = role_on_call_hours

        data = [
            {'name': user, 'data': [number_of_hours], 'groups': [{'name': user, 'data': [number_of_hours]}]}
            for user, number_of_hours in hours_per_user.items()
        ]
        demisto.results(json.dumps(data))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
