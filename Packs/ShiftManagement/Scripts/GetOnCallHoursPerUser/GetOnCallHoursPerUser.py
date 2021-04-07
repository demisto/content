import operator
from functools import reduce
from typing import Dict, List

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


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
        get_users_response: List = demisto.executeCommand('getUsers', {})
        if is_error(get_users_response):
            demisto.error(f'Failed to get users: {str(get_error(get_users_response))}')
        else:
            users = get_users_response[0]['Contents']
            roles = get_roles_response[0]['Contents']
            for role in roles:
                role_on_call_hours = 0
                shifts = role.get('shifts') or []
                for shift in shifts:
                    role_on_call_hours += count_hours_in_shift(shift)
                role_users = map(
                    lambda role_user: role_user.get('name', ''),
                    filter(lambda u: role.get('name') in reduce(operator.add, u.get('roles', {}).values()), users)
                )
                for username in role_users:
                    if username in hours_per_user:
                        hours_per_user[username] += role_on_call_hours
                    else:
                        hours_per_user[username] = role_on_call_hours

        bar_widget = BarColumnPieWidget()
        for user, number_of_hours in hours_per_user.items():
            bar_widget.add_category(name=user, number=number_of_hours)

        return_results(bar_widget)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
