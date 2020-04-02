import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import List

HOURS_DAYS_HEADER = 'Hours / Days'
SUNDAY_HEADER = 'Sunday'
MONDAY_HEADER = 'Monday'
TUESDAY_HEADER = 'Tuesday'
WEDNESDAY_HEADER = 'Wednesday'
THURSDAY_HEADER = 'Thursday'
FRIDAY_HEADER = 'Friday'
SATURDAY_HEADER = 'Saturday'

DAY_NUM_TO_DAY_HEADER = {
    0: SUNDAY_HEADER,
    1: MONDAY_HEADER,
    2: TUESDAY_HEADER,
    3: WEDNESDAY_HEADER,
    4: THURSDAY_HEADER,
    5: FRIDAY_HEADER,
    6: SATURDAY_HEADER
}


def main():
    get_roles_response: List = demisto.executeCommand('getRoles', {})
    if is_error(get_roles_response):
        demisto.error(f'Failed to get roles: {str(get_error(get_roles_response))}')
    else:
        roles = get_roles_response[0]['Contents']

        shifts_table = [
            {
                HOURS_DAYS_HEADER: f'__{hour}:00 - {hour + 1}:00__',
                SUNDAY_HEADER: '',
                MONDAY_HEADER: '',
                TUESDAY_HEADER: '',
                WEDNESDAY_HEADER: '',
                THURSDAY_HEADER: '',
                FRIDAY_HEADER: '',
                SATURDAY_HEADER: ''
            } for hour in range(24)
        ]

        for role in roles:
            role_name = role.get('name', '')
            shifts = role.get('shifts') or []
            for shift in shifts:
                from_day = shift.get('fromDay', 0)
                to_day = shift.get('toDay', 0)
                from_hour = shift.get('fromHour', 0)
                to_hour = shift.get('toHour', 0)
                for hour in range(from_hour, to_hour):
                    for day in range(from_day, to_day + 1):
                        if shifts_table[hour][DAY_NUM_TO_DAY_HEADER[day]]:
                            shifts_table[hour][DAY_NUM_TO_DAY_HEADER[day]] += f', {role_name}'
                        else:
                            shifts_table[hour][DAY_NUM_TO_DAY_HEADER[day]] = role_name

        demisto.results(
            tableToMarkdown(
                name='Roles Per Shift',
                t=shifts_table,
                headers=[HOURS_DAYS_HEADER, SUNDAY_HEADER, MONDAY_HEADER, TUESDAY_HEADER,
                         WEDNESDAY_HEADER, THURSDAY_HEADER, FRIDAY_HEADER, SATURDAY_HEADER]
            )
        )


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
