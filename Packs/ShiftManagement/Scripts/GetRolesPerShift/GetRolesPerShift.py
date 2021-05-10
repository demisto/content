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


def hour_in_shift(day, hour, shift):
    check_time_bottom = day * 24 * 60 + hour * 60
    check_time_top = day * 24 * 60 + hour * 60 + 59
    shift_from_time = shift.get('fromDay', 0) * 24 * 60 + shift.get('fromHour', 0) * 60 + shift.get('fromMinute', 0)
    shift_to_time = shift.get('toDay', 0) * 24 * 60 + shift.get('toHour', 0) * 60 + shift.get('toMinute', 0)
    return (shift_from_time <= check_time_bottom < shift_to_time) or \
           (shift_from_time <= check_time_top < shift_to_time)


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

        for day in range(7):
            for hour in range(24):
                collected_roles = []
                for role in roles:
                    role_name = role.get('name', '')
                    shifts = role.get('shifts') or []
                    for shift in shifts:
                        if hour_in_shift(day, hour, shift):
                            collected_roles.append(role_name)
                            break
                shifts_table[hour][DAY_NUM_TO_DAY_HEADER[day]] = ', '.join(collected_roles)

        widget = TextWidget(text='Roles Per Shift\n' + tableToMarkdown(
            name='',
            t=shifts_table,
            headers=[HOURS_DAYS_HEADER, SUNDAY_HEADER, MONDAY_HEADER, TUESDAY_HEADER,  # disable-secrets-detection
                     WEDNESDAY_HEADER, THURSDAY_HEADER, FRIDAY_HEADER, SATURDAY_HEADER]
        ))
        return_results(widget)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
