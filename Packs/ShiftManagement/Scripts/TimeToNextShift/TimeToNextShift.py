from CommonServerPython import *


def get_time_to_next_shift(roles):
    today_week_day = datetime.today().weekday()
    # transform python weekday to demisto shift weekday(monday in python is 0 and in demisto is 1)
    today_week_day = 0 if today_week_day == 6 else today_week_day + 1

    for role in roles:
        shifts = role.get('shifts') or []
        for shift in shifts:
            shift_from_day = shift.get('fromDay')
            shift_to_day = shift.get('toDay')

            if shift_from_day <= today_week_day <= shift_to_day:

                # get the time when the shift starts
                delta = shift_from_day - today_week_day
                shift_from = datetime.today() + timedelta(days=delta)
                shift_from = shift_from.replace(minute=shift.get('fromMinute'), hour=shift.get('fromHour'), second=0)

                # get the time when the shift ends
                delta = shift_to_day - today_week_day
                shift_to = datetime.today() + timedelta(days=delta)
                shift_to = shift_to.replace(minute=shift.get('toMinute'), hour=shift.get('toHour'), second=0)

                if shift_from < datetime.today() < shift_to:
                    # found the current shift
                    diff = shift_to - datetime.today()
                    return round(diff.total_seconds())
    return 0


def main():
    get_roles_response = demisto.executeCommand('getRoles', {})
    if is_error(get_roles_response):
        demisto.error(f'Failed to get roles: {str(get_error(get_roles_response))}')
    else:
        roles = get_roles_response[0]['Contents']
        widget = [{'name': '', 'data': [get_time_to_next_shift(roles)]}]
        return_results(json.dumps(widget))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
