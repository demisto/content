from CommonServerPython import *


def main():
    today_week_day = datetime.today().weekday()
    today_week_day = 0 if today_week_day == 6 else today_week_day + 1
    total_seconds = ''

    get_roles_response = demisto.executeCommand('getRoles', {})
    if is_error(get_roles_response):
        demisto.error(f'Failed to get roles: {str(get_error(get_roles_response))}')
    else:
        roles = get_roles_response[0]['Contents']

        for role in roles:
            shifts = role.get('shifts') or []
            for shift in shifts:
                shift_from_day = shift.get('fromDay')
                shift_to_day = shift.get('toDay')

                if shift_from_day <= today_week_day and shift_to_day >= today_week_day:

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
                        total_seconds = round(diff.total_seconds())
                        break

    widget = [{'name': '', 'data': [total_seconds]}]
    return_results(json.dumps(widget))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
