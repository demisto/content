import math
from CommonServerPython import *  # noqa: F401

text_widget = ''

today_week_day = datetime.today().weekday()
today_week_day = 0 if today_week_day == 6 else today_week_day + 1


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

                if shift_from < datetime.today() and shift_to > datetime.today():
                    # found the current shift
                    diff = shift_to - datetime.today()
                    hours = math.floor(diff.seconds / 3600)
                    minutes = round(diff.seconds / 60 % 60)
                    text_widget = f'{hours:02d}:{minutes:02d}'
                    break

widget = TextWidget(text=f'Time left to the shift: {text_widget}')
return_results(widget)
