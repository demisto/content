""" A widget that have 3 stages:

1) invalid time range: return an error message.
2) valid time range:
    2.1) invalid license: return a hint for a new license download link.

"""

import pytz
import random

import demistomock as demisto
from CommonServerPython import *

WRONG_DATE_RANGE_HINT = '''
## You cannot drive a vehicle without a driver's license.
## You cannot practice medicine without a medical license.
## You cannot practice law without a law license.
## You cannot practice security without an XSOAR license.
'''

INVALID_LICENSE_HINT = '''
# Welcome to the twilight zone
#### Looks like we run out of money and lost our XSOAR license.

#### Don't be alarmed, we can handle it together.
#### goto the [secret place]()
'''

SUCCESS_MESSAGE = '''
Now that you have the license issue sorted out.
you have the power of automation!
please help me with my failing task.

> with great power comes great responsibility!
    - B. parker
  
'''

VICTORY_MESSAGE = '''
'''


def utc_to_time(naive: datetime, time_zone: str = 'Asia/Tel_Aviv'):
    return naive.replace(tzinfo=pytz.utc).astimezone(pytz.timezone(time_zone))


def is_correct_date_range(time_from: datetime, time_to: datetime):
    validate = [
        time_from.date().strftime('%Y-%m-%d') == '2020-10-31',
        time_to.date().strftime('%Y-%m-%d') == '2020-12-25',
    ]

    demisto.debug(f'check_time_frame: {validate}')
    return all(validate)


def is_valid_license_temp(time_from: datetime, time_to: datetime):
    validate = [
        time_from.date().strftime('%Y-%m-%d') == '2020-12-01',
        time_to.date().strftime('%Y-%m-%d') == '2020-12-25',
    ]

    demisto.debug(f'WidgetLicenseErrorGifs - is_correct_date_range: {validate}')
    return all(validate)


def is_valid_license():
    res = demisto.executeCommand('demisto-api-get', {'uri': '/license'})
    if is_error(res):
        raise DemistoException('Failed to run command: demisto-api-get')

    license_info = res[0]['Contents']
    demisto.info(f'license info:\n {license_info}')

    if dict_safe_get(license_info, ['customFields', 'EscapeRoomKey']):
        return True

    return False


def v_for_vendetta(time_from: datetime, time_to: datetime):
    validate = [t.day == 5 and t.month == 11 for t in (time_from, time_to)]

    if any(validate):
        return '\n\n> **Remember remember the fifth of November**\n - V for Vendetta'

    return ''


def is_wednesday(time_from: datetime, time_to: datetime):
    validate = [t.weekday == 2 for t in (time_from, time_to)]

    if any(validate):
        return '\n\nP.S.\nAre you wearing Bordeaux? your chosen dates say you should.'

    return ''


# MAIN FUNCTION #


def main():
    try:
        args = demisto.args()
        demisto.info(str(args))
        time_from = dateparser.parse(args.get('from', '0001-01-01T00:00:00Z'))
        local_time_from = utc_to_time(time_from)
        time_to = dateparser.parse(args.get('to', '0001-01-01T00:00:00Z'))
        local_time_to = utc_to_time(time_to)

        if not is_correct_date_range(local_time_from, local_time_to):
            text = WRONG_DATE_RANGE_HINT
        # elif not is_valid_license():
        elif not is_valid_license_temp(local_time_from, local_time_to):
            text = INVALID_LICENSE_HINT
        else:
            text = SUCCESS_MESSAGE

        return_results(TextWidget(text))

    except Exception as exc:  # pylint: disable=W0703
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute Widget. Error: {str(exc)}')


# ENTRY POINT #


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
