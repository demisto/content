import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''

import pytz

''' GLOBAL VARIABLES '''
args = demisto.args()

''' Helper Code '''


def determine_correct_format(time, fmt):
    time = datetime.strptime(time, fmt)

    return time


def convert_UTC_Timezone(time, convert_to_timezone, fmt):
    # set two timezones we want to work with
    desired_timezone = pytz.timezone(f'{convert_to_timezone}')

    # convert me to desired timezone
    desired_time = time.astimezone(desired_timezone).strftime(fmt)

    return desired_time


''' MAIN '''


def main():
    try:
        # Get Args
        time = args.get('value')
        convert_to_timezone = args.get('timezone')
        fmt = args.get('format')

        # Convert UTC to correct format
        utc_time = determine_correct_format(time, fmt)

        # Convert to desired Timezone from UTC
        desired_time = convert_UTC_Timezone(utc_time, convert_to_timezone, fmt)

        return_results(str(desired_time))

    except Exception as e:
        return_error(f'Error: {e}')


''' Script Starts Here'''
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
