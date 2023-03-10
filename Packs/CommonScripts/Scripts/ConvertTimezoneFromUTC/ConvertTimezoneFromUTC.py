import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import pytz
from traceback import format_exc


def determine_correct_format(time: str, fmt: str) -> datetime:
    time_as_datetime = datetime.strptime(time, fmt)
    return time_as_datetime


def convert_UTC_Timezone_command(time: datetime, timezone: str, fmt: str) -> str:
    desired_timezone = pytz.timezone(timezone)

    # convert me to desired timezone
    desired_time = time.astimezone(desired_timezone).strftime(fmt)
    return desired_time


def main():     # pragma: no cover
    try:
        # Get Args
        args = demisto.args()
        str_utc_time = args.get('value')
        requested_timezone = args.get('timezone')
        fmt = args.get('format')

        # Convert UTC time string to a datetime type
        utc_time = determine_correct_format(time=str_utc_time, fmt=fmt)

        # Convert to requested Timezone and format
        return_results(convert_UTC_Timezone_command(time=utc_time, timezone=requested_timezone, fmt=fmt))

    except Exception as e:
        demisto.error(format_exc())
        return_error(f'ConvertTimezone command failed. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
