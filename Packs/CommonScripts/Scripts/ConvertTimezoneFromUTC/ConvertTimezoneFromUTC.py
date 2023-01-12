import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import pytz
from traceback import format_exc


def determine_correct_format(time: str, fmt: str) -> datetime:
    time = datetime.strptime(time, fmt)
    return time


def convert_UTC_Timezone_command(time: datetime, timezone: str, fmt: str) -> CommandResults:
    # set two timezones we want to work with
    desired_timezone = pytz.timezone(timezone)

    # convert me to desired timezone
    desired_time = time.astimezone(desired_timezone).strftime(fmt)
    return CommandResults(
        readable_output=desired_time
    )


def main():     # pragma: no cover
    try:
        # Get Args
        args = demisto.args()
        time = args.get('value')
        timezone = args.get('timezone')
        fmt = args.get('format')

        # Convert UTC string to a datetime type
        utc_time = determine_correct_format(time=time, fmt=fmt)

        # Convert to desired Timezone and format
        return_results(convert_UTC_Timezone_command(time=utc_time, timezone=timezone, fmt=fmt))

    except Exception as e:
        demisto.error(format_exc())
        return_error(f'ConvertTimezone command failed. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
