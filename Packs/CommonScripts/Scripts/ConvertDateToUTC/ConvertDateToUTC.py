import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import pytz


''' MAIN FUNCTION '''


def main():
    try:
        date = demisto.getArg('date')
        date_format = demisto.getArg('date_format')
        time_zone = demisto.getArg('timezone')

        time_zone = pytz.timezone(time_zone)

        # Initialize datetime
        date = datetime.strptime(date, date_format)

        # Convert to timezone aware date
        localized_date = time_zone.localize(date)

        # Convert to UTC timezone
        utc_converted_date = localized_date.astimezone(pytz.timezone("UTC"))
        epoch_time = utc_converted_date.strftime('%s')

        # Initialize entry context to return
        entry_context = {
            'UTCDate': utc_converted_date.strftime(date_format),
            'UTCDateEpoch': epoch_time,
        }

        return_results({
            'Contents': json.dumps(entry_context),
            'ContentsFormat': formats['json'],
            'EntryContext': entry_context,
        })

    except Exception as exc:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ConvertDateToUTC. Error: {str(exc)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
