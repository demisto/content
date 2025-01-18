import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from calendar import timegm
from datetime import datetime, timedelta, tzinfo


EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000


ZERO = timedelta(0)
HOUR = timedelta(hours=1)


class UTC(tzinfo):
    """UTC"""

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO


utc = UTC()  # type: ignore[abstract]


def dt_to_filetime(dt):
    """Converts a datetime to Microsoft filetime format. If the object is
    time zone-naive, it is forced to UTC before conversion.
    >>> "%.0f" % dt_to_filetime(datetime(2009, 7, 25, 23, 0))
    '128930364000000000'
    >>> dt_to_filetime(datetime(1970, 1, 1, 0, 0, tzinfo=utc))
    116444736000000000L
    >>> dt_to_filetime(datetime(1970, 1, 1, 0, 0))
    116444736000000000L
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=utc)
    # return EPOCH_AS_FILETIME + (timegm(dt.timetuple()) * HUNDREDS_OF_NANOSECONDS)
    ad_time = EPOCH_AS_FILETIME + (timegm(dt.timetuple()) * HUNDREDS_OF_NANOSECONDS)
    ad_time_str = str(ad_time)
    entry = ({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": ad_time,
        "HumanReadable": ad_time,
        "EntryContext": {"ADFileTime": ad_time, "ADFileTimeStr": ad_time_str}
    })
    return entry


'''MAIN FUNCTION'''


def main():
    try:
        args = demisto.args()
        days_ago = args['days_ago']
        new_date = datetime.today() - timedelta(int(days_ago))
        dt = new_date.replace(hour=0, minute=0, second=0, microsecond=0)
        entry = dt_to_filetime(dt)
        demisto.results(entry)
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute script.\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
