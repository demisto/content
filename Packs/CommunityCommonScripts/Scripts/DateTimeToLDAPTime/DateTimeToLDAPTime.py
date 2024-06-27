import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from datetime import datetime
from traceback import format_exc


def convert_time_command(time):
    # ((current time - epoch start date) in seconds + seconds since 1/1/1601) * 10000000 (to get nanoseconds)
    res = ((time - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds() + 11644473600) * 10000000
    return int(res)


def main():
    try:
        # Get Args
        args = demisto.args()
        str_utc_time = args.get('value')
        fmt = args.get('input_format')

        # Convert UTC time string to a datetime type
        utc_time = datetime.strptime(str_utc_time, fmt)

        # Convert to LDAP time
        return_results(convert_time_command(time=utc_time))

    except Exception as e:
        demisto.error(format_exc())
        return_error(f'Convert DateTimeToLDAPTime to LDAP Time command failed. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
