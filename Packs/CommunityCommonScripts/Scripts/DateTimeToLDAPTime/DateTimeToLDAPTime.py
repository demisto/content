import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import dateparser


def convert_time(time_to_convert: Optional[datetime]):
    if time_to_convert:
        # ((current time - epoch start date) in seconds + seconds since 1/1/1601) * 10000000 (to get nanoseconds)
        ldap_time = ((time_to_convert - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds() + 11644473600) * 10000000
        return str(int(ldap_time))
    return time_to_convert


def main():
    try:
        # Get Args
        args = demisto.args()
        str_utc_time = args['value']  # direct access, since this argument is required

        # Convert UTC time string to a datetime type
        utc_time = dateparser.parse(str_utc_time)

        # Convert to LDAP time
        return_results(convert_time(time_to_convert=utc_time))

    except Exception as e:
        return_error(f'Convert DateTimeToLDAPTime to LDAP Time command failed. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
