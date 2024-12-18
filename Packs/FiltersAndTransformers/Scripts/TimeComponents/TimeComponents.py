import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re
from datetime import timezone, tzinfo, UTC
import dateparser
import pytz


def timezone_abbreviations(utc_offset: Optional[timedelta]) -> set[str]:
    tznames = set()
    if utc_offset is not None:
        now = datetime.now(pytz.utc)
        for tz in map(pytz.timezone, pytz.all_timezones_set):
            if (d := now.astimezone(tz)).utcoffset() == utc_offset:
                if tzname := d.tzname():
                    if tzname[0:1] not in ('+', '-'):
                        tznames.add(tzname)
    return tznames


def detect_time_zone(value: Any) -> tzinfo:
    if isinstance(value, int):
        return timezone(timedelta(minutes=value))

    if isinstance(value, str):
        value = value.strip()
        if value == 'Z':
            return timezone(timedelta(hours=0))
        elif m := re.fullmatch('([+-])([0-9]{1,2})(:?([0-9]{2}))?', value):
            # +H, +HMM, +HHMM, +H:MM, +HH:MM
            offset = ((int(m[2]) * 60) + int(m[4] or 0)) * (-1 if m[1] == '-' else 1)
            return timezone(timedelta(minutes=offset))
        elif m := re.match(r'(^|\s)(UTC|GMT)([+-])([0-9]{1,2})(:?([0-9]{2}))?($|\s)', value):
            # Includes: UTC+H, UTC+HMM, UTC+HHMM, UTC+H:MM, UTC+HH:MM
            offset = ((int(m[4]) * 60) + int(m[6] or 0)) * (-1 if m[3] == '-' else 1)
            return timezone(timedelta(minutes=offset))
        else:
            # Try to parse as zone info
            try:
                return pytz.timezone(value)
            except Exception:
                pass

            # Try to parse as time string
            try:
                d = dateparser.parse(value)
                if d is not None and d.tzinfo is not None:
                    return d.tzinfo
            except Exception:
                pass

    raise DemistoException(f'Unable to extract time zone - {value}')


def parse_date_time_value(value: Any) -> datetime:
    """ Parse a date time value

    :param value: The date or time to parse
    :return: aware datetime object
    """
    if value in [None, '']:
        return datetime.now(UTC)

    if isinstance(value, int):
        # Parse as time stamp
        try:
            # Considered the value as seconds > milliseconds > microseconds when it's too large (> uint max).
            # (Currently later than 2106-02-07 06:28:15)
            while value > 4294967295:
                value /= 1000

            return datetime.fromtimestamp(value).astimezone(UTC)
        except Exception as err:
            raise DemistoException(f'Error with input date / time - {err}')

    if isinstance(value, str):
        value = value.strip()
        try:
            # Parse as time stamp
            return parse_date_time_value(int(value))
        except (TypeError, ValueError):
            pass

    try:
        date_time = dateparser.parse(value)
        assert date_time is not None, f'could not parse {value}'

        if date_time.tzinfo is not None:
            return date_time

        date_time = dateparser.parse(value, settings={'TIMEZONE': 'UTC', 'RETURN_AS_TIMEZONE_AWARE': True})
        assert date_time is not None, f'could not parse {value}'
        return date_time
    except Exception as err:
        raise DemistoException(f'Error with input date / time - {err}')


def main():
    try:
        args = demisto.args()
        date_time = parse_date_time_value(args.get('value'))
        if time_zone := args.get('time_zone'):
            date_time = date_time.astimezone(detect_time_zone(time_zone))

        time_components = {
            'year': date_time.year,
            'year_4_digit': date_time.strftime('%Y'),
            'month': date_time.month,
            'month_3_letter': date_time.strftime('%b'),
            'month_full_name': date_time.strftime('%B'),
            'month_2_digit': date_time.strftime('%m'),
            'day': date_time.day,
            'day_2_digit': date_time.strftime('%d'),
            'day_of_week': int(date_time.strftime('%w')),
            'day_of_week_3_letter': date_time.strftime('%a'),
            'day_of_week_full_name': date_time.strftime('%A'),
            'day_of_year': int(date_time.strftime('%j')),
            'day_of_year_3_digit': date_time.strftime('%j'),
            'hour': date_time.hour,
            'hour_12_clock': (date_time.hour % 12) or 12,
            'hour_2_digit_24_clock': date_time.strftime('%H'),
            'hour_2_digit_12_clock': date_time.strftime('%I'),
            'hour_of_day': date_time.hour + (date_time.minute / 60) + (date_time.second / 60 / 60),
            'minute': date_time.minute,
            'minute_2_digit': date_time.strftime('%M'),
            'minute_of_day': (date_time.hour * 24) + date_time.minute + (date_time.second / 60),
            'second': date_time.second,
            'second_2_digit': date_time.strftime('%S'),
            'second_of_day': (date_time.hour * 24 * 60) + (date_time.minute * 60) + date_time.second,
            'millisecond': int(date_time.microsecond / 1000),
            'period_12_clock': date_time.strftime('%p'),
            'time_zone_hhmm': date_time.strftime('%z'),
            'time_zone_offset': (date_time.utcoffset() or timedelta(hours=0)).total_seconds() / 60,
            'time_zone_abbreviations': sorted(timezone_abbreviations(date_time.utcoffset())),
            'unix_epoch_time': int(date_time.timestamp()),
            'iso_8601': date_time.isoformat(),
            'y-m-d': f'{date_time.year}-{date_time.month}-{date_time.day}',
            'yyyy-mm-dd': f"{date_time.strftime('%Y-%m-%d')}",
            'h:m:s': f'{date_time.hour}:{date_time.minute}:{date_time.second}',
            'H:m:s': f'{(date_time.hour % 12) or 12}:{date_time.minute}:{date_time.second}',
            'hh:mm:ss': f"{date_time.strftime('%I:%M:%S')}",
            'HH:mm:ss': f"{date_time.strftime('%H:%M:%S')}",
        }

        if key := args.get('key'):
            if (component := time_components.get(key)) is None:
                raise DemistoException(f'No key is found in the time components - {key}')
            return_results(component)
        else:
            return_results(time_components)
    except Exception as err:
        # Don't return an error by return_error() as this is transformer.
        raise DemistoException(str(err))


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
