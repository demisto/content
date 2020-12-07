import demistomock as demisto
from dateutil.parser import ParserError, parse
from datetime import timezone


def parse_datestring_to_iso(date_value: str, day_first: bool, year_first: bool, fuzzy: bool) -> str:
    try:
        datetime_obj = parse(date_value, dayfirst=day_first, yearfirst=year_first, fuzzy=fuzzy)
        if not datetime_obj.tzinfo:
            datetime_obj = datetime_obj.replace(tzinfo=timezone.utc)
        return datetime_obj.isoformat()
    except ParserError as e:
        demisto.error(f'ParserError occurred: {e}\n Returning the original date string.')
        date_string = date_value
    return date_string


def main():
    args = demisto.args()
    date_value = args.get('value')
    day_first = args.get('dayfirst', 'True').lower() == 'true'
    year_first = args.get('yearfirst', 'False').lower() == 'true'
    fuzzy = args.get('fuzzy', 'True').lower() == 'true'
    iso_string = parse_datestring_to_iso(date_value, day_first, year_first, fuzzy)
    demisto.results(iso_string)


# python2 uses __builtin__ python3 uses builtins
if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
