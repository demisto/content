import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import dateparser


def check_date(value, relative_date):
    settings = {'TO_TIMEZONE': 'UTC', 'RETURN_AS_TIMEZONE_AWARE': False}
    v = dateparser.parse(value, settings=settings)  # type: ignore[arg-type]
    da = dateparser.parse(relative_date, settings=settings)  # type: ignore[arg-type]
    return v > da  # type: ignore


def main():
    value = demisto.args().get('left')
    if isinstance(value, list):
        value = demisto.args().get('left')[0]

    relative_date = demisto.args().get('right')
    return_results(check_date(value, relative_date))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
