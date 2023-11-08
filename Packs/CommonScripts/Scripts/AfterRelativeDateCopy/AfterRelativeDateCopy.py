import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import dateparser


def check_date(value, relative_date):
    v = dateparser.parse(value)
    da = dateparser.parse(relative_date)
    return v > da  # type: ignore


def main():
    # just for test
    value = demisto.args().get('left')
    if isinstance(value, list):
        value = demisto.args().get('left')[0]

    relative_date = demisto.args().get('right')
    return_results(check_date(value, relative_date))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
