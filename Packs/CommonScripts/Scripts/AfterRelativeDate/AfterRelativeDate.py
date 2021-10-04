import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import dateparser


def check_date(value, relative_date):
    v = dateparser.parse(value)
    da = dateparser.parse(relative_date)
    if v > da:
        return True
    else:
        return False


def main():
    value = demisto.args().get('left')
    if isinstance(value, list):
        value = demisto.args().get('left')[0]

    relative_date = demisto.args().get('right')
    return_results(check_date(value, relative_date))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
