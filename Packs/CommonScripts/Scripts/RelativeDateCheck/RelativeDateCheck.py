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
    value = demisto.args()['left']
    if type(value) is list:
        value = demisto.args()['left'][0]

    relative_date = demisto.args()['right']
    return_results(check_date(value, relative_date))


if __name__ == '__main__':
    main()