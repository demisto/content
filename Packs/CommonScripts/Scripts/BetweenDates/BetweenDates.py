import dateparser
import demistomock as demisto
from CommonServerPython import *


def is_between_dates(value, begin_date, end_date):
    input_time = dateparser.parse(value)
    start_time = dateparser.parse(begin_date)
    end_time = dateparser.parse(end_date)

    return start_time <= input_time <= end_time


if __name__ in ('__main__', '__builtin__', 'builtins'):
    return_results(is_between_dates(**demisto.args()))
