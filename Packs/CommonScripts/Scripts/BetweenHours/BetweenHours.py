import dateparser
import demistomock as demisto
from CommonServerPython import *


def is_between_hours(value, begin_time, end_time):
    input_time = dateparser.parse(value).time()  # type: ignore
    start_time = dateparser.parse(begin_time).time()  # type: ignore
    end_time = dateparser.parse(end_time).time()  # type: ignore

    return start_time <= input_time <= end_time


if __name__ in ('__main__', '__builtin__', 'builtins'):
    return_results(is_between_hours(**demisto.args()))
