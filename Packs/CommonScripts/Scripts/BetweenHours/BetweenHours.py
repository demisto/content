import dateparser
import demistomock as demisto
from CommonServerPython import *


def is_between_hours(value, begin_time, end_time):
    input_time = dateparser.parse(value).time()  # type: ignore
    start_time = dateparser.parse(begin_time).time()  # type: ignore
    end_time = dateparser.parse(end_time).time()  # type: ignore

    return start_time <= input_time <= end_time


if __name__ in ('__main__', '__builtin__', 'builtins'):
    args = demisto.args()
    value, begin_time, end_time = args['value'], args['begin_time'], args['end_time']

    result = is_between_hours(value, begin_time, end_time)

    output = {"value": value, "begin_time": begin_time, "end_time": end_time, "result": result}
    human_readable = f'# BetweenHours\n' \
        f'The time *{value}* {"*IS*" if result else "*IS NOT*"} between *{begin_time}* and *{end_time}*'

    return_results(CommandResults(outputs_prefix="BetweenHours", readable_output=human_readable, outputs=result))
