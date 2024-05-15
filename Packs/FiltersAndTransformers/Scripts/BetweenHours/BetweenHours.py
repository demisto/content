import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import dateparser


def is_between_hours(value, begin_time, end_time):
    # https://stackoverflow.com/questions/71256416/pytzusagewarning-doesnt-seem-to-go-away
    input_time = dateparser.parse(value, settings={'TIMEZONE': 'UTC'}).time()  # type: ignore
    start_time = dateparser.parse(begin_time, settings={'TIMEZONE': 'UTC'}).time()  # type: ignore
    end_time = dateparser.parse(end_time, settings={'TIMEZONE': 'UTC'}).time()  # type: ignore
    if start_time >= end_time:  # if the time range crosses midnight.
        return start_time <= input_time or input_time <= end_time
    return start_time <= input_time <= end_time


if __name__ in ('__main__', '__builtin__', 'builtins'):
    args = demisto.args()
    value, begin_time, end_time = args['value'], args['begin_time'], args['end_time']

    result = is_between_hours(value, begin_time, end_time)

    output = {"value": value, "begin_time": begin_time, "end_time": end_time, "result": result}
    human_readable = f'# BetweenHours\n' \
        f'The time *{value}* {"*IS*" if result else "*IS NOT*"} between *{begin_time}* and *{end_time}*'

    return_results(CommandResults(outputs_prefix="BetweenHours", readable_output=human_readable, outputs=result))
