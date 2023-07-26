import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import dateparser


def is_between_dates(value, begin_date, end_date):
    input_time = dateparser.parse(value)
    start_time = dateparser.parse(begin_date)
    end_time = dateparser.parse(end_date)

    return start_time <= input_time <= end_time  # type: ignore


if __name__ in ('__main__', '__builtin__', 'builtins'):
    args = demisto.args()
    value, begin_date, end_date = args['value'], args['begin_date'], args['end_date']

    result = is_between_dates(value, begin_date, end_date)

    output = {"value": value, "begin_date": begin_date, "end_date": end_date, "result": result}
    human_readable = f'# BetweenDates\n' \
        f'The date *{value}* {"*IS*" if result else "*IS NOT*"} between *{begin_date}* and *{end_date}*'

    return_results(CommandResults(outputs_prefix="BetweenDates", readable_output=human_readable, outputs=result))
