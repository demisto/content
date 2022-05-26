import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

import dateparser


EQUAL = 'equal'
BEFORE = 'before'
AFTER = 'after'

TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%S%Z'
DT_STRING = "TimeStampCompare(val.TestedTime && val.TestedTime == obj.TestedTime && " \
            "val.ComparedTime && val.ComparedTime == obj.ComparedTime)"


def time_stamp_compare_command(args):
    tested_time = args.get('tested_time')
    values_to_compare = argToList(args.get('values_to_compare'))
    time_format = args.get('time_format', None)
    if time_format == '':
        time_format = None
    elif time_format is not None:
        time_format = [time_format]

    results = []
    parsed_tested_time = dateparser.parse(tested_time, date_formats=time_format, settings={
        'TIMEZONE': 'UTC',
        'RELATIVE_BASE': datetime(datetime.now().year, 1, 1)
    })
    for compared_time in values_to_compare:
        parsed_compared_time = dateparser.parse(compared_time, date_formats=time_format, settings={
            'TIMEZONE': 'UTC',
            'RELATIVE_BASE': datetime(datetime.now().year, 1, 1)
        })
        assert parsed_compared_time is not None and parsed_tested_time is not None
        result = compare_times(parsed_compared_time.timestamp(), parsed_tested_time.timestamp())

        results.append({
            "TestedTime": tested_time,
            "ComparedTime": compared_time,
            "Result": result
        })

    human_readable = tableToMarkdown("Timestamp compare", results, ['TestedTime', 'ComparedTime', 'Result'])

    return (
        human_readable,
        {
            DT_STRING: results
        },
        results
    )


def compare_times(parsed_compared_time, parsed_tested_time):
    if parsed_compared_time < parsed_tested_time:
        result = BEFORE
    elif parsed_compared_time > parsed_tested_time:
        result = AFTER
    else:
        result = EQUAL

    return result


def main():
    try:
        return_outputs(*time_stamp_compare_command(demisto.args()))
    except Exception as exc:
        return_error(f'Failed to execute TimeStampCompare. Error: {str(exc)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
