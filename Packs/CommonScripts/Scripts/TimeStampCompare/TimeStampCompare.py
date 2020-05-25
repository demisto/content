import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

from dateutil.parser import parse


EQUAL = 'equal'
BEFORE = 'before'
AFTER = 'after'

TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%S%Z'
DT_STRING = "TimeStampCompare(val.TestedTime && val.TestedTime == obj.TestedTime && " \
            "val.ComparedTime && val.ComparedTime == obj.ComparedTime)"


def time_stamp_compare_command(args):
    tested_time = args.get('tested_time')
    values_to_compare = argToList(args.get('values_to_compare'))

    results = []
    parsed_tested_time = parse(tested_time)
    for compared_time in values_to_compare:
        parsed_compared_time = parse(compared_time)
        result = compare_times(parsed_compared_time, parsed_tested_time)

        results.append({
            "TestedTime": parsed_tested_time.strftime(TIMESTAMP_FORMAT),
            "ComparedTime": parsed_compared_time.strftime(TIMESTAMP_FORMAT),
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
    if parsed_compared_time > parsed_tested_time:
        result = BEFORE
    elif parsed_compared_time < parsed_tested_time:
        result = AFTER
    else:
        result = EQUAL

    return result


def main():
    try:
        return_outputs(*time_stamp_compare_command(demisto.args()))
    except Exception as ex:
        return_error(f'Failed to execute TimeStampCompare. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
