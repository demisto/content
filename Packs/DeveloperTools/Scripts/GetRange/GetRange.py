"""Base Script for Cortex XSOAR (aka Demisto)

This is an empty script with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

"""
import traceback
import demistomock as demisto
from CommonServerPython import CommandResults, return_results, return_error


def get_range_command(args):
    """
         Filter value list with an input range.
         Args:
             args- dict(value to filter , index (list | str)
         Returns:
             filtered list.
     """
    val = args['value']
    indexes = args['range']

    if isinstance(indexes, (list, tuple)):
        return CommandResults(
            outputs={'value': [val[index] for index in indexes]})
    if isinstance(indexes, str):
        if '-' in indexes:
            start, end = indexes.split('-')
            start = int(start) if start else 0
            end = int(end) if end else len(val)
            return CommandResults(
                outputs={'value': val[start:end + 1]})
    return CommandResults(
        outputs={'value': []})


def main():
    try:
        return_results(results=get_range_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute GetRange. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
