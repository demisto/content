import demistomock as demisto
from CommonServerPython import *
from typing import Dict, Any
import traceback


def wait_for_key(args: Dict[str, Any]):

    context_key = args.get('context_key')
    try:
        max_iterations = int(args.get('iterations'))
    except (ValueError, TypeError):
        return_error('Please provide an integer value for "iterations"')

    demisto_context = demisto.context()
    itr = 0
    done = False
    while not done and itr < max_iterations:
        if demisto_context.get(context_key) is not None:
            done = True
        demisto.executeCommand("Sleep", {"seconds": "1"})
        itr = itr + 1

    if done is False:
        demisto.log('Could not find "' + context_key + '" after "' + str(itr) + '" iterations')


def main():
    try:
        args = demisto.args()
        return_results(wait_for_key(args))

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute wait_for_key. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
