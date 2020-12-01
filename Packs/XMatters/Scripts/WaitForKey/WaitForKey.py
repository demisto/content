from typing import Dict, Any
import traceback
import demistomock as demisto


def wait_for_key(args: Dict[str, Any]):

    context_key = args.get('context_key')
    MAX_ITERATIONS = int(args.get('iterations'))

    demisto_context = demisto.context()
    itr = 0
    done = False
    while not done and itr < MAX_ITERATIONS:
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
