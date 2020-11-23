import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        args = demisto.args()
        context_key = args.get('context_key')
        MAX_ITERATIONS = int(args.get('iterations'))

        itr = 0
        done = False
        while not done and itr < MAX_ITERATIONS:
            if context.get(context_key) is not None:
                done = True
            demisto.executeCommand("Sleep", {"seconds": "1"})
            itr = itr + 1

        if done is False:
            demisto.log('Could not find "' + context_key + '" after "' + str(itr) + '" iterations')

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute wait_for_key. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
