import demistomock as demisto
from CommonServerPython import *

import traceback


''' MAIN FUNCTION '''


def main():
    try:
        return_results(
            CommandResults(readable_output='# hello ![](https://media.giphy.com/media/5vR6pNsjhoKwo/giphy.gif)'))
    except Exception as exc:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ERTokenLayoutGif. Error: {str(exc)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
