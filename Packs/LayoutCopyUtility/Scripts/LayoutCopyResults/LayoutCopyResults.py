import traceback
from itertools import chain

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

def result_check(result):
    if result !={}:
        return result
    else:
        return None
def get_results():
    context = argToList(demisto.context().get('XSOAR').get('results'))
    if context:
        result_check = lambda result: result if result != {} else None
        results = [result for result in [k.get('layoutcopy').get('pretty') for k in context if result_check(k)]]
        results = '\n'.join(list(chain(*results)))
        return results
    else:
        return 'Start copying to view results!'


def main():
    try:
        return_results(CommandResults(
            outputs_prefix='XSOAR.results',
            readable_output=get_results()
        )
        )
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
