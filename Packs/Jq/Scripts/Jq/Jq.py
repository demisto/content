import traceback

import demistomock as demisto  # noqa: F401
import pyjq
from CommonServerPython import *  # noqa: F401

''' STANDALONE FUNCTION '''


def jq_filter(value, query):
    res = pyjq.all(query, value)
    return res


''' COMMAND FUNCTION '''


def jq_query(args):

    value = args.get('value')
    query = args.get('query')

    result = jq_filter(value, query)

    return result


''' MAIN FUNCTION '''


def main():
    try:
        return_results(jq_query(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
