import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import traceback

import pyjq


''' MAIN FUNCTION '''


def jq_wrap(json_str, query):
    j = json.loads(json_str)

    res = pyjq.all(query, j)
    cmd_res = demisto.executeCommand('Set', {'key': 'jq.result', 'value': res})
    if not is_error(cmd_res):
        return_results(res)


def main():
    try:
        jq_wrap(demisto.args()["value"], demisto.args()["query"])
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute jq. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
