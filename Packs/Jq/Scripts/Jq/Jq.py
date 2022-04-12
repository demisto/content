import json
import traceback

import demistomock as demisto  # noqa: F401
import pyjq
from CommonServerPython import *  # noqa: F401


''' MAIN FUNCTION '''


def jq_wrap(json_str, query):
    if type(json_str) == str:
        j = json.loads(json_str)
    else:
        j = json_str

    res = pyjq.all(query, j)
    try:
        demisto.executeCommand('Set', {'key': 'jq.result', 'value': res})
    except:
        pass  # ignore issue when can't set context - script executed as transform script
    return_results(res)


def main():
    try:
        jq_wrap(demisto.args()["value"], demisto.args()["query"])
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute jq. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
