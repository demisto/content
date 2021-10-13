import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    key = demisto.args()['key']
    obj_str = json.dumps(demisto.get(demisto.context(), key))
    demisto.setContext('JsonStr', obj_str)
    return_results(obj_str)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
