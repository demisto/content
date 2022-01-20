import demistomock as demisto
from CommonServerPython import *

import json


def load_json(args):
    json_str = args['input']
    obj = json.loads(json_str, strict=False)


    return {
        "EntryContext": {"JsonObject": obj},
        "Type": entryTypes['note'],
        "ContentsFormat": formats['json'],
        "Contents": obj
    }


if __name__ in ('__builtin__', 'builtins', '__main__'):
    res = load_json(demisto.args())
    demisto.results(res)
