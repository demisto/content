import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

JSON_CONTEXT_KEY = "JsonObject"
json_str = demisto.args()['input']
obj = json.loads(json_str)

demisto.results({
    "EntryContext": {JSON_CONTEXT_KEY: obj},
    "Type": entryTypes['note'],
    "ContentsFormat": formats['json'],
    "Contents": obj})
