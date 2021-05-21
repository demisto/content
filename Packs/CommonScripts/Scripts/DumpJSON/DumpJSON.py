import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

JSON_CONTEXT_KEY = "JsonStr"
key = demisto.args()['key']
objStr = json.dumps(demisto.get(demisto.context(), key))
demisto.setContext(JSON_CONTEXT_KEY, objStr)
demisto.results(objStr)
