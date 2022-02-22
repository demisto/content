import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json

JSON_CONTEXT_KEY = "JsonObject"
json_str = demisto.args()['input']

demisto.debug(json_str)

obj = json.loads(json_str)

if "_source" in obj:
    new_obj = obj["_source"]
    obj = new_obj

objStr = json.dumps(obj)

demisto.setContext(JSON_CONTEXT_KEY, objStr)
demisto.results(objStr)
