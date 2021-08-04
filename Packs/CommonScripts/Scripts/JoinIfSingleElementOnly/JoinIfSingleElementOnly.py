import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

value = demisto.args()["value"]
res = value
if isinstance(value, list):
    if len(value) == 1:
        res = value[0]

demisto.results(res)
