import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

value = demisto.args()["value"]

if isinstance(value, list):
    res = value
    res.reverse()
else:
    res = value

demisto.results(res)
