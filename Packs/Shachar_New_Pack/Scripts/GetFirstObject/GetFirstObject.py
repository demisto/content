import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

value = demisto.args()['value']
if isinstance(value, list) or isinstance(value, tuple):
    demisto.results(value[0])
else:
    demisto.results(value)
