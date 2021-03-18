import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

value = demisto.args()["value"]
dt = demisto.args()["dt"]

res = demisto.dt(value, dt)
demisto.results(res)
