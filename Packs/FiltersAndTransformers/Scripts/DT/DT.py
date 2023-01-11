import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()
value = args["value"]
dt = args["dt"]

res = demisto.dt(value, dt)
return_results(encode_string_results(res))
