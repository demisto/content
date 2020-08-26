import demistomock as demisto
from CommonServerPython import *  # noqa: F401

host = demisto.args()["value"]

res = "https://demo-cortex.axonius.com/dashboard/explorer?search={}".format(host)

demisto.results(res)
