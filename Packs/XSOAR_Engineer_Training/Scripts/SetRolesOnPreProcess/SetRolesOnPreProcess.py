import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
demisto.executeCommand("setIncident", {"roles": "Administrator,DayTime"})
demisto.results(True)
