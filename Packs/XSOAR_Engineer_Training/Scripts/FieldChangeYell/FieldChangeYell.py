import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
new = demisto.args().get("new")
field = demisto.args().get("cliName")
demisto.results(demisto.executeCommand("setIncident", {field: new.upper()}))
