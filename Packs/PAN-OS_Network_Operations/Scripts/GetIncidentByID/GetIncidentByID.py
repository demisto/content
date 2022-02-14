import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

return_results(demisto.executeCommand("getIncidents", {"id": demisto.args().get("id")}))
