import demistomock as demisto
from CommonServerPython import *

demisto.results(demisto.executeCommand("linkIncidents", {"linkedIncidentIDs": demisto.getArg(
    "linkedIncidentIDs"), "action": demisto.getArg("action")}))
