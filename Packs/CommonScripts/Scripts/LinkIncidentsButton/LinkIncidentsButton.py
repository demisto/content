import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


action = demisto.getArg('action')
if action not in ['link', 'unlink']:
    action = 'link'

demisto.results(demisto.executeCommand("linkIncidents", {"linkedIncidentIDs": demisto.getArg("linkedIncidentIDs"),
                                                         "action": action}))
