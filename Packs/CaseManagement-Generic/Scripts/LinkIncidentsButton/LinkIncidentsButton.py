import demistomock as demisto

demisto.results(demisto.executeCommand("linkIncidents", {"linkedIncidentIDs": demisto.getArg(
    "linkedIncidentIDs"), "action": demisto.getArg("action")}))
