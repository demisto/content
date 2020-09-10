import demistomock as demisto

action = demisto.getArg('action')
if action not in ['link', 'unlink']:
    action = 'link'

demisto.results(demisto.executeCommand("linkIncidents", {"linkedIncidentIDs": demisto.getArg("linkedIncidentIDs"),
                                                         "action": action}))
