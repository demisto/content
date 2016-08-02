res = []
dArgs = {}
inArgs= demisto.args()
if demisto.get(inArgs, 'owner'):
    res += demisto.executeCommand("setOwner", {'owner': inArgs['owner']})
if demisto.get(inArgs, 'playbook'):
    res += demisto.executeCommand("setPlaybook", {'name': inArgs['playbook']})
if demisto.get(inArgs, 'stage'):
    res += demisto.executeCommand("setStage", {'stage': inArgs['stage']})
if demisto.get(inArgs, 'name'):
    dArgs['incName'] = inArgs['name']
if demisto.get(inArgs, 'details'):
    dArgs['details'] = inArgs['details']
if demisto.get(inArgs, 'severity'):
    dArgs['severity'] = inArgs['severity']
if demisto.get(inArgs, 'labels'):
    dArgs['labels'] = inArgs['labels']
if demisto.get(inArgs, 'addLabels'):
    dArgs['addLabels'] = inArgs['addLabels']
if demisto.get(inArgs, 'type'):
    dArgs['type'] = inArgs['type']
    if (not demisto.get(inArgs, 'updatePlaybookForType') or demisto.get(inArgs, 'updatePlaybookForType') == 'yes') and not demisto.get(inArgs, 'playbook'):
        demisto.executeCommand("setPlaybookAccordingToType", {'type': inArgs['type']})
if dArgs:
    res += demisto.executeCommand("setIncident", dArgs)
demisto.results(res)
