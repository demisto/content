import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
user = demisto.args().get('user', '')
addToContext = bool(demisto.args().get('addToContext', False))
addToEvidence = bool(demisto.args().get('addToEvidence', False))

if user == '':
    output = "{{color:#fd0800}}(Error not username passed)"
else:
    temp = demisto.executeCommand('ad-get-user', {'username': user, 'attributes': 'sAMAccountName,name,mail,manager'})
    if addToContext:
        demisto.results(temp)

    temp = temp[0]['Contents']['attributes']
    output = "**UserID:** " + temp["sAMAccountName"][0] + "\n**Username:** " + \
        temp["name"][0] + "(" + temp["mail"][0] + ")\n**Manager:** " + temp["manager"][0]

demisto.results(demisto.executeCommand('setIncident', {'customFields': {'lookupoutput': output}}))
