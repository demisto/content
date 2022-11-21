import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

removeIfContains = demisto.args()["removeIfContains"]
incID = demisto.incidents()[0]["id"]

bodyGet = {"incidentID": incID}
res = demisto.executeCommand("demisto-api-post", {"uri": "/evidence/search", "body": bodyGet})[0]["Contents"]["response"]
entries = res["entries"]
evidences = res["evidences"]
evidencesDict = {}

for evidence in evidences:
    evidencesDict[evidence["entryId"]] = evidence["id"]

for entry in entries:
    if removeIfContains in entry["contents"]:
        bodyDelete = {"evidenceID": evidencesDict[entry["id"]]}
        demisto.executeCommand("demisto-api-post", {"uri": "/evidence/delete", "body": bodyDelete})
demisto.results("Done removing empty evidence")
