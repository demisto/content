import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
args = demisto.args()
incident_id = args.get('incident_id')
entry_id = args.get('entryID')
body = args.get('body', None)

response = demisto.executeCommand(
    "demisto-api-multipart", {"uri": "incident/upload/{}".format(incident_id), "entryID": entry_id, "body": body})[0]
if isError(response):
    demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                    "Contents": "There was an issue uploading file.  Check API key and input arguments."})
else:
    if body:
        demisto.results("Successfully uploaded file to incident. Comment is:" + body)
    else:
        demisto.results("Successfully uploaded file to incident")
