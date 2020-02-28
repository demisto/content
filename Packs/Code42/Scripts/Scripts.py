import demistomock as demisto
from CommonServerPython import *
import json
res = []

filelist = demisto.args()["exfiltratedfiles"]
# If filelist is passed as string, load into dict
if isinstance(filelist, str):
    try:
        filelist = json.loads(filelist)
    except Exception as ex:
        res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                    "Contents": "Error occurred while parsing output from command. Exception info:\n"
                    + str(ex) + "\n\nInvalid output:\n"})
        demisto.results(res)
# Iterate through items and convert keys to lowercase
newevents = []
for event in filelist:
    newevents.append(dict((k.lower(), v) for k, v in event.items()))
demisto.executeCommand('setIncident', {'exfiltratedfilelist': newevents})
