import demistomock as demisto
from CommonServerPython import *
from time import sleep

timeout = 960
interval = 10

# Constant and mandatory arguments

caseid = demisto.get(demisto.args(), 'caseid')
jobid = demisto.get(demisto.args(), 'jobid')

feDone = False

# Poll stage
status = None
sec = 0
ec = {}  # type: dict
resp = None
sleep(10)  # small waitto be sure job is submitted, otherwise we get 404
while sec < timeout:
    if not feDone:
        status = "Done"
        # Get status
        resp = demisto.executeCommand('accessdata-get-jobstatus', {
            'caseID': caseid,
            'jobID': jobid
        })
        ec = demisto.get(resp[0], 'Contents')
        # find status
        unfinishedStates = ["Started", "Pending", "Submitted", "InProgress"]
        if ec is not None and 'State' in ec and ec['State'] in unfinishedStates:
            sec += interval
            sleep(interval)
            # continue loop
        else:
            # loop done failed
            feDone = True
    else:
        break

# Get results
if not feDone:
    demisto.results({
        "Type": entryTypes["error"],
        "ContentsFormat": formats["text"],
        "Contents": 'Could not retrieve job results from Quinc (may be due to timeout).'
    })

demisto.results({
    "ContentsFormat": formats["json"],
    "Type": entryTypes["note"],
    "Contents": ec,
    "EntryContext": {"Accessdata.Job(val.ID == obj.ID)": ec}
})
