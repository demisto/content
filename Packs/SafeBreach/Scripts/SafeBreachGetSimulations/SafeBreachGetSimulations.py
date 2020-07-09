import demistomock as demisto
from CommonServerPython import *
# Python template - reading arguments, calling a command, handling errors and returning results
res = []
label_value = demisto.dt(demisto.incidents()[0], 'labels(val.type=="id").value')
# Calling a command - returns a list of one or more entries
resCmdName = demisto.executeCommand("safebreach-get-simulations", {'simulationId': label_value})
try:
    for entry in resCmdName:
        if isError(entry):
            # Check if it's that error we know about and have a solution for - notify, retry, display a specific error message, etc.
            if "failed with status 404 NOT FOUND" in entry["Contents"]:
                res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                            "Contents": "Received HTTP Error 404 from Session API. Please ensure that you do not already have an active session with that sensor."})
            else:
                # If it's not an error we recognize - send all entries returned from the command back to the war room as-is.
                res = resCmdName
                break
                # # If it's not an error we recognize - send that error to the war room but keep handling the other returned entries
                # res.append(entry)
        else:
            myData = demisto.get(entry, 'Contents.result_obj.results')
            # Log myData to war room - for debugging. May remove this later in production script
            demisto.log(str(myData))
            if myData:
                res.append({"Type": entryTypes["note"], "ContentsFormat": formats["table"], "Contents": myData})
            else:
                res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                            "Contents": "Could not extract result list from response: " + json.dumps(entry["Contents"])})
except Exception as ex:
    res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                "Contents": "Error occurred while parsing output from command. Exception info:\n" + str(ex) + "\n\nInvalid output:\n" + str(resCmdName)})
demisto.results(res)
