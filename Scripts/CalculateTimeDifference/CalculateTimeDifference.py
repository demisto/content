import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

entries = []
start_time = demisto.args()['start_time'].replace('"', '')
end_time = demisto.args()['end_time'].replace('"', '')

try:
    # Strip microseconds and convert to datetime object
    start_time_obj = datetime.datetime.strptime(start_time.split(".")[0], "%Y-%m-%dT%H:%M:%S")
    end_time_obj = datetime.datetime.strptime(end_time.split(".")[0], "%Y-%m-%dT%H:%M:%S")
    # Calculate the difference in minutes
    time_diff = end_time_obj - start_time_obj
    mins = round((time_diff.total_seconds() / 60), 2)

    entries.append({
        "Type": entryTypes['note'],
        "Contents": mins,
        "ContentsFormat": formats['text'],
        "HumanReadable": "Calculated Time Difference: {} minutes.".format(str(mins)),
        "EntryContext": {
            "Time.Difference": mins,
            "Time.Start": start_time,
            "Time.End": end_time
        }
    })

except Exception as ex:
    entries.append({
        "Type": entryTypes["error"],
        "ContentsFormat": formats["text"],
        "Contents": "Error occurred while parsing output from command. Exception info:\n" + str(ex)
    })
demisto.results(entries)
