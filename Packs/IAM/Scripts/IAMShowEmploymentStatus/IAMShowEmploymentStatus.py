import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

ACTIVE_COLOR = "color:rgb(29,184,70)"  # Green
TERMINATED_COLOR = "color:rgb(209,60,60)"  # Red
LEAVE_OF_ABSENCE = "color:rgb(64,65,66)" # Black

incident = demisto.incidents()
employmentstatus = demisto.get(demisto.args()['indicator'], "CustomFields.employmentstatus")
if not employmentstatus:
    employmentstatus = "Not Set"
displaycolor = LEAVE_OF_ABSENCE
if employmentstatus.lower() == "active":
    displaycolor = ACTIVE_COLOR
elif employmentstatus.lower() == "terminated":
    displaycolor = TERMINATED_COLOR

html = "<div style='text-align:center;'><h1 style='" + displaycolor + ";'>" + employmentstatus + "</h1></div>"


demisto.results({
'ContentsFormat': formats['html'],
'Type': entryTypes['note'],
'Contents': html
})


