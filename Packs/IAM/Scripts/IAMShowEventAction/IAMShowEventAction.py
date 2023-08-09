import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


incident = demisto.incidents()
eventaction = "'" + str(incident[0].get('CustomFields', {}).get('eventaction', '')) + "'"

html = "<div style='color:#404142;text-align:center;'><h1>" + str(eventaction) + "</h1></div>"

demisto.results({
'ContentsFormat': formats['html'],
'Type': entryTypes['note'],
'Contents': html
})


