import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


BLACK_COLOR = "color:rgb(64,65,66)"

# Getting user display name:
incident = demisto.incidents()
display_name = str(incident[0].get('CustomFields', {}).get('displayname', ''))

html = "<div style='text-align:center; padding: 6px; font-size:32px; " + BLACK_COLOR + ";'>" + display_name + "</div>"

# Return the data to the layout:
demisto.results({
'ContentsFormat': formats['html'],
'Type': entryTypes['note'],
'Contents': html
})
