import demistomock as demisto
from CommonServerPython import *

incident = demisto.incidents()
query = incident[0].get('CustomFields', {}).get('breachconfirmation', "Pending Confirmation")
Color = 'green'

if query == "Confirm":
    color = 'red'
    html = "<div style='color:red;'><h2>Confirmed</h2></div>"

elif query == "Not Confirm":
    color = 'red'
    html = "<div style='color:blue;'><h2>Not Confirmed</h2></div>"

else:
    html = "<div style='color:green;'><h2>Pending Confirmation</h2></div>"


demisto.results({
    'ContentsFormat': formats['html'],
    'Type': entryTypes['note'],
    'Contents': html
})
