import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

RED_HTML_STYLE = "color:#FF1744;text-align:center;font-size:800%;>"
GREEN_HTML_STYLE = "color:#00CD33;text-align:center;font-size:800%;>"

incident = demisto.incidents()
query = incident[0].get('CustomFields', {}).get('unassignedincidents', '0')

incident_ids = set(query)

if query == '0':
    html = f"<h1 style={GREEN_HTML_STYLE}0 </h2>"

else:
    html = f"<h1 style={RED_HTML_STYLE}{len(incident_ids)}</h2>"

demisto.results({
    'ContentsFormat': formats['html'],
    'Type': entryTypes['note'],
    'Contents': html
})
