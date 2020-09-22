import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()
htmlstyle1 = "color:#FF1744;text-align:center;font-size:800%;>"  # color red
htmlstyle2 = "color:#00CD33;text-align:center;font-size:800%;>"  # color green
query = incident[0].get('CustomFields', {}).get('unassignedincidents', '0')
incidentnumbers = set(query)
incidentnumbers_count = len(incidentnumbers)
if query == '0':
    html = "<h1 style=" + htmlstyle2 + "0 </h2>"

else:
    html = "<h1 style=" + htmlstyle1 + str(incidentnumbers_count) + "</h2>"

demisto.results({
    'ContentsFormat': formats['html'],
    'Type': entryTypes['note'],
    'Contents': html
})
