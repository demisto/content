import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

COLORS = {
    '1 - Request Was Approved': '#1DB846',  # (success green)
    '2 - Request Was Submitted': '#7995D4',  # (royal blue)
    '3 - Awaiting Request Owner Validation': '#EF9700',  # (warning orange)
    '4 - FW Policy Was Updated': '#009933',  # (polo)
    '5 - Request Was Rejected': '#D13C3C'  # (alert-red)
}

TEXT = {
    '1 - Request Was Approved': 'Request Was Approved',
    '2 - Request Was Submitted': 'Request Was Submitted',
    '3 - Awaiting Request Owner Validation': 'Awaiting Request Owner Validation',
    '4 - FW Policy Was Updated': 'FW Policy Was Updated',
    '5 - Request Was Rejected': 'Request Was Rejected'
}


incident = demisto.incidents()
incident_state = (incident[0].get('CustomFields', {}).get('state'))

try:
    text_color = COLORS[incident_state]
    text_content = TEXT[incident_state]
except Exception as e:
    demisto.debug(f'SnowIncidentStatus debug - state is: {incident_state}\n{e}')
    text_color = '#000000'
    text_content = 'Pending Update'


html = f"<div style='color:{text_color};text-align:center;font-size:32px;'><h1>{text_content}</h1></div>"
demisto.results({
    'ContentsFormat': formats['html'],
    'Type': entryTypes['note'],
    'Contents': html
})
