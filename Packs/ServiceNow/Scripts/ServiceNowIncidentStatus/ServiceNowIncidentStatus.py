import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

COLORS = {
    '1 - New': '#00CD33',  # (success green)
    '2 - In Progress': '#7995D4',  # (royal blue)
    '3 - On Hold': '#FF9000',  # (warning orange)
    '4 - Awaiting Caller': '#FF9000',  # (warning orange)
    '5 - Awaiting Evidence': '#FF9000',  # (warning orange)
    '6 - Resolved': '#89A5C1',  # (polo)
    '7 - Closed': '#9AA0A3',  # (natural grey)
    '8 - Canceled': '#FF1744'  # (alert-red)
}

TEXT = {
    '1 - New': 'New',
    '2 - In Progress': 'In Progress',
    '3 - On Hold': 'On-Hold',
    '4 - Awaiting Caller': 'Awaiting Caller',
    '5 - Awaiting Evidence': 'Awaiting Evidence',
    '6 - Resolved': 'Resolved',
    '7 - Closed': 'Closed',
    '8 - Canceled': 'Canceled'
}


incident = demisto.incidents()
service_now_state = (incident[0].get('CustomFields', {}).get('servicenowstate'))

try:
    text_color = COLORS[service_now_state]
    text_content = TEXT[service_now_state]
except Exception as e:
    demisto.debug(f'SnowIncidentStatus debug - state is: {service_now_state}\n{e}')
    text_color = '#000000'
    text_content = 'Pending Update'


html = f"<div style='color:{text_color};text-align:center;'><h2>{text_content}</h2></div>"
demisto.results({
    'ContentsFormat': formats['html'],
    'Type': entryTypes['note'],
    'Contents': html
})
