import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

COLORS = {
    '1 - New': '#00CD33',  # (success green)
    '2 - Processing (assigned)': '#7995D4',  # (royal blue)
    '3 - Processing (planned)': '#FF9000',  # (warning orange)
    '4 - Pending': '#FF9000',  # (warning orange)
    '5 - Solved': '#FF9000',  # (warning orange)
    '6 - Closed': '#89A5C1'  # (polo)
}

TEXT = {
    '1 - New': 'New',
    '2 - Processing (assigned)': 'Processing (assigned)',
    '3 - Processing (planned)': 'Processing (planned)',
    '4 - Pending': 'Pending',
    '5 - Solved': 'Solved',
    '6 - Closed': 'Closed'
}

incident = demisto.incidents()
glpi_state = (incident[0].get('CustomFields', {}).get('glpistatus'))

try:
    text_color = COLORS[glpi_state]
    text_content = TEXT[glpi_state]
except Exception as e:
    demisto.debug(f'GLPIIncidentStatus debug - state is: {glpi_state}\n{e}')
    text_color = '#000000'
    text_content = 'Pending Update'


html = f"<div style='color:{text_color};text-align:center;'><h2>{text_content}</h2></div>"
demisto.results({
    'ContentsFormat': formats['html'],
    'Type': entryTypes['note'],
    'Contents': html
})
