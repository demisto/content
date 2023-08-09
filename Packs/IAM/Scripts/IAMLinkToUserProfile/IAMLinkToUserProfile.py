import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

BLACK_COLOR = "color:rgb(64,65,66)"


incident = demisto.incidents()
employeeid = str(incident[0].get('CustomFields', {}).get('employeeid', ''))
display_name = str(incident[0].get('CustomFields', {}).get('displayname', ''))
employee_email = str(incident[0].get('CustomFields', {}).get('email', ''))

query = f'type:"User Profile" employeeid:"{employeeid}"'
server_url = ""
html = ""

try:
    indicator_id = demisto.executeCommand("findIndicators", {'query': query})[0].get('Contents')[0].get('id')
    server_url = demisto.executeCommand('GetServerURL',{})[0]["Contents"]
    if display_name:
        html = f"""<div style='text-align:center; padding: 8px; font-size:32px; {BLACK_COLOR};'><a href="{server_url}/#/indicator/{indicator_id}">{display_name}</a></div>"""
    else:
        html = f"""<div style='text-align:center; padding: 8px; font-size:32px; {BLACK_COLOR};'><a href="{server_url}/#/indicator/{indicator_id}">{employee_email}</a></div>"""

except Exception:
    if display_name:
        html = f"""<div style='text-align:center; padding: 8px; font-size:32px; {BLACK_COLOR};'>{display_name}</div>"""
        demisto.debug(f"IAMLinkToUserProfile failed: {employeeid=}, {query=}, {display_name=}, {employee_email=}, {indicator_id=}")
    else:
        html = f"""<div style='text-align:center; padding: 8px; font-size:32px; {BLACK_COLOR};'>{employee_email}</div>"""
        demisto.debug(f"IAMLinkToUserProfile failed: {employeeid=}, {query=}, {display_name=}, {employee_email=}, {indicator_id=}")


demisto.results({
'ContentsFormat': formats['html'],
'Type': entryTypes['note'],
'Contents': html
})
