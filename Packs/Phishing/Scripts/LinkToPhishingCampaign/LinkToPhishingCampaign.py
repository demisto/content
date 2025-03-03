import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

BLACK_COLOR = "color:rgb(64,65,66)"

server_url = ""
html = ""


try:
    incident = demisto.incidents()
    incident_id = incident[0].get('id', {})
    campaign_incident_id = str(incident[0].get('CustomFields', {}).get('partofcampaign', ''))
    urls = demisto.demistoUrls()
    server_url = urls.get('server', '')
    if campaign_incident_id and campaign_incident_id != "None":
        prefix = 'Custom' if is_xsoar_saas() else '#/Custom'
        related_url = f"{server_url}/{prefix}/vvoh19d1ue/{campaign_incident_id}"
        html = f"""<div style='text-align:center; padding: 40px; font-size:15px; {BLACK_COLOR};'
        >This incident is part of a <a href="{related_url}"
        >Phishing Campaign #{campaign_incident_id}</a></div>"""
    else:
        html = f"""<div style='text-align:center; padding: 40px; font-size:15px; {BLACK_COLOR};'
        >This incident is not part of a phishing campaign.</div>"""

except Exception:
    html = f"""<div style='text-align:center; padding: 40px; font-size:15px; {BLACK_COLOR};'
    >This incident is part of a phishing campaign (incident #{campaign_incident_id}).</div>"""


demisto.results({
    'ContentsFormat': formats['html'],
    'Type': entryTypes['note'],
    'Contents': html
})
