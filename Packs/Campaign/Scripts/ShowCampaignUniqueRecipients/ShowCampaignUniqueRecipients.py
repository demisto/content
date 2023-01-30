import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Variable initialization:
html = ""
campaign_incidents: list[dict]

try:
    incident_id = demisto.incidents()[0].get('id', {})
    context = demisto.executeCommand("getContext", {'id': incident_id})
    campaign_incidents = demisto.get(context[0], "Contents.context.EmailCampaign.incidents")
    unique_recipients = set(recipient for incident in campaign_incidents for recipient in incident.get(
        "recipients", []) if isinstance(incident.get("recipients"), list))
    html = f"<div style='font-size:17px; text-align:center; padding-top: 20px;'> Unique Recipients " \
           f"<div style='font-size:32px;'> <div> {len(unique_recipients)} </div></div>"
except Exception:
    html = "<div style='text-align:center; padding-top: 20px;'> <div> No recipients </div>"

# Return the data to the layout:
demisto.results({
    'ContentsFormat': EntryFormat.HTML,
    'Type': EntryType.NOTE,
    'Contents': html
})
