import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Variable initialization:
html = ""
campaign_incidents = ""

try:
    incident_id = demisto.incidents()[0].get('id', {})
    context = demisto.executeCommand("getContext", {'id': incident_id})
    campaign_incidents = demisto.get(context[0], "Contents.context.EmailCampaign.incidents")
    unique_senders = {incident.get("emailfrom") for incident in campaign_incidents}  # type: ignore[attr-defined]
    html = f"<div style='font-size:17px; text-align:center; padding-top: 20px;'> " \
           f"Unique Senders <div style='font-size:32px;'> <div> {len(unique_senders)} </div></div>"
except Exception:
    html = "<div style='text-align:center; padding-top: 20px;'> <div> No senders </div>"

# Return the data to the layout:
demisto.results({
    'ContentsFormat': EntryFormat.HTML,
    'Type': EntryType.NOTE,
    'Contents': html
})
