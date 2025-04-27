import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Variable initialization:
html = ""
campaign_incidents = ""

try:
    # Getting incident context:
    incident_id = demisto.incidents()[0].get("id", {})
    context = demisto.executeCommand("getContext", {"id": incident_id})
    email_campaign = context[0]["Contents"].get("context", {}).get("EmailCampaign")
    if email_campaign and isinstance(email_campaign, list):
        email_campaign = email_campaign[0]
    campaign_incidents = email_campaign.get("incidents", [])
    html = (
        f"<div style='font-size:17px; text-align:center; padding: 15px;'> "
        f"Number of Incidents <div style='font-size:32px;'> <div> {len(campaign_incidents)} </div></div>"
    )

except Exception:
    html = "<div style='text-align:center; font-size:32px;'> <div> No Campaign </div> <div style='font-size:17px;'> </div>"

# Return the data to the layout:
demisto.results({"ContentsFormat": EntryFormat.HTML, "Type": EntryType.NOTE, "Contents": html})
