import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# get the close notes & reason from the XSOAR Incident
close_reason = demisto.args().get("closeReason", "Resolved")
close_notes = demisto.args().get("closeNotes", "No close notes provided")

# get the xdr incident id
xdrincidentid = demisto.incident().get("CustomFields", {}).get("xdrincidentid", False)

# map XSOAR close reasons to XDR close codes
close_code_map = {
    "False Positive": "RESOLVED_FALSE_POSITIVE",
    "Resolved": "RESOLVED_THREAT_HANDLED",
    "Other": "RESOLVED_OTHER",
    "Duplicate": "RESOLVED_DUPLICATE"
}

if xdrincidentid:
    demisto.results(demisto.executeCommand("xdr-update-incident",
                    {"incident_id": xdrincidentid, "status": close_code_map.get(close_reason), "resolve_comment": close_notes}))

else:
    demisto.results("No XDR Incident ID found, doing nothing...")
