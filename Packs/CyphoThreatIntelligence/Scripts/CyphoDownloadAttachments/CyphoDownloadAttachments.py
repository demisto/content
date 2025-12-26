import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

try:
    incident = demisto.incident()
    ticket_id = incident.get("CustomFields", {}).get("cyphoticketid")

    if not ticket_id:
        raise ValueError("Ticket ID (cyphoticketid) is missing from incident.")

    args = {"ticket_id": ticket_id}

    download_response = demisto.executeCommand("cypho-download-attachment", args)

    if is_error(download_response[0]):
        raise DemistoException(f"Attachment download failed: {download_response[0].get('Contents')}")

    return_results(download_response)

except Exception as e:
    demisto.error(f"[CyphoDownloadAttachment] Error: {str(e)}")
    return_results(CommandResults(readable_output="Failed to download attachment from the ticket."))
