import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    incident = demisto.incident()
    close_reason = demisto.args().get("closeReason")
    close_notes = demisto.args().get("closeNotes")
    incident_id = incident.get("id")
    linked_incidents = incident.get("linkedIncidents")

    if linked_incidents and not str(close_notes).startswith("Closed from parent Incident"):
        demisto.executeCommand("executeCommandAt",
                               {"command": "closeInvestigation",
                                "arguments": {
                                    "closeReason": close_reason,
                                    "closeNotes": f"Closed from parent Incident {incident_id}\n"
                                                  f"\nClose Notes:\n{close_notes}"},
                                "incidents": ",".join(linked_incidents)})
        demisto.results(f"Closing linked Incidents {','.join(linked_incidents)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
