"""
Reads Taegis Requested Assignee and Taegis Requested Status from the incident,
pushes to Taegis via the integration command, then sets fields to placeholders.
Use with the "Update in Taegis" section: user selects from the human-friendly
dropdowns (same options as current assignee), then clicks the button.
After push we set the requested fields to placeholder values so the user isn't
confused with the read-only Taegis XDR Assignee / Case Status.
"""

REQUESTED_ASSIGNEE_KEY = "taegisrequestedassignee"
REQUESTED_STATUS_KEY = "taegisrequestedstatus"
PLACEHOLDER_ASSIGNEE = "Select Assignee"
PLACEHOLDER_STATUS = "Select Status"


def main():
    incident = demisto.incident()
    if not incident or not isinstance(incident, dict):
        demisto.results([{"Type": 1, "ContentsFormat": "markdown", "Contents": "No incident context. Run this from an incident."}])
        return

    inner = incident.get("incident") or incident.get("Incident") or incident
    if not isinstance(inner, dict):
        inner = incident
    custom = inner.get("CustomFields") or inner.get("customFields") or {}
    if not isinstance(custom, dict):
        custom = {}

    assignee_raw = (custom.get(REQUESTED_ASSIGNEE_KEY) or "").strip() if custom.get(REQUESTED_ASSIGNEE_KEY) else ""
    status_raw = (custom.get(REQUESTED_STATUS_KEY) or "").strip() if custom.get(REQUESTED_STATUS_KEY) else ""
    # Treat placeholders as empty so we don't push them to Taegis
    assignee_id = assignee_raw if assignee_raw and assignee_raw != PLACEHOLDER_ASSIGNEE else ""
    status = status_raw if status_raw and status_raw != PLACEHOLDER_STATUS else ""

    if not assignee_id and not status:
        demisto.results(
            [
                {
                    "Type": 1,
                    "ContentsFormat": "markdown",
                    "Contents": "Select **Taegis Requested Assignee** and/or **Taegis Requested Status** in the \"Update in Taegis\" section above, then click the button again.",
                }
            ]
        )
        return

    investigation_id = inner.get("dbotMirrorId") or custom.get("dbotMirrorId")
    if not investigation_id or str(investigation_id).strip() == "":
        demisto.results(
            [
                {
                    "Type": 1,
                    "ContentsFormat": "markdown",
                    "Contents": "This incident is not mirrored from Taegis (no dbotMirrorId). Cannot push assignee/status.",
                }
            ]
        )
        return

    cmd_args = {"id": str(investigation_id).strip()}
    if assignee_id:
        cmd_args["assignee_id"] = assignee_id
    if status:
        cmd_args["status"] = status

    result = demisto.executeCommand("taegis-push-assignee-status", cmd_args)
    if not result or not isinstance(result, list):
        demisto.results([{"Type": 1, "ContentsFormat": "markdown", "Contents": "Request could not be sent. Check the War Room for errors."}])
        return

    # Set requested fields to placeholders so the user isn't confused with read-only Assignee/Status
    try:
        demisto.executeCommand(
            "setIncident",
            {REQUESTED_ASSIGNEE_KEY: PLACEHOLDER_ASSIGNEE, REQUESTED_STATUS_KEY: PLACEHOLDER_STATUS},
        )
    except Exception:
        pass

    demisto.results(result)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
