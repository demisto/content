import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        incident = demisto.incident()
        signal_id = incident.get("CustomFields", {}).get("datadogsecuritysignalid")

        if not signal_id:
            return_error("No Datadog Security Signal ID found in incident.")

        result = demisto.executeCommand("datadog-signal-get", {"signal_id": signal_id})

        if not result or isError(result):
            return_error(f"Failed to fetch signal: {get_error(result)}")

        signal = result[0].get("Contents", {})  # type: ignore

        if not signal:
            return_error("No signal data returned from Datadog.")

        mapped_data = demisto.mapObject(
            signal, "Datadog Cloud SIEM - Incoming Mapper", "DatadogCloudSIEM"
        )

        custom_fields = {}
        for key, value in mapped_data.items():
            field_name = "".join(key.lower().split())
            custom_fields[field_name] = value

        owner = signal.get("triage", {}).get("assignee", {}).get("name")

        signal_state = signal.get("triage", {}).get("state")
        if signal_state == "archived":
            close_reason = signal.get("triage", {}).get("archive_reason", "Other")
            close_notes = signal.get("triage", {}).get("archive_comment", "")

        if custom_fields:
            demisto.executeCommand("setIncident", {"customFields": custom_fields})

            if owner:
                demisto.executeCommand("setOwner", {"owner": owner})

            if signal_state == "archived":
                demisto.executeCommand(
                    "closeInvestigation",
                    {"closeReason": close_reason, "closeNotes": close_notes},
                )
            return_results(
                CommandResults(
                    readable_output="Successfully synced incident fields from Datadog."
                )
            )
        else:
            return_results(CommandResults(readable_output="No fields to update."))

    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute DatadogSyncIncidentFields. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
