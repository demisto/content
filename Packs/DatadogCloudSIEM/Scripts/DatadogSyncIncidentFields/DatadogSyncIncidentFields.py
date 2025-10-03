from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        # Get signal ID from incident
        incident = demisto.incident()
        signal_id = incident.get("CustomFields", {}).get("datadogsecuritysignalid")

        if not signal_id:
            return_error("No Datadog Security Signal ID found in incident.")

        # Fetch the signal from Datadog
        result = demisto.executeCommand(
            "datadog-security-signal-get", {"signal_id": signal_id}
        )

        if not result or isError(result):
            return_error(f"Failed to fetch signal: {get_error(result)}")

        # Get signal data from command Contents (not context)
        signal = result[0].get("Contents", {})  # type: ignore

        if not signal:
            return_error("No signal data returned from Datadog.")

        demisto.debug(f"Signal data: {signal}")

        # Map using the mapper
        mapped_data = demisto.mapObject(
            signal, "Datadog Cloud SIEM - Incoming Mapper", "DatadogCloudSIEM"
        )

        demisto.debug(f"Mapped data: {mapped_data}")

        # Convert mapped field names to custom field names (lowercase, no spaces)
        custom_fields = {}
        for key, value in mapped_data.items():
            field_name = "".join(key.lower().split())
            custom_fields[field_name] = value

        demisto.debug(f"Custom fields: {custom_fields}")

        # Update incident
        if custom_fields:
            demisto.executeCommand("setIncident", custom_fields)
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
