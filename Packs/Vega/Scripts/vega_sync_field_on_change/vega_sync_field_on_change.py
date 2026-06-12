import demistomock as demisto
from CommonServerPython import *

VEGA_INTEGRATION_BRAND = "Vega"
VEGA_ALERT_INCIDENT_TYPE = "Vega Alert"
VEGA_INCIDENT_INCIDENT_TYPE = "Vega Incident"


def main() -> None:
    incident = demisto.incident() or {}
    incident_type = str(incident.get("type") or incident.get("Type") or "").strip()
    command_args = {**demisto.args(), "using-brand": VEGA_INTEGRATION_BRAND}

    if incident_type == VEGA_ALERT_INCIDENT_TYPE:
        demisto.executeCommand("vega-update-alert", command_args)
        return

    if incident_type == VEGA_INCIDENT_INCIDENT_TYPE:
        demisto.executeCommand("vega-update-incident", command_args)
        return

    return_error(
        f"vega-sync-field-on-change is only supported for {VEGA_ALERT_INCIDENT_TYPE} and "
        f"{VEGA_INCIDENT_INCIDENT_TYPE} investigations. Current type: {incident_type or 'unknown'}."
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
