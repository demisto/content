import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def filter_non_locked(res):
    """Return custom or detached incident types."""
    return [x for x in res if x.get("locked") is False or x.get("detached") is True]


def main():
    try:
        if is_demisto_version_ge("8.0.0"):
            uri = "xsoar/public/v1/incidenttype"
        else:
            account_name = demisto.incidents()[0].get("account", "")
            uri = f"acc_{account_name}/incidenttype" if account_name else "incidenttype"

        result = execute_command("core-api-get", {"uri": uri})
        if isinstance(result, list):
            res = result[0].get("response", []) if result else []
        else:
            res = (result or {}).get("response") or []

        table = []
        for incident_type in filter_non_locked(res):
            extract_settings = incident_type.get("extractSettings") or {}
            mode = extract_settings.get("mode")
            if mode == "All":
                table.append(
                    {
                        "incidenttype": incident_type.get("prevName"),
                        "detection": "Indicators extraction defined on all fields",
                    }
                )
            elif mode == "Specific" and extract_settings.get("fieldCliNameToExtractSettings"):
                table.append(
                    {
                        "incidenttype": incident_type.get("prevName"),
                        "detection": "No indicators extraction defined on all fields",
                    }
                )

        execute_command("setIncident", {"healthcheckautoextractionbasedincidenttype": table})
        return_results(CommandResults(readable_output="HealthCheckIncidentTypes Done"))
    except Exception as e:
        return_error(f"Failed to execute HealthCheckIncidentTypes: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
