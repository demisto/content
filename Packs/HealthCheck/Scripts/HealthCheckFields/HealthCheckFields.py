import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

DESCRIPTION = "Custom fields which usually contains big data are being indexed, consider not to index it"
RESOLUTION = (
    "Navigate to incident field page (Settings > Advanced > Fields), select Field > Edit, "
    "and turn off Make data available for search under the Attributes tab its determines if "
    "the values in these fields are available when searching."
)
RIKEY_TYPES = ["grid", "html", "longText", "markdown", "url"]


def find_indexed_longText_fields(fields):
    """Return custom indexed fields that are likely to contain large amounts of data."""
    return [
        {"fieldname": field.get("name"), "fieldtype": field.get("type")}
        for field in fields
        if (
            field.get("type") in RIKEY_TYPES
            and field.get("unsearchable") is False
            and field.get("packID") == ""
            and field.get("system") is False
            and field.get("name") != "description"
        )
    ]


def main():
    try:
        incident = demisto.incidents()[0]

        if is_demisto_version_ge("8.0.0"):
            uri = "xsoar/public/v1/incidentfields"
        else:
            account_name = incident.get("account", "")
            uri = f"acc_{account_name}/incidentfields" if account_name else "incidentfields"

        res = execute_command("core-api-get", {"uri": uri})

        if isinstance(res, list):
            res = res[0] if res else {}

        fields = (res or {}).get("response") or []
        found = find_indexed_longText_fields(fields)

        demisto.executeCommand("setIncident", {"healthcheckriskyindexedfields": found})

        action_items = []
        if found:
            action_items.append(
                {
                    "category": "Content",
                    "severity": "Medium",
                    "description": DESCRIPTION,
                    "resolution": RESOLUTION,
                }
            )

        return_results(
            CommandResults(
                readable_output="HealthCheckFields Done",
                outputs_prefix="HealthCheck.ActionableItems",
                outputs=action_items,
            )
        )
    except Exception as e:
        return_error(f"Failed to execute HealthCheckFields: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
