import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def _render(template, item):
    return re.sub(r"\$\{(\w+)\}", lambda m: str(item.get(m.group(1), "")), template or "")


def main():
    args = demisto.args()
    items = argToList(args.get("items")) or []
    incident_type = args.get("incident_type")
    severity = args.get("severity")
    name_template = args.get("name_template", "")
    field_map_raw = args.get("field_map", "")
    field_map = {}
    for pair in field_map_raw.split(","):
        if "=" in pair:
            k, v = pair.split("=", 1)
            field_map[k.strip()] = v.strip()

    created = []
    for it in items:
        labels = []
        cf = {}
        for cli, src in field_map.items():
            cf[cli] = it.get(src) if not src.startswith("=") else src[1:]
        body = {
            "name": _render(name_template, it) or f"Darkmon: {incident_type}",
            "type": incident_type,
            "rawJSON": demisto.dt(it, "{.}") if hasattr(demisto, "dt") else None,
            "customFields": cf,
        }
        if severity:
            body["severity"] = severity
        try:
            demisto.executeCommand("createNewIncident", body)
            created.append(body["name"])
        except Exception as e:
            demisto.error(f"createNewIncident failed: {e}")

    return_results({"CreatedIncidents": created, "Count": len(created)})


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
