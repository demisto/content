import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def filter_non_locked(res):
    nonLockedTypes = list(filter(lambda x: x.get("locked") is False or x.get("detached") is True, res))
    return nonLockedTypes


def main():
    incident = demisto.incidents()[0]
    account_name = incident.get("account")
    account_name = f"acc_{account_name}" if account_name != "" else ""
    # `execute_command` collapses a single result entry to a dict but returns a
    # list when multiple entries are present.
    result = execute_command("core-api-get", {"uri": f"{account_name}/incidenttype"})
    if isinstance(result, list):
        demisto.debug(f"result is a list of length {len(result)}")
        res = result[0].get("response", []) if result else []
    else:
        demisto.debug("result is a dict")
        res = result.get("response", [])

    nonLockedTypes = filter_non_locked(res)

    table = []
    for incident_type in nonLockedTypes:
        newEntry = {}
        extract_settings = incident_type.get("extractSettings") or {}
        mode = extract_settings.get("mode")
        if mode == "All":
            newEntry["incidenttype"] = incident_type.get("prevName")
            newEntry["detection"] = "Indicators extraction defined on all fields"
            table.append(newEntry)
        elif mode == "Specific" and extract_settings.get("fieldCliNameToExtractSettings"):
            newEntry["incidenttype"] = incident_type.get("prevName")
            newEntry["detection"] = "No indicators extraction defined on all fields"
            table.append(newEntry)
        else:
            continue
    execute_command("setIncident", {"healthcheckautoextractionbasedincidenttype": table})


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
