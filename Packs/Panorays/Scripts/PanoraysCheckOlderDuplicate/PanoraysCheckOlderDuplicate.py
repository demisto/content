import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def check_older_duplicate(finding_id: str, this_incident_id: str) -> bool:
    """Returns True if an open/pending "Panorays Finding" incident with the same finding_id and a lower
    incident ID than this_incident_id already exists."""
    query = f'type:"Panorays Finding" and -status:2 and panoraysfindingid:"{finding_id}" ' f"and id:<{this_incident_id}"
    result = demisto.executeCommand("getIncidents", {"query": query, "size": "1"})
    if not result:
        return False
    for entry in result:
        if is_error(entry):
            raise DemistoException(get_error(entry))
        contents = entry.get("Contents") or {}
        data = contents.get("data") or []
        if data:
            return True
    return False


def main():
    try:
        args = demisto.args()
        finding_id = args.get("finding_id", "")
        this_incident_id = args.get("incident_id", "")
        found = check_older_duplicate(finding_id, this_incident_id)
        return_results(
            CommandResults(
                outputs_prefix="PanoraysDuplicateCheck",
                outputs={"OlderDuplicateExists": found},
                readable_output=f"Older open/pending duplicate exists: {found}",
            )
        )
    except Exception as e:
        return_error(f"Failed to check for older duplicate incidents: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
