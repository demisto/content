import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        args = demisto.args()
        incident_entity_id = args.get("incident_entity_id")
        incident_detection_id = args.get("incident_detection_id")

        query = (
            f'-status:closed -category:job vectraruxentityid:"{incident_entity_id}" '
            f'-vectraruxdetectionid:="{incident_detection_id}"'
        )
        res = demisto.executeCommand("SearchIncidentsV2", {"query": query})
        if isError(res[0]):
            return_error(f"Error searching incidents: {get_error(res[0])}")

        content = res[0]["Contents"]

        data = []
        if content:
            data = content[0].get("Contents", {}).get("data", [])

        incident_ids = []
        for item in data:
            detection_id = item.get("id")
            incident_ids.append(str(detection_id))

        if incident_ids:
            res = demisto.executeCommand("linkIncidents", {"linkedIncidentIDs": ",".join(incident_ids)})
        return_results(res)
    except Exception as e:
        return_error(f"Failed to execute VectraRUXLinkEntityDetections script. Error: {str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
