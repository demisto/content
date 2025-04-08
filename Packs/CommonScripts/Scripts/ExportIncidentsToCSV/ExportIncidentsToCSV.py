import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

NO_INCIDENTS_FOUND = "Incidents search returned no results"
LIMIT_EXCEEDED = "Limit Exceeded"


def main():
    incident_query = demisto.args().get("query")
    incident_fetch_back_days = int(demisto.args().get("fetchdays"))

    if demisto.args().get("columns"):
        incident_columns = [x.strip() for x in demisto.args().get("columns").split(",")]
    else:
        incident_columns = [
            "id",
            "name",
            "type",
            "severity",
            "status",
            "owner",
            "roles",
            "playbookId",
            "occurred",
            "created",
            "modified",
            "closed",
        ]

    # body for the incident request
    incident_body = {
        "all": True,
        "filter": {
            "query": incident_query,
            "sort": [{"field": "id", "asc": False}],
            "period": {"by": "day", "fromValue": incident_fetch_back_days},
        },
        "columns": incident_columns,
    }

    # generate the file
    export_to_csv_result = demisto.executeCommand("core-api-post", {"uri": "/incident/batch/exportToCsv", "body": incident_body})
    if not export_to_csv_result:
        raise ValueError(f"Error {get_error(export_to_csv_result)} when trying to export incident(s) with query {incident_query} to CSV")
    demisto.debug(f"{export_to_csv_result=}")
    export_to_csv_result_content = export_to_csv_result[0].get("Contents", {})

    if isinstance(export_to_csv_result_content, str):
        if NO_INCIDENTS_FOUND in export_to_csv_result_content:
            demisto.results(NO_INCIDENTS_FOUND)
            return
        elif LIMIT_EXCEEDED in export_to_csv_result_content:
            pass
        else:
            raise ValueError("Couldn't export incidents to CSV")
    else:
        csv_file_name = export_to_csv_result_content.get("response")

    # download the file and return to the war room
    incident_csv_result = demisto.executeCommand("core-api-get", {"uri": f"/incident/csv/{csv_file_name}"})
    if not incident_csv_result:
        raise ValueError(f"Error {get_error(incident_csv_result)} when trying to retrieve the CSV")
    demisto.debug(f"{incident_csv_result=}")
    file = incident_csv_result[0].get("Contents", {}).get("response", "")
    demisto.results(fileResult(csv_file_name, file))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
