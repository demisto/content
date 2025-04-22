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
        raise ValueError(f"Error when trying to export incident(s) with query {incident_query} to CSV")

    if is_error(export_to_csv_result):
        export_to_csv_result_content = export_to_csv_result[0].get("Contents", {})
        if NO_INCIDENTS_FOUND in export_to_csv_result_content:
            return_results(NO_INCIDENTS_FOUND)
        elif LIMIT_EXCEEDED in export_to_csv_result_content:
            return_error(f"{LIMIT_EXCEEDED} (10,000 incidents). Try to run the same query with lower fetchdays value")
        else:
            raise ValueError(f"Couldn't export incidents to CSV. {export_to_csv_result=}")
        return

    demisto.debug(f"{export_to_csv_result=}")
    export_to_csv_result_content = export_to_csv_result[0].get("Contents", {})
    csv_file_name = export_to_csv_result_content.get("response")

    # download the file and return to the war room
    incident_csv_result = demisto.executeCommand("core-api-get", {"uri": f"/incident/csv/{csv_file_name}"})
    if is_error(incident_csv_result):
        raise ValueError(f"Error {get_error(incident_csv_result)} when trying to retrieve the CSV")

    demisto.debug(f"{incident_csv_result=}")
    file = incident_csv_result[0].get("Contents", {}).get("response", "")
    demisto.results(fileResult(csv_file_name, file))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
