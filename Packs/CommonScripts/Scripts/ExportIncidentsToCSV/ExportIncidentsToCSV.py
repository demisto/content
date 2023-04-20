import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    incident_query = demisto.args().get("query")
    incident_fetch_back_days = int(demisto.args().get("fetchdays"))

    if demisto.args().get("columns"):
        incident_columns = [x.strip() for x in demisto.args().get("columns").split(",")]
    else:
        incident_columns = ["id", "name", "type", "severity", "status", "owner",
                            "roles", "playbookId", "occurred", "created", "modified", "closed"]

    # body for the incident request
    incident_body = {
        "all": True,
        "filter": {
            "query": incident_query,
            "sort": [{
                "field": "id",
                "asc": False
            }],
            "period": {
                "by": "day",
                "fromValue": incident_fetch_back_days
            }
        },
        "columns": incident_columns
    }

    # generate the file
    res = demisto.executeCommand("demisto-api-post", {"uri": "/incident/batch/exportToCsv",
                                                      "body": incident_body})[0]["Contents"]["response"]

    # download the file and return to the war room
    file = demisto.executeCommand("demisto-api-get", {"uri": f"/incident/csv/{res}"})[0]["Contents"]["response"]
    demisto.results(fileResult(res, file))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
