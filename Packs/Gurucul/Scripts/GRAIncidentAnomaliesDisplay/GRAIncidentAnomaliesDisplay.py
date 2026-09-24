import traceback

import demistomock as demisto
from CommonServerPython import *


def _grid_cell(value):
    if value is None:
        return ""
    if isinstance(value, str) and value.strip().lower() in {"null", "none"}:
        return ""
    return value


def get_anomalies_by_incident_id():
    incident = demisto.incident()

    custom_fields = incident.get("CustomFields") or {}
    gra_incident_id = custom_fields.get("graincident") or ""
    if not gra_incident_id:
        return_results("No GRA incident id (graincident) on this incident.")
        return

    old_anomalies = custom_fields.get("graincidentanomalydetails") or []

    incident_id = gra_incident_id.split("-")[-1]
    if incident_id != "":
        res = execute_command("gra-incidents-anomaly", {"incidentId": incident_id, "using": incident.get("sourceInstance")})
        anomalies_changed_count = 0

        if res is not None:
            updated_anomalies = []
            for anomaly in res:
                if anomaly is not None:
                    new_anomaly = {
                        "anomalyname": _grid_cell(anomaly.get("anomalyName")),
                        "riskaccepteddate": _grid_cell(anomaly.get("riskAcceptedDate")),
                        "datasourcename": _grid_cell(anomaly.get("datasourcename")),
                        "riskscore": _grid_cell(anomaly.get("riskScore")),
                        "assignee": _grid_cell(anomaly.get("assignee")),
                        "assigneetype": _grid_cell(anomaly.get("assigneeType")),
                        "status": _grid_cell(anomaly.get("status")),
                    }
                    updated_anomalies.append(new_anomaly)

                    for old_anomaly in old_anomalies:
                        if old_anomaly.get("anomalyname") == anomaly.get("anomalyName") and (
                            old_anomaly.get("status") != anomaly.get("status")
                            or old_anomaly.get("assignee") != anomaly.get("assignee")
                        ):
                            anomalies_changed_count += 1
                            break

            if anomalies_changed_count == 0 and len(old_anomalies) != len(updated_anomalies):
                anomalies_changed_count = len(updated_anomalies) - len(old_anomalies)

            if anomalies_changed_count != 0:
                execute_command("setIncident", {"id": incident.get("id"), "graincidentanomalydetails": updated_anomalies})
                if anomalies_changed_count == 1:
                    return_results(
                        "There is 1 anomaly update identified for this incident. "
                        "Refresh Analytical Features for updated attributes list."
                    )
                else:
                    return_results(
                        f"There are {anomalies_changed_count} anomaly updates identified for this "
                        f"incident. Refresh Analytical Features for updated attributes list."
                    )
            else:
                return_results("There are no anomaly changes identified for this incident.")


def main():
    try:
        get_anomalies_by_incident_id()
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute gra-incidents-anomaly. Error: {ex!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
