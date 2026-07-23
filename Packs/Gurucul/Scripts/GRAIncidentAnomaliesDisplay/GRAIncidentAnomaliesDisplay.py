import demistomock as demisto
from CommonServerPython import *


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
        res = execute_command("gra-incidents-anomaly", {"incidentId": incident_id, "using": incident["sourceInstance"]})
        anomalies_changed_count = 0

        if res is not None:
            updated_anomalies = []
            for anomaly in res:
                if anomaly is not None:
                    new_anomaly = {
                        "anomalyname": anomaly["anomalyName"],
                        "riskaccepteddate": anomaly["riskAcceptedDate"],
                        "resourcename": anomaly["resourceName"],
                        "riskscore": anomaly["riskScore"],
                        "assignee": anomaly["assignee"],
                        "assigneetype": anomaly["assigneeType"],
                        "status": anomaly["status"],
                    }
                    updated_anomalies.append(new_anomaly)

                    for old_anomaly in old_anomalies:
                        if old_anomaly["anomalyname"] == anomaly["anomalyName"] and (
                            old_anomaly["status"] != anomaly["status"] or old_anomaly["assignee"] != anomaly["assignee"]
                        ):
                            anomalies_changed_count += 1
                            break

            if anomalies_changed_count == 0 and len(old_anomalies) != len(updated_anomalies):
                anomalies_changed_count = len(updated_anomalies) - len(old_anomalies)

            if anomalies_changed_count != 0:
                execute_command("setIncident", {"id": incident["id"], "graincidentanomalydetails": updated_anomalies})
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
        return_error(f"Failed to execute gra-incidents-anomaly. Error: {ex!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
