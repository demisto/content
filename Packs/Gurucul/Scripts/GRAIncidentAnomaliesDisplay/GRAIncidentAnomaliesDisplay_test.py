import demistomock as demisto
import GRAIncidentAnomaliesDisplay
from GRAIncidentAnomaliesDisplay import get_anomalies_by_incident_id

_INCIDENT = {
    "id": 100,
    "sourceInstance": "instance_name",
    "CustomFields": {
        "graincident": "IN-33",
        "graincidentanomalydetails": [
            {
                "anomalyname": "anomalyName1",
                "status": "Open",
                "assignee": "assignee1",
                "assigneetype": "User",
                "resourcename": "resourceName1",
                "riskaccepteddate": None,
                "riskscore": 92,
            }
        ],
    },
}


def test_missing_graincident(mocker):
    mocker.patch.object(demisto, "incident", return_value={"id": 1, "CustomFields": {}})
    return_results_mocker = mocker.patch.object(GRAIncidentAnomaliesDisplay, "return_results")

    get_anomalies_by_incident_id()

    return_results_mocker.assert_called_once_with("No GRA incident id (graincident) on this incident.")


def test_anomaly_status_change_triggers_set_incident(mocker):
    mocker.patch.object(demisto, "incident", return_value=_INCIDENT)
    mocker.patch.object(
        GRAIncidentAnomaliesDisplay,
        "execute_command",
        side_effect=[
            [
                {
                    "anomalyName": "anomalyName1",
                    "status": "Closed",
                    "assignee": "assignee1",
                    "assigneeType": "User",
                    "resourceName": "resourceName1",
                    "riskAcceptedDate": None,
                    "riskScore": 92,
                }
            ],
            None,
        ],
    )
    return_results_mocker = mocker.patch.object(GRAIncidentAnomaliesDisplay, "return_results")

    get_anomalies_by_incident_id()

    calls = GRAIncidentAnomaliesDisplay.execute_command.call_args_list
    assert calls[0][0] == ("gra-incidents-anomaly", {"incidentId": "33", "using": "instance_name"})
    assert calls[1][0][0] == "setIncident"
    assert calls[1][0][1]["graincidentanomalydetails"][0]["status"] == "Closed"
    return_results_mocker.assert_called_once_with(
        "There is 1 anomaly update identified for this incident. " "Refresh Analytical Features for updated attributes list."
    )


def test_no_anomaly_changes(mocker):
    mocker.patch.object(demisto, "incident", return_value=_INCIDENT)
    mocker.patch.object(
        GRAIncidentAnomaliesDisplay,
        "execute_command",
        return_value=[
            {
                "anomalyName": "anomalyName1",
                "status": "Open",
                "assignee": "assignee1",
                "assigneeType": "User",
                "resourceName": "resourceName1",
                "riskAcceptedDate": None,
                "riskScore": 92,
            }
        ],
    )
    return_results_mocker = mocker.patch.object(GRAIncidentAnomaliesDisplay, "return_results")

    get_anomalies_by_incident_id()

    assert GRAIncidentAnomaliesDisplay.execute_command.call_count == 1
    return_results_mocker.assert_called_once_with("There are no anomaly changes identified for this incident.")
