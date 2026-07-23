import graanalyticalfeaturedisplay
from graanalyticalfeaturedisplay import displayAnalyticalFeatures

_INCIDENT = {
    "CustomFields": {
        "gracase": "CS-1",
        "gracaseanomalydetails": [
            {
                "anomalyname": "anomaly_name",
                "assignee": "assignee_name",
                "assigneetype": "assignee_type",
                "resourcename": "resource_name",
                "riskaccepteddate": "null",
                "riskscore": "0",
                "status": "open",
            },
        ],
    },
    "id": 28862,
    "sourceInstance": "instance_name",
    "labels": [
        {"type": "Brand", "value": "GRA"},
        {"type": "Instance", "value": "GRA-Test"},
        {"type": "entityTypeId", "value": "51"},
        {"type": "riskDate", "value": "01/01/2021 00:00:00"},
        {
            "type": "anomalies",
            "value": '[{"anomalyName":"anomalyName","assignee":"assignee","assigneeType":"assigneeType",'
            '"resourceName":"resourceName","riskAcceptedDate":null,"riskScore":87,'
            '"status":"Open"}]',
        },
        {"type": "ownerType", "value": "ownerType"},
        {"type": "ownerType", "value": "ownerType"},
        {"type": "incidentType", "value": "GRACase"},
        {"type": "caseId", "value": "CS-535"},
        {"type": "openDate", "value": "08/30/2021 12:36:22"},
        {"type": "ownerId", "value": "1"},
        {"type": "entity", "value": "entityValue"},
        {"type": "status", "value": "Open"},
        {"type": "riskScore", "value": "89"},
        {"type": "entityId", "value": "163"},
        {"type": "graweblink", "value": "graweblink"},
    ],
}


def test_gra_analytical_feature_display(monkeypatch, mocker):
    """
    Scenario: This script executes the 'gra-analytical-features-entity-value' command to display Analytical Features.

    Given
    - An alert incident

    When
    - Display Analytical Features.

    Then
    - Ensure the correct parameters to the gra-analytical-features-entity-value command
    """
    monkeypatch.setattr(graanalyticalfeaturedisplay, "_get_incident", lambda: _INCIDENT)
    response = displayAnalyticalFeatures()
    expected = None
    assert response == expected


_INCIDENT_GRA = {
    "CustomFields": {
        "graincident": "IN-1",
        "graincidentanomalydetails": [
            {
                "anomalyname": "anomaly_name",
                "assignee": "assignee_name",
                "assigneetype": "assignee_type",
                "resourcename": "resource_name",
                "riskaccepteddate": "null",
                "riskscore": "0",
                "status": "open",
            },
        ],
    },
    "id": 28863,
    "sourceInstance": "instance_name",
    "labels": [
        {"type": "entityTypeId", "value": "51"},
        {"type": "riskDate", "value": "01/01/2021 00:00:00"},
        {"type": "entity", "value": "entityValue"},
    ],
}


def test_gra_analytical_feature_display_incident_path(monkeypatch, mocker):
    """Ensure graincidentanomalydetails is used for GRA Incident incidents."""
    monkeypatch.setattr(graanalyticalfeaturedisplay, "_get_incident", lambda: _INCIDENT_GRA)
    execute_mocker = mocker.patch.object(graanalyticalfeaturedisplay, "execute_command", return_value=None)
    response = displayAnalyticalFeatures()
    assert response is None
    execute_mocker.assert_called_once_with(
        "gra-analytical-features-entity-value",
        {
            "entityValue": "entityValue",
            "modelName": "anomaly_name",
            "fromDate": "2021-01-01",
            "toDate": "2021-01-01",
            "entityTypeId": "51",
            "using": "instance_name",
        },
    )
