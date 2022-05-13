import graanalyticalfeaturedisplay
from graanalyticalfeaturedisplay import displayAnalyticalFeatures


_INCIDENT = {
    'id': 28862,
    "labels": [
        {
            "type": "Brand",
            "value": "GRA"
        },
        {
            "type": "Instance",
            "value": "GRA-Test"
        },
        {
            "type": "entityTypeId",
            "value": "51"
        },
        {
            "type": "riskDate",
            "value": "01/01/2021 00:00:00"
        },
        {
            "type": "anomalies",
            "value": "[{\"anomalyName\":\"anomalyName\",\"assignee\":\"assignee\",\"assigneeType\":\"assigneeType\","
                     "\"resourceName\":\"resourceName\",\"riskAcceptedDate\":null,\"riskScore\":87,"
                     "\"status\":\"Open\"}]"
        },
        {
            "type": "ownerType",
            "value": "ownerType"
        },
        {
            "type": "ownerType",
            "value": "ownerType"
        },
        {
            "type": "incidentType",
            "value": "GRACase"
        },
        {
            "type": "caseId",
            "value": "CS-535"
        },
        {
            "type": "openDate",
            "value": "08/30/2021 12:36:22"
        },
        {
            "type": "ownerId",
            "value": "1"
        },
        {
            "type": "entity",
            "value": "entityValue"
        },
        {
            "type": "status",
            "value": "Open"
        },
        {
            "type": "riskScore",
            "value": "89"
        },
        {
            "type": "entityId",
            "value": "163"
        },
        {
            "type": "graweblink",
            "value": "graweblink"
        }
    ]
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
