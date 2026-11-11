import demistomock as demisto
import graupdateincidentstatus
from graupdateincidentstatus import close_incident

_INCIDENT = {
    "id": 28862,
    "sourceInstance": "instance_name",
    "labels": [{"type": "incidentId", "value": "33"}],
}

_INCIDENT_CUSTOM_FIELD = {
    "id": 28863,
    "sourceInstance": "instance_name",
    "labels": [],
    "CustomFields": {"graincident": "IN-44"},
}


def test_gra_update_incident_status(monkeypatch, mocker):
    """Ensure gra-incident-action is called with label incidentId."""
    monkeypatch.setattr(graupdateincidentstatus, "_get_incident", lambda: _INCIDENT)
    execute_mocker = mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": "ok"}])
    close_incident()
    execute_mocker.assert_called_with(
        "gra-incident-action",
        {
            "action": "closeIncident",
            "subOption": "True Incident",
            "incidentId": "33",
            "incidentComment": "",
            "using": "instance_name",
        },
    )


def test_gra_update_incident_status_graincident_fallback(monkeypatch, mocker):
    """Ensure incident id is taken from CustomFields.graincident when labels are empty."""
    monkeypatch.setattr(graupdateincidentstatus, "_get_incident", lambda: _INCIDENT_CUSTOM_FIELD)
    execute_mocker = mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": "ok"}])
    close_incident()
    execute_mocker.assert_called_with(
        "gra-incident-action",
        {
            "action": "closeIncident",
            "subOption": "True Incident",
            "incidentId": "44",
            "incidentComment": "",
            "using": "instance_name",
        },
    )


def test_gra_update_incident_status_false_positive(monkeypatch, mocker):
    """False Positive close reason maps to modelReviewIncident / Tuning Required."""
    monkeypatch.setattr(graupdateincidentstatus, "_get_incident", lambda: _INCIDENT)
    mocker.patch.object(demisto, "args", return_value={"closeReason": "False Positive", "closeNotes": "fp"})
    execute_mocker = mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": "ok"}])
    close_incident()
    execute_mocker.assert_called_with(
        "gra-incident-action",
        {
            "action": "modelReviewIncident",
            "subOption": "Tuning Required",
            "incidentId": "33",
            "incidentComment": "fp",
            "using": "instance_name",
        },
    )


def test_gra_update_incident_status_other(monkeypatch, mocker):
    """Other close reason maps to modelReviewIncident / Others."""
    monkeypatch.setattr(graupdateincidentstatus, "_get_incident", lambda: _INCIDENT)
    mocker.patch.object(demisto, "args", return_value={"closeReason": "Other", "closeNotes": "review"})
    execute_mocker = mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": "ok"}])
    close_incident()
    execute_mocker.assert_called_with(
        "gra-incident-action",
        {
            "action": "modelReviewIncident",
            "subOption": "Others",
            "incidentId": "33",
            "incidentComment": "review",
            "using": "instance_name",
        },
    )
