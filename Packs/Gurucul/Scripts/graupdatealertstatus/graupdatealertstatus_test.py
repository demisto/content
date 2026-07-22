import demistomock as demisto
import graupdatealertstatus
from graupdatealertstatus import close_alert

_INCIDENT = {
    "id": 28862,
    "sourceInstance": "instance_name",
    "labels": [{"type": "alertId", "value": "101"}],
}

_INCIDENT_CUSTOM_FIELD = {
    "id": 28863,
    "sourceInstance": "instance_name",
    "labels": [],
    "CustomFields": {"graalert": "AL-202"},
}


def test_gra_update_alert_status(monkeypatch, mocker):
    """Ensure gra-alert-action is called with label alertId."""
    monkeypatch.setattr(graupdatealertstatus, "_get_incident", lambda: _INCIDENT)
    execute_mocker = mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": "ok"}])
    close_alert()
    execute_mocker.assert_called_with(
        "gra-alert-action",
        {
            "action": "closeAlert",
            "alertId": "101",
            "alertComment": "",
            "incidentType": "Incident",
            "subStatus": "True Positive",
            "using": "instance_name",
        },
    )


def test_gra_update_alert_status_graalert_fallback(monkeypatch, mocker):
    """Ensure alert id is taken from CustomFields.graalert when labels are empty."""
    monkeypatch.setattr(graupdatealertstatus, "_get_incident", lambda: _INCIDENT_CUSTOM_FIELD)
    execute_mocker = mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": "ok"}])
    close_alert()
    execute_mocker.assert_called_with(
        "gra-alert-action",
        {
            "action": "closeAlert",
            "alertId": "202",
            "alertComment": "",
            "incidentType": "Incident",
            "subStatus": "True Positive",
            "using": "instance_name",
        },
    )


def test_gra_update_alert_status_false_positive(monkeypatch, mocker):
    """False Positive close reason maps to Not An Incident / False Positive."""
    monkeypatch.setattr(graupdatealertstatus, "_get_incident", lambda: _INCIDENT)
    mocker.patch.object(demisto, "args", return_value={"closeReason": "False Positive", "closeNotes": "fp"})
    execute_mocker = mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": "ok"}])
    close_alert()
    execute_mocker.assert_called_with(
        "gra-alert-action",
        {
            "action": "closeAlert",
            "alertId": "101",
            "alertComment": "fp",
            "incidentType": "Not An Incident",
            "subStatus": "False Positive",
            "using": "instance_name",
        },
    )


def test_gra_update_alert_status_other(monkeypatch, mocker):
    """Other close reason maps to Not An Incident / Model Review."""
    monkeypatch.setattr(graupdatealertstatus, "_get_incident", lambda: _INCIDENT)
    mocker.patch.object(demisto, "args", return_value={"closeReason": "Other", "closeNotes": "review"})
    execute_mocker = mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": "ok"}])
    close_alert()
    execute_mocker.assert_called_with(
        "gra-alert-action",
        {
            "action": "closeAlert",
            "alertId": "101",
            "alertComment": "review",
            "incidentType": "Not An Incident",
            "subStatus": "Model Review",
            "using": "instance_name",
        },
    )
