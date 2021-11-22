import pytest
from CommonServerPython import *
import OpsGenieV3
from unittest.mock import MagicMock


def test_create_alert_wrong_responders():
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.create_alert(mock_client, {'responders': ['team', 'id']})


def test_get_alerts():
    mock_client = OpsGenieV3.Client(base_url="")
    mock_client.get_alert = MagicMock()
    OpsGenieV3.get_alerts(mock_client, {"alert-id": 1234})
    assert mock_client.get_alert.called
    OpsGenieV3.list_alerts = MagicMock()
    OpsGenieV3.get_alerts(mock_client, {})
    assert OpsGenieV3.list_alerts.called


def test_assign_alert_without_args():
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.assign_alert(mock_client, {})


def test_add_responder_alert_wrong_responders():
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.assign_alert(mock_client, {'responders': ['team', 'id']})


def test_get_escalations():
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.escalate_alert(mock_client, {})


def test_escalate_alert_without_args():
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.escalate_alert(mock_client, {})


def test_get_schedules():
    mock_client = OpsGenieV3.Client(base_url="")
    mock_client.get_schedule = MagicMock()
    OpsGenieV3.get_schedules(mock_client, {"schedule_id": 1234})
    assert mock_client.get_schedule.called
    mock_client.list_schedules = MagicMock()
    OpsGenieV3.get_schedules(mock_client, {})
    assert mock_client.list_schedules.called


def test_get_schedule_overrides_without_args():
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.get_schedule_overrides(mock_client, {})


def test_get_on_call_without_args():
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.get_on_call(mock_client, {})


def test_create_incident():
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.create_incident(mock_client, {'responders': ['team', 'id']})


def test_get_incidents():
    mock_client = OpsGenieV3.Client(base_url="")
    mock_client.get_incident = MagicMock()
    OpsGenieV3.get_incidents(mock_client, {"incident_id": 1234})
    assert mock_client.get_incident.called
    OpsGenieV3.list_incidents = MagicMock()
    OpsGenieV3.get_incidents(mock_client, {})
    assert OpsGenieV3.list_incidents.called


def test_add_responder_incident():
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.add_responder_incident(mock_client, {'responders': ['team', 'id']})


def test_get_teams():
    mock_client = OpsGenieV3.Client(base_url="")
    mock_client.get_team = MagicMock()
    OpsGenieV3.get_teams(mock_client, {"team_id": 1234})
    assert mock_client.get_team.called
    mock_client.list_teams = MagicMock()
    OpsGenieV3.get_teams(mock_client, {})
    assert mock_client.list_teams.called
