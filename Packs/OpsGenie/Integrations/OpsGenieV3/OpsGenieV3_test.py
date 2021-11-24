import pytest
import io
from CommonServerPython import *
import OpsGenieV3
from unittest.mock import MagicMock


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_create_alert_wrong_responders():
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.create_alert(mock_client, {'responders': ['team', 'id']})


def test_get_alerts(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'list_alerts',
                        return_value=util_load_json('test_data/get_alerts.json'))
    res = OpsGenieV3.get_alerts(mock_client, {"limit": 1})
    assert (len(res.outputs) == 1)


def test_get_alerts_going_to_right_function():
    mock_client = OpsGenieV3.Client(base_url="")
    mock_client.get_alert = MagicMock()
    OpsGenieV3.get_alerts(mock_client, {"alert-id": 1234})
    assert mock_client.get_alert.called
    OpsGenieV3.list_alerts = MagicMock()
    OpsGenieV3.get_alerts(mock_client, {})
    assert OpsGenieV3.list_alerts.called


def test_delete_alert(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'delete_alert',
                        return_value=util_load_json('test_data/request.json'))
    res = OpsGenieV3.delete_alert(mock_client, {"alert-id": 1234})
    assert(res.readable_output == "Waiting for request_id=3b078fd5-37d1-472e-823b-9f95b17aba8f")


def test_ack_alert(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'ack_alert',
                        return_value=util_load_json('test_data/request.json'))
    res = OpsGenieV3.ack_alert(mock_client, {"alert-id": 1234})
    assert (res.readable_output == "Waiting for request_id=3b078fd5-37d1-472e-823b-9f95b17aba8f")


def test_close_alert(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'close_alert',
                        return_value=util_load_json('test_data/request.json'))
    res = OpsGenieV3.close_alert(mock_client, {"alert-id": 1234})
    assert (res.readable_output == "Waiting for request_id=3b078fd5-37d1-472e-823b-9f95b17aba8f")


def test_assign_alert_without_args():
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.assign_alert(mock_client, {})


def test_add_responder_alert_wrong_responders():
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.assign_alert(mock_client, {'responders': ['team', 'id']})


def test_get_escalations_without_args():
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.escalate_alert(mock_client, {})


def test_get_escalations(mocker):
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'get_escalations',
                        return_value=util_load_json('test_data/get_escalations.json'))
    res = OpsGenieV3.get_escalations(mock_client, {})
    assert len(res.outputs) == 2


def test_escalate_alert_without_args():
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.escalate_alert(mock_client, {})


def test_add_alert_tag(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'add_alert_tag',
                        return_value=util_load_json('test_data/request.json'))
    res = OpsGenieV3.add_alert_tag(mock_client, {"alert-id": 1234, "tags": [1, 2]})
    assert (res.readable_output == "Waiting for request_id=3b078fd5-37d1-472e-823b-9f95b17aba8f")


def test_remove_alert_tag(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'remove_alert_tag',
                        return_value=util_load_json('test_data/request.json'))
    res = OpsGenieV3.remove_alert_tag(mock_client, {"alert-id": 1234, "tags": [1, 2]})
    assert (res.readable_output == "Waiting for request_id=3b078fd5-37d1-472e-823b-9f95b17aba8f")


def test_get_alert_attachments(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'get_alert_attachments',
                        return_value=util_load_json('test_data/get_alert_attachments.json'))
    res = OpsGenieV3.get_alert_attachments(mock_client, {"alert-id": 1234})
    assert (res.readable_output == "### OpsGenie Attachment\n**No entries.**\n")


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


def test_delete_incident(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'delete_incident',
                        return_value=util_load_json('test_data/request.json'))
    res = OpsGenieV3.delete_incident(mock_client, {"incident_id": 1234})
    assert (res.readable_output == "Waiting for request_id=3b078fd5-37d1-472e-823b-9f95b17aba8f")


def test_get_incidents(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'list_incidents',
                        return_value=util_load_json('test_data/get_incidents.json'))
    res = OpsGenieV3.get_incidents(mock_client, {"limit": 1})
    assert (len(res.outputs) == 1)


def test_get_incidents_going_to_right_function():
    mock_client = OpsGenieV3.Client(base_url="")
    mock_client.get_incident = MagicMock()
    OpsGenieV3.get_incidents(mock_client, {"incident_id": 1234})
    assert mock_client.get_incident.called
    OpsGenieV3.list_incidents = MagicMock()
    OpsGenieV3.get_incidents(mock_client, {})
    assert OpsGenieV3.list_incidents.called


def test_close_incident(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'close_incident',
                        return_value=util_load_json('test_data/request.json'))
    res = OpsGenieV3.close_incident(mock_client, {"incident_id": 1234})
    assert (res.readable_output == "Waiting for request_id=3b078fd5-37d1-472e-823b-9f95b17aba8f")


def test_resolve_incident(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'resolve_incident',
                        return_value=util_load_json('test_data/request.json'))
    res = OpsGenieV3.resolve_incident(mock_client, {"incident_id": 1234})
    assert (res.readable_output == "Waiting for request_id=3b078fd5-37d1-472e-823b-9f95b17aba8f")


def test_add_responder_incident():
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.add_responder_incident(mock_client, {'responders': ['team', 'id']})


def test_add_tag_incident(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'add_tag_incident',
                        return_value=util_load_json('test_data/request.json'))
    res = OpsGenieV3.add_tag_incident(mock_client, {"incident_id": 1234, "tags": [1, 2]})
    assert (res.readable_output == "Waiting for request_id=3b078fd5-37d1-472e-823b-9f95b17aba8f")


def test_remove_tag_incident(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'remove_tag_incident',
                        return_value=util_load_json('test_data/request.json'))
    res = OpsGenieV3.remove_tag_incident(mock_client, {"incident_id": 1234, "tags": [1, 2]})
    assert (res.readable_output == "Waiting for request_id=3b078fd5-37d1-472e-823b-9f95b17aba8f")


def test_get_teams(mocker):
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'list_teams',
                        return_value=util_load_json('test_data/get_teams.json'))
    res = OpsGenieV3.get_teams(mock_client, {})
    assert len(res.outputs) == 2


def test_get_teams_going_to_right_function():
    mock_client = OpsGenieV3.Client(base_url="")
    mock_client.get_team = MagicMock()
    OpsGenieV3.get_teams(mock_client, {"team_id": 1234})
    assert mock_client.get_team.called
    mock_client.list_teams = MagicMock()
    OpsGenieV3.get_teams(mock_client, {})
    assert mock_client.list_teams.called


def test_get_polling_result_not_finished(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/request.json'))
    res = OpsGenieV3.get_polling_result(mock_client, {'request_id': "3b078fd5-37d1-472e-823b-9f95b17aba8f"})
    assert isinstance(res, CommandResults)
    assert res.scheduled_command


def test_get_polling_result_finished(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/get_request.json'))
    res = OpsGenieV3.get_polling_result(mock_client, {'request_id': "f04636e9-4863-4bee-b13b-9eef0e1f3165"})
    assert isinstance(res, CommandResults)
    assert not res.scheduled_command
