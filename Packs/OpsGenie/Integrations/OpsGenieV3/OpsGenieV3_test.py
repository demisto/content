import pytest
import io
from CommonServerPython import *
import OpsGenieV3
from unittest import mock


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_create_alert_wrong_responders():
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.create_alert(mock_client, {'responders': ['team', 'id']})


def test_create_alert(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'create_alert',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/create_alert.json'))
    res = OpsGenieV3.create_alert(mock_client, {'responders': []})
    assert (res.raw_response == util_load_json('test_data/create_alert.json'))


def test_get_alerts(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'list_alerts',
                        return_value=util_load_json('test_data/get_alerts.json'))
    res = OpsGenieV3.get_alerts(mock_client, {"limit": 1})
    assert (len(res.outputs) == 1)


def test_get_alerts_going_to_right_function():
    mock_client = OpsGenieV3.Client(base_url="")
    mock_client.get_alert = mock.MagicMock()
    OpsGenieV3.get_alerts(mock_client, {"alert-id": 1234})
    assert mock_client.get_alert.called
    OpsGenieV3.list_alerts = mock.MagicMock()
    OpsGenieV3.get_alerts(mock_client, {})
    assert OpsGenieV3.list_alerts.called


def test_delete_alert(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'delete_alert',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/delete_alert.json'))
    res = OpsGenieV3.delete_alert(mock_client, {"alert-id": 1234})
    assert (res.raw_response == util_load_json('test_data/delete_alert.json'))


def test_ack_alert(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'ack_alert',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/ack_alert.json'))
    res = OpsGenieV3.ack_alert(mock_client, {"alert-id": 1234})
    assert (res.raw_response == util_load_json('test_data/ack_alert.json'))


def test_close_alert(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'close_alert',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/close_alert.json'))
    res = OpsGenieV3.close_alert(mock_client, {"alert-id": 1234})
    assert (res.raw_response == util_load_json('test_data/close_alert.json'))


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
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/add_alert_tag.json'))
    res = OpsGenieV3.add_alert_tag(mock_client, {"alert-id": 1234, "tags": [1, 2]})
    assert (res.raw_response == util_load_json('test_data/add_alert_tag.json'))


def test_remove_alert_tag(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'remove_alert_tag',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/remove_alert_tag.json'))
    res = OpsGenieV3.remove_alert_tag(mock_client, {"alert-id": 1234, "tags": [1, 2]})
    assert (res.raw_response == util_load_json('test_data/remove_alert_tag.json'))


def test_get_alert_attachments(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'get_alert_attachments',
                        return_value=util_load_json('test_data/get_alert_attachments.json'))
    res = OpsGenieV3.get_alert_attachments(mock_client, {"alert-id": 1234})
    assert (res.readable_output == "### OpsGenie Attachment\n**No entries.**\n")


def test_get_schedules():
    mock_client = OpsGenieV3.Client(base_url="")
    mock_client.get_schedule = mock.MagicMock()
    OpsGenieV3.get_schedules(mock_client, {"schedule_id": 1234})
    assert mock_client.get_schedule.called
    mock_client.list_schedules = mock.MagicMock()
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
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/delete_incident.json'))
    res = OpsGenieV3.delete_incident(mock_client, {"incident_id": 1234})
    assert (res.raw_response == util_load_json('test_data/delete_incident.json'))


def test_get_incidents(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'list_incidents',
                        return_value=util_load_json('test_data/get_incidents.json'))
    res = OpsGenieV3.get_incidents(mock_client, {"limit": 1})
    assert (len(res.outputs) == 1)


def test_get_incidents_going_to_right_function():
    mock_client = OpsGenieV3.Client(base_url="")
    mock_client.get_incident = mock.MagicMock()
    OpsGenieV3.get_incidents(mock_client, {"incident_id": 1234})
    assert mock_client.get_incident.called
    OpsGenieV3.list_incidents = mock.MagicMock()
    OpsGenieV3.get_incidents(mock_client, {})
    assert OpsGenieV3.list_incidents.called


def test_close_incident(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'close_incident',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/close_incident.json'))
    res = OpsGenieV3.close_incident(mock_client, {"incident_id": 1234})
    assert (res.raw_response == util_load_json('test_data/close_incident.json'))


def test_resolve_incident(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'resolve_incident',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/resolve_incident.json'))
    res = OpsGenieV3.resolve_incident(mock_client, {"incident_id": 1234})
    assert (res.raw_response == util_load_json('test_data/resolve_incident.json'))


def test_add_responder_incident():
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.add_responder_incident(mock_client, {'responders': ['team', 'id']})


def test_add_tag_incident(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'add_tag_incident',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/add_tag_incident.json'))
    res = OpsGenieV3.add_tag_incident(mock_client, {"incident_id": 1234, "tags": [1, 2]})
    assert (res.raw_response == util_load_json('test_data/add_tag_incident.json'))


def test_remove_tag_incident(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'remove_tag_incident',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/remove_tag_incident.json'))
    res = OpsGenieV3.remove_tag_incident(mock_client, {"incident_id": 1234, "tags": [1, 2]})
    assert (res.raw_response == util_load_json('test_data/remove_tag_incident.json'))


def test_get_teams(mocker):
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'list_teams',
                        return_value=util_load_json('test_data/get_teams.json'))
    res = OpsGenieV3.get_teams(mock_client, {})
    assert len(res.outputs) == 2


def test_get_teams_going_to_right_function():
    mock_client = OpsGenieV3.Client(base_url="")
    mock_client.get_team = mock.MagicMock()
    OpsGenieV3.get_teams(mock_client, {"team_id": 1234})
    assert mock_client.get_team.called
    mock_client.list_teams = mock.MagicMock()
    OpsGenieV3.get_teams(mock_client, {})
    assert mock_client.list_teams.called


def test_fetch_incidents_command(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'list_alerts',
                        return_value=util_load_json('test_data/get_alerts.json'))
    mocker.patch.object(mock_client, 'list_incidents',
                        return_value=util_load_json('test_data/get_incidents.json'))
    res, last_run = OpsGenieV3.fetch_incidents_command(mock_client, {"max_fetch": 1})
    assert len(res) == 2


def test_fetch_with_paging(mocker):
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'list_alerts',
                        return_value=util_load_json('test_data/get_alerts.json'))
    mocker.patch.object(mock_client, 'get_paged',
                        return_value=util_load_json('test_data/get_alerts_without_next.json'))
    mocker.patch.object(OpsGenieV3, '_get_utc_now', return_value=datetime(2021, 11, 26))
    mocker.patch.object(OpsGenieV3, '_parse_fetch_time', return_value='2021-11-23T12:19:48Z')
    res, last_run = OpsGenieV3.fetch_incidents_command(mock_client, {"max_fetch": 2,
                                                                     "event_types": OpsGenieV3.ALERT_TYPE})
    assert (last_run == {'Alerts': {'lastRun': '2021-11-26T00:00:00Z',
                                    'next_page': 'https://api.opsgenie.com/v2/alerts?limit=1&sort=createdAt&offset=1&order=desc'},
                         'Incidents': {'lastRun': None, 'next_page': None}})
    mocker.patch.object(demisto, 'getLastRun', return_value=last_run)
    res, last_run = OpsGenieV3.fetch_incidents_command(mock_client,
                                                       {"max_fetch": 2, "event_types": OpsGenieV3.ALERT_TYPE},
                                                       last_run)
    assert (last_run == {'Alerts': {'lastRun': '2021-11-26T00:00:00Z', 'next_page': None},
                         'Incidents': {'lastRun': None, 'next_page': None}})


def test_build_query_fetch(mocker):
    args = {
        "query": "createdAt < 147039484114",
        "status": "Open",
        "is_fetch_query": True,
        "priority": "P1,P3",
        "tags": "1,2"
    }
    mock_client = OpsGenieV3.Client(base_url="")
    res = mock_client.build_query(args)
    assert (res == "createdAt < 147039484114 AND status=open AND priority: (P1 OR P3) AND tag: (1 OR 2)")


def test_build_query_not_fetch(mocker):
    args = {
        "query": "createdAt < 147039484114",
        "status": "Open",
        "is_fetch_query": False,
        "priority": "P1,P3",
        "tags": "1,2"
    }
    mock_client = OpsGenieV3.Client(base_url="")
    res = mock_client.build_query(args)
    assert (res == "createdAt < 147039484114")


def test_build_query_not_fetch_without_query(mocker):
    args = {
        "status": "Open",
        "is_fetch_query": False,
        "priority": "P1,P3",
        "tags": "1,2"
    }
    mock_client = OpsGenieV3.Client(base_url="")
    res = mock_client.build_query(args)
    assert (res == "status=open AND priority: (P1 OR P3) AND tag: (1 OR 2)")
