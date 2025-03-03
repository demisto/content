import pytest

from requests import Response

from CommonServerPython import *
import OpsGenieV3
from unittest import mock


def util_load_json(path, wrap_in_response=False):
    with open(path, encoding='utf-8') as f:
        jsonres = json.loads(f.read())
        if wrap_in_response:
            res = Response()
            res.json = lambda: jsonres
            return res
        else:
            return jsonres


@pytest.mark.parametrize('arg1, arg2, expected_output', [
    ('given', 'given', False),
    ('given', None, True),
    (None, 'yes', True),
    (None, None, False)
])
def test_is_one_argument_given(arg1, arg2, expected_output):
    """
    Given:
        - Combinations of two arguments
    When:
        - Calling function is_one_argument_given
    Then:
        - Ensure the resultes are correct
    """
    assert OpsGenieV3.is_one_argument_given(arg1, arg2) == expected_output


def test_create_alert_wrong_responders():
    """
    Given:
        - An app client object
    When:
        - Calling function create_alert with argument responders in the wrong format
    Then:
        - Ensure the resulted will raise an exception.
    """
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.create_alert(mock_client, {'responders': ['team', 'id']})


def test_create_alert(mocker):
    """
    Given:
        - An app client object
        - Responders "team,id,123"
    When:
        - Calling function create_alert with argument responders in the right format
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'create_alert',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/create_alert.json', True))
    res = OpsGenieV3.create_alert(mock_client, {'responders': "team,id,123"})
    assert (res.raw_response == util_load_json('test_data/create_alert.json'))


def test_create_alert_with_tags(mocker):
    """
    Given:
        - An app client object
        - "tags": "tag_test"
    When:
        - Calling function create_alert with argument responders in the right format
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'create_alert',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/create_alert.json', True))
    res = OpsGenieV3.create_alert(mock_client, {'tags': ["tags_test"]})
    assert (res.raw_response == util_load_json('test_data/create_alert.json'))


def test_get_alerts(mocker):
    """
    Given:
        - An app client object
        - Limit = 1
    When:
        - Calling function list_alerts
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'list_alerts',
                        return_value=util_load_json('test_data/get_alerts.json'))
    res = OpsGenieV3.get_alerts(mock_client, {"limit": 1})
    assert (len(res.outputs) == 1)


def test_get_alerts_going_to_right_function():
    """
    Given:
        - An app client object
    When:
        - Calling function get_alerts
        Case A: "alert-id" = 1234
        Case B: No arguments
    Then:
        - Ensure the right function was called
        Case A: Called get_alert
        Case B: Called list_alerts
    """
    mock_client = OpsGenieV3.Client(base_url="")
    mock_client.get_alert = mock.MagicMock()
    OpsGenieV3.get_alerts(mock_client, {"alert-id": 1234})
    assert mock_client.get_alert.called
    OpsGenieV3.list_alerts = mock.MagicMock()
    OpsGenieV3.get_alerts(mock_client, {})
    assert OpsGenieV3.list_alerts.called


def test_delete_alert(mocker):
    """
    Given:
        - An app client object
        - Alert-id = 1234
    When:
        - Calling function delete_alert
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'delete_alert',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/delete_alert.json', True))
    res = OpsGenieV3.delete_alert(mock_client, {"alert-id": 1234})
    assert (res.raw_response == util_load_json('test_data/delete_alert.json'))


def test_ack_alert(mocker):
    """
    Given:
        - An app client object
        - Alert-id = 1234
    When:
        - Calling function ack_alert
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'ack_alert',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/ack_alert.json', True))
    res = OpsGenieV3.ack_alert(mock_client, {"alert-id": 1234})
    assert (res.raw_response == util_load_json('test_data/ack_alert.json'))


def test_close_alert(mocker):
    """
    Given:
        - An app client object
        - Alert-id = 1234
    When:
        - Calling function close_alert
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'close_alert',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/close_alert.json', True))
    res = OpsGenieV3.close_alert(mock_client, {"alert-id": 1234})
    assert (res.raw_response == util_load_json('test_data/close_alert.json'))


def test_assign_alert_without_args():
    """
    Given:
        - An app client object
    When:
        - Calling function assign_alert with no arguments
    Then:
        - Ensure the resulted will raise an exception.
    """
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.assign_alert(mock_client, {})


def test_assign_alert(mocker):
    """
    Given:
        - An app client object
        - Alert-id = 1234
        - Owner_id = 123
    When:
        - Calling function assign_alert
    Then:
        - Ensure the return data is correct
    """
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'assign_alert',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/assign_alert.json', True))
    res = OpsGenieV3.assign_alert(mock_client, {"alert-id": 1234, "owner_id": 123})
    assert (res.raw_response == util_load_json('test_data/assign_alert.json'))


def test_add_responder_alert_wrong_responders():
    """
    Given:
        - An app client object
    When:
        - Calling function add_responder_alert with argument responders in the wrong format
    Then:
        - Ensure the resulted will raise an exception.
    """
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.add_responder_alert(mock_client, {'responders': ['team', 'id']})


def test_add_responder_alert(mocker):
    """
    Given:
        - An app client object
        - Alert-id = 1234
        - owner_id = 123
    When:
        - Calling function add_responder_alert
    Then:
        - Ensure the return data is correct
    """
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'add_responder_alert',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/add_responder_alert.json', True))
    res = OpsGenieV3.add_responder_alert(mock_client, {"alert-id": 1234, "owner_id": 123})
    assert (res.raw_response == util_load_json('test_data/add_responder_alert.json'))


def test_get_escalations_without_args():
    """
    Given:
        - An app client object
    When:
        - Calling function escalate_alert with no arguments
    Then:
        - Ensure the resulted will raise an exception.
    """
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.escalate_alert(mock_client, {})


def test_get_escalations(mocker):
    """
    Given:
        - An app client object
    When:
        - Calling function get_escalations
    Then:
        - Ensure the return data is correct
    """
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'get_escalations',
                        return_value=util_load_json('test_data/get_escalations.json'))
    res = OpsGenieV3.get_escalations(mock_client, {})
    assert len(res.outputs) == 2


def test_get_escalation(mocker):
    """
    Given:
        - An app client object
        - escalation_id = 123
    When:
        - Calling function get_escalations
    Then:
        - Ensure the return data is correct
    """
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'get_escalation',
                        return_value=util_load_json('test_data/get_escalations.json'))
    res = OpsGenieV3.get_escalations(mock_client, {"escalation_id": 123})
    assert len(res.outputs) == 2


def test_escalate_alert_without_args():
    """
    Given:
        - An app client object
    When:
        - Calling function escalate_alert with no arguments
    Then:
        - Ensure the resulted will raise an exception.
    """
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.escalate_alert(mock_client, {})


def test_escalate_alert(mocker):
    """
    Given:
        - An app client object
        - Alert-id = 1234
        = escalation_id = 123
    When:
        - Calling function escalate_alert
    Then:
        - Ensure the return data is correct
    """
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'escalate_alert',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/escalate_alert.json', True))
    res = OpsGenieV3.escalate_alert(mock_client, {"alert-id": 1234, "escalation_id": 123})
    assert (res.raw_response == util_load_json('test_data/escalate_alert.json'))


def test_add_alert_tag(mocker):
    """
    Given:
        - An app client object
        - Alert-id = 1234
        - tags = [1,2]
    When:
        - Calling function add_alert_tag
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'add_alert_tag',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/add_alert_tag.json', True))
    res = OpsGenieV3.add_alert_tag(mock_client, {"alert-id": 1234, "tags": [1, 2]})
    assert (res.raw_response == util_load_json('test_data/add_alert_tag.json'))


def test_remove_alert_tag(mocker):
    """
    Given:
        - An app client object
        - Alert-id = 1234
        - tags = [1,2]
    When:
        - Calling function remove_alert_tag
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'remove_alert_tag',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/remove_alert_tag.json', True))
    res = OpsGenieV3.remove_alert_tag(mock_client, {"alert-id": 1234, "tags": [1, 2]})
    assert (res.raw_response == util_load_json('test_data/remove_alert_tag.json'))


def test_get_alert_attachments(mocker):
    """
    Given:
        - An app client object
        - Alert-id = 1234
    When:
        - Calling function get_alert_attachments
    Then:
        - Ensure the return data is correct
    """
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'get_alert_attachments',
                        return_value=util_load_json('test_data/get_alert_attachments.json'))
    res = OpsGenieV3.get_alert_attachments(mock_client, {"alert-id": 1234})
    assert (res.readable_output == "### OpsGenie Attachment\n**No entries.**\n")


def test_get_schedules():
    """
    Given:
        - An app client object
    When:
        - Calling function get_schedules
        Case A: "schedule_id" = 1234
        Case B: No arguments
    Then:
        - Ensure the right function was called
        Case A: Called get_schedule
        Case B: Called list_schedules
    """
    mock_client = OpsGenieV3.Client(base_url="")
    mock_client.get_schedule = mock.MagicMock()
    OpsGenieV3.get_schedules(mock_client, {"schedule_id": 1234})
    assert mock_client.get_schedule.called
    mock_client.list_schedules = mock.MagicMock()
    OpsGenieV3.get_schedules(mock_client, {})
    assert mock_client.list_schedules.called


def test_get_schedules_with_no_args():
    """
    Given:
        - An app client object
    When:
        - Calling function get_schedules with no arguments
    Then:
        - Ensure the resulted will raise an exception.
    """
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.Client.get_schedule(mock_client, {})


def test_get_schedules_with_both_args():
    """
    Given:
        - An app client object
    When:
        - Calling function get_schedules with both arguments
    Then:
        - Ensure the resulted will raise an exception.
    """
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.get_schedules(mock_client, {"schedule_id": "ID", "schedule_name": "NAME"})


def test_get_schedule_overrides_without_args():
    """
    Given:
        - An app client object
    When:
        - Calling function get_schedule_overrides with no arguments
    Then:
        - Ensure the resulted will raise an exception.
    """
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.get_schedule_overrides(mock_client, {})


def test_get_schedule_without_args():
    """
    Given:
        - An app client object
    When:
        - Calling function get_schedule with no arguments
    Then:
        - Ensure the resulted will raise an exception.
    """
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        mock_client.get_schedule({})


def test_get_schedule_overrides():
    """
    Given:
        - An app client object
    When:
        - Calling function get_schedule_overrides
        Case A: "schedule_id" = 1234 , override_alias = 123
        Case B: No arguments
    Then:
        - Ensure the right function was called
        Case A: Called get_schedule_override
        Case B: Called list_schedule_overrides
    """
    mock_client = OpsGenieV3.Client(base_url="")
    mock_client.get_schedule_override = mock.MagicMock()
    OpsGenieV3.get_schedule_overrides(mock_client, {"schedule_id": 1234, "override_alias": 123})
    assert mock_client.get_schedule_override.called
    mock_client.list_schedule_overrides = mock.MagicMock()
    OpsGenieV3.get_schedule_overrides(mock_client, {"schedule_id": 1234})
    assert mock_client.list_schedule_overrides.called


def test_get_on_call_without_args():
    """
    Given:
        - An app client object
    When:
        - Calling function get_on_call with no arguments
    Then:
        - Ensure the resulted will raise an exception.
    """
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.get_on_call(mock_client, {})


def test_get_on_call(mocker):
    """
    Given:
        - An app client object
        - schedule_id = 1234
    When:
        - Calling function get_on_call
    Then:
        - Ensure the return data is correct
    """
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'get_on_call',
                        return_value=util_load_json('test_data/delete_incident.json'))
    res = OpsGenieV3.get_on_call(mock_client, {"schedule_id": 1234})
    assert (res.raw_response == util_load_json('test_data/delete_incident.json'))


def test_get_on_call_wrong_date_format(mocker):
    """
    Given:
        - An app client object
        - schedule_id = 1234
        - start_date = "wrong_date_format"
    When:
        - Calling function get_on_call
    Then:
        - Ensure the resulted will raise an exception.
    """
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'get_on_call',
                        return_value=util_load_json('test_data/delete_incident.json'))
    with pytest.raises(ValueError):
        OpsGenieV3.get_on_call(mock_client, {"schedule_id": 1234, "starting_date": "wrong_date_format"})


def test_create_incident_wrong_args():
    """
    Given:
        - An app client object
    When:
        - Calling function create_incident with argument responders in the wrong format
    Then:
        - Ensure the resulted will raise an exception.
    """
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.create_incident(mock_client, {'responders': ['team', 'id']})


def test_create_incident(mocker):
    """
    Given:
        - An app client object
    When:
        - Calling function create_incident
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'create_incident',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/create_incident.json', True))
    res = OpsGenieV3.create_incident(mock_client, {})
    assert (res.raw_response == util_load_json('test_data/create_incident.json'))


def test_delete_incident(mocker):
    """
    Given:
        - incident_id = 1234
    When:
        - Calling function delete_incident
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'delete_incident',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/delete_incident.json', True))
    res = OpsGenieV3.delete_incident(mock_client, {"incident_id": 1234})
    assert (res.raw_response == util_load_json('test_data/delete_incident.json'))


def test_get_incidents(mocker):
    """
    Given:
        - An app client object
        - limit = 1
    When:
        - Calling function get_incidents
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'list_incidents',
                        return_value=util_load_json('test_data/get_incidents.json'))
    res = OpsGenieV3.get_incidents(mock_client, {"limit": 1})
    assert (len(res.outputs) == 1)


def test_responders_to_json():
    """
    Given:
        - An app client object
        - responders = ["team", "id", 1, "schedule", "name", "a"]
        - responder_key = 'responders'
    When:
        - Calling function responders_to_json
    Then:
        - Ensure the return data is correct
    """
    mock_client = OpsGenieV3.Client(base_url="")
    res = mock_client.responders_to_json(responders=["team", "id", 1, "schedule", "name", "a"],
                                         responder_key='responders')
    assert (res == {'responders': [{'id': 1, 'type': 'team'}, {'name': 'a', 'type': 'schedule'}]})


def test_get_incidents_going_to_right_function():
    """
    Given:
        - An app client object
    When:
        - Calling function get_incidents
        Case A: "incident_id" = 1234
        Case B: No arguments
    Then:
        - Ensure the right function was called
        Case A: Called get_incident
        Case B: Called list_incidents
    """
    mock_client = OpsGenieV3.Client(base_url="")
    mock_client.get_incident = mock.MagicMock()
    OpsGenieV3.get_incidents(mock_client, {"incident_id": 1234})
    assert mock_client.get_incident.called
    OpsGenieV3.list_incidents = mock.MagicMock()
    OpsGenieV3.get_incidents(mock_client, {})
    assert OpsGenieV3.list_incidents.called


def test_close_incident(mocker):
    """
    Given:
        - An app client object
        - incident_id = 1234
    When:
        - Calling function close_incident
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'close_incident',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/close_incident.json', True))
    res = OpsGenieV3.close_incident(mock_client, {"incident_id": 1234})
    assert (res.raw_response == util_load_json('test_data/close_incident.json'))


def test_resolve_incident(mocker):
    """
    Given:
        - An app client object
        - incident_id = 1234
    When:
        - Calling function resolve_incident
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'resolve_incident',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/resolve_incident.json', True))
    res = OpsGenieV3.resolve_incident(mock_client, {"incident_id": 1234})
    assert (res.raw_response == util_load_json('test_data/resolve_incident.json'))


def test_add_responder_incident_wrong_args():
    """
    Given:
        - An app client object
    When:
        - Calling function add_responder_incident with argument responders in the wrong format
    Then:
        - Ensure the resulted will raise an exception.
    """
    mock_client = OpsGenieV3.Client(base_url="")
    with pytest.raises(DemistoException):
        OpsGenieV3.add_responder_incident(mock_client, {'responders': ['team', 'id']})


def test_add_responder_incident(mocker):
    """
    Given:
        - An app client object
        - incident_id = 1234
        - responders = ["team", "id", "name"]
    When:
        - Calling function add_responder_incident
    Then:
        - Ensure the return data is correct
    """
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'add_responder_incident',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/add_responder_incident.json', True))
    res = OpsGenieV3.add_responder_incident(mock_client, {"incident_id": 1234, "responders": ["team", "id", "name"]})
    assert (res.raw_response == util_load_json('test_data/add_responder_incident.json'))


def test_add_tag_incident(mocker):
    """
    Given:
        - An app client object
        - incident_id = 1234
        - tags = [1, 2]
    When:
        - Calling function add_tag_incident
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'add_tag_incident',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/add_tag_incident.json', True))
    res = OpsGenieV3.add_tag_incident(mock_client, {"incident_id": 1234, "tags": [1, 2]})
    assert (res.raw_response == util_load_json('test_data/add_tag_incident.json'))


def test_remove_tag_incident(mocker):
    """
    Given:
        - An app client object
        - incident_id = 1234
        - tags = [1, 2]
    When:
        - Calling function remove_tag_incident
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'remove_tag_incident',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/remove_tag_incident.json', True))
    res = OpsGenieV3.remove_tag_incident(mock_client, {"incident_id": 1234, "tags": [1, 2]})
    assert (res.raw_response == util_load_json('test_data/remove_tag_incident.json'))


def test_get_teams(mocker):
    """
    Given:
        - An app client object
    When:
        - Calling function get_teams
    Then:
        - Ensure the return data is correct
    """
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'list_teams',
                        return_value=util_load_json('test_data/get_teams.json'))
    res = OpsGenieV3.get_teams(mock_client, {})
    assert len(res.outputs) == 2


def test_get_teams_going_to_right_function():
    """
    Given:
        - An app client object
    When:
        - Calling function get_teams
        Case A: "team_id" = 1234
        Case B: No arguments
    Then:
        - Ensure the right function was called
        Case A: Called get_team
        Case B: Called list_teams
    """
    mock_client = OpsGenieV3.Client(base_url="")
    mock_client.get_team = mock.MagicMock()
    OpsGenieV3.get_teams(mock_client, {"team_id": 1234})
    assert mock_client.get_team.called
    mock_client.list_teams = mock.MagicMock()
    OpsGenieV3.get_teams(mock_client, {})
    assert mock_client.list_teams.called


def test_fetch_incidents_command(mocker):
    """
    Given:
        - An app client object
    When:
        - Calling function fetch_incidents_command
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'list_alerts',
                        return_value=util_load_json('test_data/get_alerts.json'))
    mocker.patch.object(mock_client, 'list_incidents',
                        return_value=util_load_json('test_data/get_incidents.json'))
    mocker.patch.object(OpsGenieV3, '_get_utc_now', return_value=datetime(2021, 11, 26))
    mocker.patch.object(OpsGenieV3, '_parse_fetch_time', return_value='2021-11-23T12:19:48Z')
    res, last_run = OpsGenieV3.fetch_incidents_command(mock_client, {"max_fetch": 1})
    assert len(res) == 2
    assert last_run == {'Alerts': {'lastRun': '2021-11-26T00:00:00Z',
                                   'next_page': 'https://api.opsgenie.com/v2/alerts?limit=1&sort='
                                                'createdAt&offset=1&order=desc'},
                        'Incidents': {'lastRun': '2021-11-26T00:00:00Z',
                                      'next_page': 'https://api.opsgenie.com/v1/incidents?limit=1&'
                                                   'sort=insertedAt&offset=1&order=desc'}}


def test_fetch_incidents_command_no_result(mocker):
    """
    Given:
        - An app client object
        - max_fetch = 1
    When:
        - Calling function fetch_incidents_command
        - The list_alerts and list_incidents functions returns empty response
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'list_alerts',
                        return_value=util_load_json('test_data/empty_response.json'))
    mocker.patch.object(mock_client, 'list_incidents',
                        return_value=util_load_json('test_data/empty_response.json'))
    mocker.patch.object(OpsGenieV3, '_get_utc_now', return_value=datetime(2021, 11, 26))
    mocker.patch.object(OpsGenieV3, '_parse_fetch_time', return_value='2021-11-23T12:19:48Z')
    res, last_run = OpsGenieV3.fetch_incidents_command(mock_client, {"max_fetch": 1})
    assert len(res) == 0
    assert last_run == {'Alerts': {'lastRun': '2021-11-26T00:00:00Z', 'next_page': None},
                        'Incidents': {'lastRun': '2021-11-26T00:00:00Z', 'next_page': None}}


def test_fetch_with_paging_only_alerts(mocker):
    """
    Given:
        - An app client object
        - max_fetch = 2
        - event_types = OpsGenieV3.ALERT_TYPE
    When:
        - Calling function fetch_incidents_command
        - The list_alerts function returns result with paging
    Then:
        - Ensure the return data is correct
    """
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


def test_fetch_with_paging_only_incidents(mocker):
    """
    Given:
        - An app client object
        - max_fetch = 2
        - event_types = OpsGenieV3.INCIDENT_TYPE
    When:
        - Calling function fetch_incidents_command
        - The list_incidents function returns result with paging
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'list_incidents',
                        return_value=util_load_json('test_data/get_incidents.json'))
    mocker.patch.object(mock_client, 'get_paged',
                        return_value=util_load_json('test_data/get_incidents_without_next.json'))
    mocker.patch.object(OpsGenieV3, '_get_utc_now', return_value=datetime(2021, 11, 26))
    mocker.patch.object(OpsGenieV3, '_parse_fetch_time', return_value='2021-11-23T12:19:48Z')
    res, last_run = OpsGenieV3.fetch_incidents_command(mock_client, {"max_fetch": 2,
                                                                     "event_types": OpsGenieV3.INCIDENT_TYPE})
    assert (last_run == {'Incidents': {'lastRun': '2021-11-26T00:00:00Z',
                                       'next_page': 'https://api.opsgenie.com/v1/incidents?limit='
                                                    '1&sort=insertedAt&offset=1&order=desc'},
                         'Alerts': {'lastRun': None, 'next_page': None}})
    mocker.patch.object(demisto, 'getLastRun', return_value=last_run)
    res, last_run = OpsGenieV3.fetch_incidents_command(mock_client,
                                                       {"max_fetch": 2, "event_types": OpsGenieV3.INCIDENT_TYPE},
                                                       last_run)
    assert (last_run == {'Incidents': {'lastRun': '2021-11-26T00:00:00Z', 'next_page': None},
                         'Alerts': {'lastRun': None, 'next_page': None}})


def test_build_query_fetch():
    """
    Given:
        - An app client object
        - args
        - is_fetch_query = True
    When:
        - Calling function build_query
    Then:
        - Ensure the return data is correct
    """
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


def test_build_query_not_fetch():
    """
    Given:
        - An app client object
        - args
        - is_fetch_query = False
    When:
        - Calling function build_query
    Then:
        - Ensure the return data is correct
    """
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


def test_build_query_not_fetch_without_query():
    """
    Given:
        - An app client object
        - args
        - is_fetch_query = False
    When:
        - Calling function build_query
    Then:
        - Ensure the return data is correct
    """
    args = {
        "status": "Open",
        "is_fetch_query": False,
        "priority": "P1,P3",
        "tags": "1,2"
    }
    mock_client = OpsGenieV3.Client(base_url="")
    res = mock_client.build_query(args)
    assert (res == "status=open AND priority: (P1 OR P3) AND tag: (1 OR 2)")


def test_responders_to_json_empty_value():
    """
    Given:
        - An app client object
        - responders = {}
    When:
        - Calling function responders_to_json
    Then:
        - Ensure the return data is correct
    """
    mock_client = OpsGenieV3.Client(base_url="")
    res = mock_client.responders_to_json(responders={},
                                         responder_key="responder")
    assert (res == {})


def test_get_request_command(requests_mock, mocker):
    """
    Given:
        - A call to get-request
    When:
        - response is successful
    Then:
        - output is returned
    """
    output = {'hello': 'world'}
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    requests_mock.get(url='http://example.com/v2/alert/requests/1', json={'data': output})
    args = {'request_id': 1, 'request_type': 'alert'}
    response = OpsGenieV3.get_request_command(OpsGenieV3.Client(base_url="http://example.com"), args)
    assert response.outputs == output


def test_get_request_command_404(requests_mock, mocker):
    """
      Given:
          - A call to get-request
      When:
          - response is 404
      Then:
          - Scheduledcommand is returned
      """
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    requests_mock.get(url='http://example.com/v2/alert/requests/1', status_code=404)
    args = {'request_id': 1, 'request_type': 'alert'}
    response = OpsGenieV3.get_request_command(OpsGenieV3.Client(base_url="http://example.com"), args)
    assert response.scheduled_command._args == {**args, 'polled_once': True}


def test_get_request_command_valid_raw_response(requests_mock, mocker):
    """
      Given:
          - A call to get-request
      When:
          - raw response is valid json
      Then:
          - Scheduledcommand is returned
      """
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    requests_mock.get(url='http://example.com/v2/alert/requests/1', json={'data': {}}, status_code=404)
    args = {'request_id': 1, 'request_type': 'alert'}
    response = OpsGenieV3.get_request_command(OpsGenieV3.Client(base_url="http://example.com"), args)
    assert response.raw_response == {'data': {}}


def test_invite_user(mocker):
    """
    Given:
        - An app client object
        - Responders "team,id,123"
    When:
        - Calling function create_alert with argument responders in the right format
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'invite_user', return_value=util_load_json('test_data/invite_user.json'))
    res = OpsGenieV3.invite_user(mock_client, {'username': "test@example.com", 'fullName': 'Test Example', 'role': 'user'})
    assert (res.raw_response == util_load_json('test_data/invite_user.json'))


def test_get_team_routing_rules(mocker):
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'get_team_routing_rules',
                        return_value=util_load_json('test_data/get_team_routing_rules.json'))
    res = OpsGenieV3.get_team_routing_rules(mock_client, {'team_id': " a6604a9f-b152-54c-b31-1b9741c109"})
    assert (res.raw_response == util_load_json('test_data/get_team_routing_rules.json'))


def test_get_alert_logs(mocker):
    """
    Given:
        - An app client object
        - alert_id = 0123456
    When:
        - Calling function get_alert_notes
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'get_alert_logs',
                        return_value=util_load_json('test_data/get_alert_logs.json'))
    res = OpsGenieV3.get_alert_logs(mock_client, {"alert_id": '0123456'})
    assert isinstance(res.raw_response, dict)


def test_add_alert_note(mocker):
    """
    Given:
        - An app client object
        - alert_id = 1234
        - note = "testdemisto"
    When:
        - Calling function add_alert_note
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'add_alert_note',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/add_alert_note.json', True))
    res = OpsGenieV3.add_alert_note(mock_client, {"alert_id": 1234, "note": "testdemisto"})
    assert (res.raw_response == util_load_json('test_data/add_alert_note.json'))


def test_add_alert_details(mocker):
    """
    Given:
        - An app client object
        - Alert-id = 1234
        - details = "test=demisto"
    When:
        - Calling function add_alert_details
    Then:
        - Ensure the return data is correct
    """
    mocker.patch('CommonServerPython.get_demisto_version', return_value={"version": "6.2.0"})
    mock_client = OpsGenieV3.Client(base_url="")
    mocker.patch.object(mock_client, 'add_alert_details',
                        return_value=util_load_json('test_data/request.json'))
    mocker.patch.object(mock_client, 'get_request',
                        return_value=util_load_json('test_data/add_alert_details.json', True))
    res = OpsGenieV3.add_alert_details(mock_client, {"alert-id": 1234, "details": {'test': 'demisto'}})
    assert (res.raw_response == util_load_json('test_data/add_alert_details.json'))
