# -*- coding: utf-8 -*-
from CommonServerPython import *
import pytest


def load_mock_response(file_name):
    """
    Load mock file that simulates an API response.

    Args:
        file_name (str): Name of the mock response JSON file to return.

    Returns:
        str: Mock file content.

    """
    with open('test_data/' + file_name, mode='r') as f:
        return json.loads(f.read())


def test_get_incidents(requests_mock, mocker):
    """
    Given:
        - An incident with non-ascii character in its documentation

    When:
        - Running get incidents command

    Then:
        - Ensure command run without failing on UnicodeError
        - Verify the non-ascii character appears in the human readable output as expected
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'DefaultRequestor'
        }
    )
    from PagerDuty import get_incidents_command
    requests_mock.get(
        'https://api.pagerduty.com/incidents?include%5B%5D=assignees&statuses%5B%5D=triggered&statuses%5B%5D'
        '=acknowledged&include%5B%5D=first_trigger_log_entries&include%5B%5D=assignments&time_zone=UTC',
        json={
            'incidents': [{
                'first_trigger_log_entry': {
                    'channel': {
                        'details': {
                            'Documentation': '•'
                        }
                    }
                }
            }]
        }
    )
    res = get_incidents_command()
    assert '| Documentation: • |' in res['HumanReadable']


def test_add_responders(requests_mock, mocker):
    """
    Given:
        - a responder request.

    When:
        - Running PagerDuty-add-responders command.

    Then:
        - Ensure command returns the correct output.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            "incident_id": "PXP12GZ",
            "message": "Please help with issue - join bridge at +1(234)-567-8910",
            "user_requests": "P09TT3C,PAIXXX"
        }
    )
    requests_mock.post(
        'https://api.pagerduty.com/incidents/PXP12GZ/responder_requests',
        json=load_mock_response('responder_requests.json').get('specific_users')
    )

    from PagerDuty import add_responders_to_incident
    res = add_responders_to_incident(**demisto.args())
    expected_users_requested = ','.join([x.get("ID") for x in res.outputs])
    assert demisto.args().get('incident_id') == res.outputs[0].get('IncidentID')
    assert demisto.args().get('message') == res.outputs[0].get('Message')
    assert demisto.params().get('DefaultRequestor') == res.outputs[1].get('RequesterID')
    assert demisto.args().get('user_requests') == expected_users_requested


def test_add_responders_default(requests_mock, mocker):
    """
    Given:
        - a responder request without specifying responders.

    When:
        - Running add_responders_to_incident function.

    Then:
        - Ensure the function returns the correct output.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            "incident_id": "PXP12GZ",
            "message": "Please help with issue - join bridge at +1(234)-567-8910"
        }
    )
    requests_mock.post(
        'https://api.pagerduty.com/incidents/PXP12GZ/responder_requests',
        json=load_mock_response('responder_requests.json').get('default_user')
    )

    from PagerDuty import add_responders_to_incident
    res = add_responders_to_incident(**demisto.args())
    expected_users_requested = ','.join([x.get("ID") for x in res.outputs])
    assert demisto.args().get('incident_id') == res.outputs[0].get('IncidentID')
    assert demisto.args().get('message') == res.outputs[0].get('Message')
    assert demisto.params().get('DefaultRequestor') == res.outputs[0].get('RequesterID')
    assert demisto.params().get('DefaultRequestor') == expected_users_requested


def test_play_response_play(requests_mock, mocker):
    """
    Given:
        - a responder request without specifying responders.

    When:
        - Running PagerDuty-run-response-play function.

    Then:
        - Ensure the function returns a valid status.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            "incident_id": "PXP12GZ",
            "from_email": "john.doe@example.com",
            "response_play_uuid": "response_play_id",
        }
    )
    requests_mock.post(
        'https://api.pagerduty.com/response_plays/response_play_id/run',
        json={"status": "ok"}
    )

    from PagerDuty import run_response_play
    res = run_response_play(**demisto.args())

    assert res.raw_response == {"status": "ok"}


def test_get_users_on_call(requests_mock, mocker):
    """
    Given:
        - a request to get user on-call by schedule ID.

    When:
        - Running get_on_call_users_command function.

    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            "scheduleID": "PI7DH85",
        }
    )
    requests_mock.get(
        'https://api.pagerduty.com/schedules/PI7DH85/users',
        json=load_mock_response('schedules.json')
    )
    from PagerDuty import get_on_call_users_command
    res = get_on_call_users_command(**demisto.args())
    assert demisto.args().get('scheduleID') == res.outputs[0].get('ScheduleID')


def test_get_users_on_call_now(requests_mock, mocker):
    """
    Given:
        - a reqest to get user oncall by schedule ID without specifying responders.

    When:
        - Running get_on_call_users_command function.

    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            "schedule_ids": "PI7DH85,PA7DH85",
        }
    )
    requests_mock.get(
        'https://api.pagerduty.com/oncalls',
        json=load_mock_response('oncalls.json')
    )
    from PagerDuty import get_on_call_now_users_command
    res = get_on_call_now_users_command(**demisto.args())
    assert res.outputs[0].get('ScheduleID') in demisto.args().get('schedule_ids')
    assert 'oncalls' in res.raw_response


def test_submit_event(requests_mock, mocker):
    """
    Given:
        - a reqest to submit request.

    When:
        - Running submit_event function.

    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )
    source = 'test'
    summary = 'test'
    severity = 'test'
    action = 'test'

    requests_mock.post(
        'https://events.pagerduty.com/v2/enqueue',
        json={
            'status': 'status',
            'message': 'message',
            'dedup_key': 'dedup_key'
        }
    )
    from PagerDuty import submit_event_command
    res = submit_event_command(source, summary, severity, action)
    assert '### Trigger Event' in res.get('HumanReadable')


def test_get_all_schedules_command(mocker, requests_mock):
    """
    Given:
        - a reqest to get all schedule

    When:
        - Running get_all_schedules function.

    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )

    requests_mock.get(
        'https://api.pagerduty.com/schedules',
        json={
            'schedules': [{'id': 'id',
                           'name': 'name',
                           'time_zone': 'time_zone',
                           'escalation_policies': [{'id': 'id', 'summary': 'summary'}]}]

        }
    )
    from PagerDuty import get_all_schedules_command
    res = get_all_schedules_command()
    assert '### All Schedules' in res.get('HumanReadable')


def test_get_users_contact_methods_command(mocker, requests_mock):
    """
    Given:
        - a reqest to get all schedule.

    When:
        - Running get_all_schedules function.

    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )

    user_id = 'id'

    requests_mock.get(
        f'https://api.pagerduty.com/users/{user_id}/contact_methods',
        json={'contact_methods': [{'id': 'id', 'address': 'address', 'country_code': 'country_code'}]}
    )
    from PagerDuty import get_users_contact_methods_command
    res = get_users_contact_methods_command(user_id)
    assert '### Contact Methods' in res.get('HumanReadable')


def test_get_users_notification_command(mocker, requests_mock):
    """
    Given:
        - a request to get users notifications.

    When:
        - Running get_users_notification_command function.

    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )

    user_id = 'id'

    requests_mock.get(
        f'https://api.pagerduty.com/users/{user_id}/notification_rules',
        json={'notification_rules': [{'id': 'id', 'urgency': 'urgency', 'type': 'type'}]}
    )
    from PagerDuty import get_users_notification_command
    res = get_users_notification_command(user_id)
    assert '### User notification rules' in res.get('HumanReadable')


@pytest.mark.parametrize('severity, expected_result', [('high', 3), ('low', 1), ('other_severity', 0)])
def test_translate_severity(mocker, severity, expected_result):
    """
    Given:
        - a severity.
    When:
        - Running translate_severity function.
    Then:
        - Ensure the function returns a valid output.
    """
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            'APIKey': 'API_KEY',
            'ServiceKey': 'SERVICE_KEY',
            'FetchInterval': 'FETCH_INTERVAL',
            'DefaultRequestor': 'P09TT3C'
        }
    )
    from PagerDuty import translate_severity
    res = translate_severity(severity)
    assert res == expected_result
