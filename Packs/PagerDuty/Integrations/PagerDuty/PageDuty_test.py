# -*- coding: utf-8 -*-
from CommonServerPython import *


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
    Test sending request to a responder
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
        json={
            "responder_request": {
                "incident": {
                    "id": "PXP12GZ",
                    "type": "incident_reference",
                    "summary": "[#99999] Test Incident for Demisto Integration - No Action",
                    "self": "https://api.pagerduty.com/incidents/PXP12GZ",
                    "html_url": "https://upstart.pagerduty.com/incidents/PXP12GZ"
                },
                "requester": {
                    "id": "P09TT3C",
                    "type": "user_reference",
                    "summary": "John Doe",
                    "self": "https://api.pagerduty.com/users/P09TT3C",
                    "html_url": "https://mycompany.pagerduty.com/users/P09TT3C"
                },
                "requested_at": "2022-02-24T18:08:50-08:00",
                "message": "Please help with issue - join bridge at +1(234)-567-8910",
                "responder_request_targets": [
                    {
                        "responder_request_target": {
                            "type": "user",
                            "id": "P09TT3C",
                            "summary": "",
                            "incidents_responders": [
                                {
                                    "state": "pending",
                                    "user": {
                                        "id": "P09TT3C",
                                        "type": "user_reference",
                                        "summary": "John Doe",
                                        "self": "https://api.pagerduty.com/users/P09TT3C",
                                        "html_url": "https://mycompany.pagerduty.com/users/P09TT3C",
                                        "avatar_url": "https://secure.gravatar.com/avatar/\
                                        1c747247b75acc1f724e2784c838b3f8.png?d=mm&r=PG",
                                        "job_title": ""
                                    },
                                    "incident": {
                                        "id": "PXP12GZ",
                                        "type": "incident_reference",
                                        "summary": "[#30990] Test Incident for Demisto Integration - No Action",
                                        "self": "https://api.pagerduty.com/incidents/PXP12GZ",
                                        "html_url": "https://upstart.pagerduty.com/incidents/PXP12GZ"
                                    },
                                    "updated_at": "2022-02-24T16:58:27-08:00",
                                    "message": "Please help with issue - join bridge at +1(234)-567-8910",
                                    "requester": {
                                        "id": "P09TT3C",
                                        "type": "user_reference",
                                        "summary": "John Doe",
                                        "self": "https://api.pagerduty.com/users/P09TT3C",
                                        "html_url": "https://mycompany.pagerduty.com/users/P09TT3C",
                                        "avatar_url": "https://secure.gravatar.com/avatar/\
                                        1c747247b75acc1f724e2784c838b3f8.png?d=mm&r=PG",
                                        "job_title": ""
                                    },
                                    "requested_at": "2022-02-25T00:58:27Z"
                                }
                            ]
                        }
                    },
                    {
                        "responder_request_target": {
                            "type": "user",
                            "id": "PAIXXX",
                            "summary": "",
                            "incidents_responders": [
                                {
                                    "state": "pending",
                                    "user": {
                                        "id": "PAIXXX",
                                        "type": "user_reference",
                                        "summary": "Jane Doe",
                                        "self": "https://api.pagerduty.com/users/PAIXXX",
                                        "html_url": "https://upstart.pagerduty.com/users/PAIXXX",
                                        "avatar_url": "https://secure.gravatar.com/avatar/\
                                        7982b65c651637dc65c626924c4a3b9c.png?d=mm&r=PG",
                                        "job_title": ""
                                    },
                                    "incident": {
                                        "id": "PXP12GZ",
                                        "type": "incident_reference",
                                        "summary": "[#30990] Test Incident for Demisto Integration - No Action",
                                        "self": "https://api.pagerduty.com/incidents/PXP12GZ",
                                        "html_url": "https://upstart.pagerduty.com/incidents/PXP12GZ"
                                    },
                                    "updated_at": "2022-02-24T18:08:50-08:00",
                                    "message": "Please help with issue - join bridge at +1(234)-567-8910",
                                    "requester": {
                                        "id": "P09TT3C",
                                        "type": "user_reference",
                                        "summary": "John Doe",
                                        "self": "https://api.pagerduty.com/users/P09TT3C",
                                        "html_url": "https://mycompany.pagerduty.com/users/P09TT3C",
                                        "avatar_url": "https://secure.gravatar.com/avatar/\
                                        1c747247b75acc1f724e2784c838b3f8.png?d=mm&r=PG",
                                        "job_title": ""
                                    },
                                    "requested_at": "2022-02-25T00:58:27Z"
                                }
                            ]
                        }
                    }
                ]
            }
        }
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
    Test sending request to a responder without specifying responders
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
         }
    )
    requests_mock.post(
        'https://api.pagerduty.com/incidents/PXP12GZ/responder_requests',
        json={
            "responder_request": {
                "incident": {
                    "id": "PXP12GZ",
                    "type": "incident_reference",
                    "summary": "[#99999] Test Incident for Demisto Integration - No Action",
                    "self": "https://api.pagerduty.com/incidents/PXP12GZ",
                    "html_url": "https://upstart.pagerduty.com/incidents/PXP12GZ"
                },
                "requester": {
                    "id": "P09TT3C",
                    "type": "user_reference",
                    "summary": "John Doe",
                    "self": "https://api.pagerduty.com/users/P09TT3C",
                    "html_url": "https://mycompany.pagerduty.com/users/P09TT3C"
                },
                "requested_at": "2022-02-24T18:08:50-08:00",
                "message": "Please help with issue - join bridge at +1(234)-567-8910",
                "responder_request_targets": [
                    {
                        "responder_request_target": {
                            "type": "user",
                            "id": "P09TT3C",
                            "summary": "",
                            "incidents_responders": [
                                {
                                    "state": "pending",
                                    "user": {
                                        "id": "P09TT3C",
                                        "type": "user_reference",
                                        "summary": "John Doe",
                                        "self": "https://api.pagerduty.com/users/P09TT3C",
                                        "html_url": "https://mycompany.pagerduty.com/users/P09TT3C",
                                        "avatar_url": "https://secure.gravatar.com/avatar/\
                                        1c747247b75acc1f724e2784c838b3f8.png?d=mm&r=PG",
                                        "job_title": ""
                                    },
                                    "incident": {
                                        "id": "PXP12GZ",
                                        "type": "incident_reference",
                                        "summary": "[#30990] Test Incident for Demisto Integration - No Action",
                                        "self": "https://api.pagerduty.com/incidents/PXP12GZ",
                                        "html_url": "https://upstart.pagerduty.com/incidents/PXP12GZ"
                                    },
                                    "updated_at": "2022-02-24T16:58:27-08:00",
                                    "message": "Please help with issue - join bridge at +1(234)-567-8910",
                                    "requester": {
                                        "id": "P09TT3C",
                                        "type": "user_reference",
                                        "summary": "John Doe",
                                        "self": "https://api.pagerduty.com/users/P09TT3C",
                                        "html_url": "https://mycompany.pagerduty.com/users/P09TT3C",
                                        "avatar_url": "https://secure.gravatar.com/avatar/\
                                        1c747247b75acc1f724e2784c838b3f8.png?d=mm&r=PG",
                                        "job_title": ""
                                    },
                                    "requested_at": "2022-02-25T00:58:27Z"
                                }
                            ]
                        }
                    },
                ]
            }
        }
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
    Test sending request to a responder without specifying responders
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
        json={
          "status": "ok"
        }
    )

    from PagerDuty import run_response_play
    res = run_response_play(**demisto.args())

    assert res.raw_response == {"status": "ok"}