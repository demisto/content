# from xMatters import Client
# from typing import Any, Dict, Tuple, List, Optional, cast
# import unittest


def test_xm_trigger_workflow_command(requests_mock):
    """Tests trigger workflow command

    :param requests_mock:
    :return:
    """
    from xMatters import Client, xm_trigger_workflow_command

    # '7a161a3f-8d53-42de-80cd-92fb017c5a12'
    mock_response = {
        'requestId': 'I GOT ONE!'
    }

    recipients = 'bonnieKat'
    subject = 'This glass is offending me.'
    body = 'I shall push it off the table'
    incident_id = '437'
    close_task_id = '3'

    base_url = 'https://acme.xmatters.com/?' + '&recipients=' + recipients + \
               '&subject=' + subject + \
               '&body=' + body + \
               '&incident_id=' + incident_id + \
               '&close_task_id=' + close_task_id

    requests_mock.register_uri('POST', base_url, json=mock_response)

    client = Client(
        base_url=base_url,
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    results = xm_trigger_workflow_command(client, recipients=recipients,
                                          subject=subject,
                                          body=body,
                                          incident_id=incident_id,
                                          close_task_id=close_task_id, )

    assert results.readable_output == "Successfully sent a message to xMatters."


def test_xm_get_events_command(requests_mock):
    from xMatters import Client, xm_get_events_command

    hostname = 'https://acme.xmatters.com'
    mock_response = {
        "count": 1,
        "total": 1,
        "data":
            [
                {
                    "id": "116f41dc-395c-4bba-a806-df1eda88f4aa",
                    "name": "An customer-reported issue with Monitoring Tool X requires attention",
                    "eventType": "USER",
                    "plan": {
                        "id": "c56730a9-1435-4ae2-8c7e-b2539e635ac6",
                        "name": "Cat Facts!"
                    },
                    "form": {
                        "id": "b593c84c-497d-461d-9521-7d9a2d09a4f3",
                        "name": "Send Fact"
                    },
                    "floodControl": False,
                    "submitter": {
                        "id": "c21b7cc9-c52a-4878-8d26-82b26469fdc7",
                        "targetName": "bonnieKat",
                        "firstName": "bonnie",
                        "lastName": "Kat",
                        "recipientType": "PERSON",
                        "links": {
                            "self": "/api/xm/1/people/c21b7cc9-c52a-4878-8d26-82b26469fdc7"
                        },
                    },
                    "priority": "HIGH",
                    "incident": "INCIDENT_ID-981006",
                    "overrideDeviceRestrictions": False,
                    "otherResponseCountThreshold": 2,
                    "otherResponseCount": 1,
                    "escalationOverride": False,
                    "bypassPhoneIntro": False,
                    "requirePhonePassword": False,
                    "revision": {
                        "id": "34c384ba-eaa4-4278-9ebb-94726232b063",
                        "at": "2019-08-09T16:59:38.371Z",
                        "seq": "21866402165008"
                    },
                    "eventId": "981006",
                    "created": "2016-10-31T22:37:35.301+0000",
                    "terminated": "2016-10-31T22:38:40.063+0000",
                    "status": "TERMINATED",
                    "links": {
                        "self": "/api/xm/1/events/116f41dc-395c-4bba-a806-df1eda88f4aa"
                    },
                    "responseCountsEnabled": False,
                    "properties": {
                        "Customer reported": True,
                        "Customers affected": 100,
                        "Country#en": "USA"
                    }
                }
            ],
        "links":
            {
                "self": "/api/xm/1/events?priority=HIGH&offset=0&limit=100"
            }
    }

    requests_mock.register_uri('GET', hostname + '/api/xm/1/events?priority=HIGH', json=mock_response)

    client = Client(
        base_url=hostname,
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    results = xm_get_events_command(client, priority='HIGH')
    assert results.readable_output.startswith("Retrieved Events from xMatters:")


def test_xm_get_event_command(requests_mock):
    from xMatters import Client, xm_get_event_command

    hostname = 'https://acme.xmatters.com'
    mock_response = {
        "id": "116f41dc-395c-4bba-a806-df1eda88f4aa",
        "name": "A family of raccoons has moved into the datacenter. They are pretty good cable runners",
        "eventType": "USER",
        "plan": {
            "id": "c56730a9-1435-4ae2-8c7e-b2539e635ac6",
            "name": "DC Monitoring"
        },
        "form": {
            "id": "b593c84c-497d-461d-9521-7d9a2d09a4f3",
            "name": "User Submitted"
        },
        "floodControl": False,
        "submitter": {
            "id": "c21b7cc9-c52a-4878-8d26-82b26469fdc7",
            "targetName": "bonnieKat",
            "firstName": "bonnie",
            "lastName": "Kat",
            "recipientType": "PERSON",
            "links": {
                "self": "/api/xm/1/people/c21b7cc9-c52a-4878-8d26-82b26469fdc7"
            },
        },
        "priority": "HIGH",
        "incident": "INCIDENT_ID-981006",
        "overrideDeviceRestrictions": False,
        "otherResponseCountThreshold": 2,
        "otherResponseCount": 1,
        "escalationOverride": False,
        "bypassPhoneIntro": False,
        "requirePhonePassword": False,
        "revision": {
            "id": "34c384ba-eaa4-4278-9ebb-94726232b063",
            "at": "2019-08-09T16:59:38.371Z",
            "seq": "21866402165008"
        },
        "eventId": "981006",
        "created": "2016-10-31T22:37:35.301+0000",
        "terminated": "2016-10-31T22:38:40.063+0000",
        "status": "TERMINATED",
        "links": {
            "self": "/api/xm/1/events/116f41dc-395c-4bba-a806-df1eda88f4aa"
        },
        "responseCountsEnabled": False,
        "properties": {
            "Customer reported": True,
            "Customers affected": 100,
            "Country#en": "USA"
        }
    }

    requests_mock.register_uri('GET', hostname + '/api/xm/1/events/34111', json=mock_response)

    client = Client(
        base_url=hostname,
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    results = xm_get_event_command(client, event_id='34111')
    assert results.readable_output.startswith("Retrieved Event \"34111\" from xMatters")


def test_fetch_incidents(requests_mock):
    from xMatters import Client, fetch_incidents

    hostname = 'https://acme.xmatters.com'

    client = Client(
        base_url=hostname,
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    mock_response = {
        "count": 2,
        "data": [
            {
                "bypassPhoneIntro": False,
                "created": "2020-11-04T16:50:39.929+0000",
                "escalationOverride": False,
                "eventId": "9147637302",
                "eventType": "USER",
                "floodControl": False,
                "form": {
                    "id": "75be94d8-0329-4c97-b4b6-c2da098edb06",
                    "name": "Monitoring Alert Generator"
                },
                "id": "fbf2fe08-68a3-4417-94d5-e09d68d412c7",
                "incident": "INCIDENT_ID-9147637302",
                "links": {
                    "self": "/api/xm/1/events/fbf2fe08-68a3-4417-94d5-e09d68d412c7"
                },
                "name": "Hang tight - your alert is on the way!",
                "overrideDeviceRestrictions": False,
                "plan": {
                    "id": "f7836611-e18b-40f2-a435-0288b3823260",
                    "name": "#Demo2020 Sales Engineering Demo Starter"
                },
                "priority": "HIGH",
                "requirePhonePassword": False,
                "responseCountsEnabled": False,
                "status": "TERMINATED",
                "submitter": {
                    "firstName": "Oscar Admin",
                    "id": "2c831e7c-b0de-433b-a5b0-879a79130c90",
                    "lastName": "Wilde",
                    "links": {
                        "self": "/api/xm/1/people/2c831e7c-b0de-433b-a5b0-879a79130c90"
                    },
                    "recipientType": "PERSON",
                    "targetName": "owilde"
                },
                "terminated": "2020-11-04T16:51:40.619+0000"
            },
            {
                "bypassPhoneIntro": False,
                "created": "2020-11-04T16:27:35.056+0000",
                "escalationOverride": False,
                "eventId": "9146487384",
                "eventType": "USER",
                "floodControl": False,
                "form": {
                    "id": "75be94d8-0329-4c97-b4b6-c2da098edb06",
                    "name": "Monitoring Alert Generator"
                },
                "id": "b9887e2a-90e7-49a1-8fb6-a648db5948ac",
                "incident": "INCIDENT_ID-9146487384",
                "links": {
                    "self": "/api/xm/1/events/b9887e2a-90e7-49a1-8fb6-a648db5948ac"
                },
                "name": "Hang tight - your alert is on the way!",
                "overrideDeviceRestrictions": False,
                "plan": {
                    "id": "f7836611-e18b-40f2-a435-0288b3823260",
                    "name": "#Demo2020 Sales Engineering Demo Starter"
                },
                "priority": "HIGH",
                "requirePhonePassword": False,
                "responseCountsEnabled": False,
                "status": "TERMINATED",
                "submitter": {
                    "firstName": "Oscar",
                    "id": "dc4163ae-8bbf-4007-9616-0cfb6b1dadfa",
                    "lastName": "Wilde",
                    "links": {
                        "self": "/api/xm/1/people/dc4163ae-8bbf-4007-9616-0cfb6b1dadfa"
                    },
                    "recipientType": "PERSON",
                    "targetName": "owilde"
                },
                "terminated": "2020-11-04T16:28:35.909+0000"
            }
        ],
        "links": {
            "self": "/api/xm/1/events?priority=HIGH&limit=100&offset=0"
        },
        "total": 2
    }

    requests_mock.register_uri('GET', hostname + '/api/xm/1/events?priority=HIGH', json=mock_response)

    next_run, incidents = fetch_incidents(
        client=client,
        priority="HIGH",
        first_fetch_time=1594250101
    )

    assert len(incidents) == 2

    mock_response = {"count": 0,
                     "total": 0,
                     "data": [],
                     "links": {"self": "/api/xm/1/events?limit=100&offset=0&status=ACTIVE"}}

    requests_mock.register_uri('GET', hostname + '/api/xm/1/events?status=ACTIVE', json=mock_response)

    next_run, incidents = fetch_incidents(
        client=client,
        alert_status="ACTIVE",
        first_fetch_time=1594250101
    )

    assert len(incidents) == 0
