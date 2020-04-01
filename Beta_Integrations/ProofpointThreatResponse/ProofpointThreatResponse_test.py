import pytest
from CommonServerPython import *
from ProofpointThreatResponse import create_incident_field_context, get_emails_context, pass_sources_list_filter, \
    pass_abuse_disposition_filter, filter_incidents, prepare_ingest_alert_request_body

MOCK_INCIDENT = {
    "id": 1,
    "type": "Malware",
    "summary": "Unsolicited Bulk Email",
    "description": "EvilScheme test message",
    "score": 4200,
    "state": "Open",
    "created_at": "2018-05-26T21:07:17Z",
    "event_count": 3,
    "event_sources": [
        "Proofpoint TAP"
    ],
    "users": [
        ""
    ],
    "assignee": "Unassigned",
    "team": "Unassigned",
    "hosts": {
        "attacker": [
            ""
        ],
        "forensics": [
            "",
        ]
    },
    "incident_field_values": [
        {
            "name": "Attack Vector",
            "value": "Email"
        },
        {
            "name": "Classification",
            "value": "Spam"
        },
        {
            "name": "Severity",
            "value": "Critical"
        },
        {
            "name": "Abuse Disposition",
            "value": "Unknown"
        }
    ],
    "events": [
        {
            "id": 3,
            "category": "malware",
            "severity": "Info",
            "source": "Proofpoint TAP",
            "threatname": "",
            "state": "Linked",
            "description": "",
            "attackDirection": "inbound",
            "received": "2018-05-26T21:07:17Z",
            "malwareName": "",
            "emails": [
                {
                    "sender": {
                        "email": "test"
                    },
                    "recipient": {
                        "email": "test"
                    },
                    "subject": "test",
                    "messageId": "test",
                    "messageDeliveryTime": {
                        "chronology": {
                            "zone": {
                                "id": "UTC"
                            }
                        },
                        "millis": 1544640072000,
                    },
                    "abuseCopy": "false",
                    "body": "test",
                    'bodyType': "test",
                    'headers': "test",
                    'urls': "test"
                }
            ],
        }
    ],
    "quarantine_results": [],
    "successful_quarantines": 0,
    "failed_quarantines": 0,
    "pending_quarantines": 0
}

INCIDENT_FIELD_CONTEXT = {
    "Attack_Vector": "Email",
    "Classification": "Spam",
    "Severity": "Critical",
    "Abuse_Disposition": "Unknown"
}

INCIDENT_FIELD_INPUT = [
    (MOCK_INCIDENT, INCIDENT_FIELD_CONTEXT)
]


@pytest.mark.parametrize('incident, answer', INCIDENT_FIELD_INPUT)
def test_get_incident_field_context(incident, answer):
    incident_field_values = create_incident_field_context(incident)
    assert incident_field_values == answer


EMAIL_RESULT = [
    {
        'sender': "test",
        'recipient': "test",
        'subject': "test",
        'message_id': "test",
        'message_delivery_time': 1544640072000,
        'body': "test",
        'body_type': "test",
        'headers': "test",
        'urls': "test"
    }
]

EMAILS_CONTEXT_INPUT = [
    (MOCK_INCIDENT['events'][0], EMAIL_RESULT)
]


@pytest.mark.parametrize('event, answer', EMAILS_CONTEXT_INPUT)
def test_get_emails_context(event, answer):
    emails_context = get_emails_context(event)
    assert emails_context == answer


SOURCE_LIST_INPUT = [
    (["Proofpoint TAP"], True),
    ([], True),
    (["No such source"], False),
    (["No such source", "Proofpoint TAP"], True)
]


@pytest.mark.parametrize('sources_list, expected_answer', SOURCE_LIST_INPUT)
def test_pass_sources_list_filter(sources_list, expected_answer):
    result = pass_sources_list_filter(MOCK_INCIDENT, sources_list)
    assert result == expected_answer


ABUSE_DISPOSITION_INPUT = [
    (["Unknown"], True),
    ([], True),
    (["No such value"], False),
    (["No such value", "Unknown"], True)
]


@pytest.mark.parametrize('abuse_dispotion_values, expected_answer', ABUSE_DISPOSITION_INPUT)
def test_pass_abuse_disposition_filter(abuse_dispotion_values, expected_answer):
    result = pass_abuse_disposition_filter(MOCK_INCIDENT, abuse_dispotion_values)
    assert result == expected_answer


DEMISTO_PARAMS = [
    ({
        'event_sources': "No such source, Proofpoint TAP",
        'abuse_disposition': "No such value, Unknown"}, [MOCK_INCIDENT]),
    ({
        'event_sources': "",
        'abuse_disposition': ""}, [MOCK_INCIDENT]),
    ({
        'event_sources': "No such source",
        'abuse_disposition': "No such value, Unknown"}, []),
    ({
        'event_sources': "No such source, Proofpoint TAP",
        'abuse_disposition': "No such value"}, []),
    ({
        'event_sources': "No such source",
        'abuse_disposition': "No such value"}, []),
]


@pytest.mark.parametrize('demisto_params, expected_answer', DEMISTO_PARAMS)
def test_filter_incidents(mocker, demisto_params, expected_answer):
    mocker.patch.object(demisto, 'params', return_value=demisto_params)
    filtered_incidents = filter_incidents([MOCK_INCIDENT])
    assert filtered_incidents == expected_answer


INGEST_ALERT_ARGS = {
    "attacker": "{\"attacker\":{\"key\":\"value\"}}",
    "cnc_host": "{\"cnc_host\":{\"key\":\"value\"}}",
    "detector": "{\"detector\":{\"key\":\"value\"}}",
    "email": "{\"email\":{\"key\":\"value\"}}",
    "forensics_hosts": "{\"forensics_hosts\":{\"key\":\"value\"}}",
    "target": "{\"target\":{\"key\":\"value\"}}",
    "threat_info": "{\"threat_info\":{\"key\":\"value\"}}",
    "custom_fields": "{\"custom_fields\":{\"key\":\"value\"}}",
    "post_url_id": "value",
    "json_version": "value",
    "summary": "value"
}

EXPECTED_RESULT = {
    "attacker": {"key": "value"},
    "cnc_host": {"key": "value"},
    "detector": {"key": "value"},
    "email": {"key": "value"},
    "forensics_hosts": {"key": "value"},
    "target": {"key": "value"},
    "threat_info": {"key": "value"},
    "custom_fields": {"key": "value"},
    "post_url_id": "value",
    "json_version": "value",
    "summary": "value"
}


def test_prepare_ingest_alert_request_body():
    prepared_body = prepare_ingest_alert_request_body(INGEST_ALERT_ARGS)
    assert prepared_body == EXPECTED_RESULT
