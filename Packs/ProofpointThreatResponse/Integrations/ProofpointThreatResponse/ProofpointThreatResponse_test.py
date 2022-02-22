import pytest

from CommonServerPython import *
from ProofpointThreatResponse import (create_incident_field_context,
                                      filter_incidents, get_emails_context,
                                      get_incident_command,
                                      get_incidents_batch_by_time_request,
                                      get_new_incidents, get_time_delta,
                                      pass_abuse_disposition_filter,
                                      pass_sources_list_filter,
                                      prepare_ingest_alert_request_body,
                                      close_incident_command)

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


def get_fetch_data():
    with open('./test_data/raw_response.json', 'r') as f:
        file = json.loads(f.read())
        return file.get('result')


FETCH_RESPONSE = get_fetch_data()


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


DEMISTO_PARAMS = [({'event_sources': "No such source, Proofpoint TAP", 'abuse_disposition': "No such value, Unknown"},
                   [MOCK_INCIDENT]), ({'event_sources': "", 'abuse_disposition': ""}, [MOCK_INCIDENT]),
                  ({'event_sources': "No such source", 'abuse_disposition': "No such value, Unknown"}, []),
                  ({'event_sources': "No such source, Proofpoint TAP", 'abuse_disposition': "No such value"}, []),
                  ({'event_sources': "No such source", 'abuse_disposition': "No such value"}, [])]


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


def test_fetch_incidents_limit_exceed(mocker):
    """
     Given
     - a dict of params given to the function which is gathered originally from demisto.params()
        The dict includes the relevant params for the fetch e.g. fetch_delta, fetch_limit, created_after, state.
     - response of the api
     When
     - a single iteration of the fetch is activated with a fetch limit set to 5
     Then
     - validate that the number or incidents that is returned is equal to the limit when the api returned more.
     """
    params = {
        'fetch_delta': '6 hours',
        'fetch_limit': ' 5',
        'created_after': '2021-03-30T11:44:24Z',
        'state': 'closed'
    }
    mocker.patch('ProofpointThreatResponse.get_incidents_request', return_value=FETCH_RESPONSE)
    incidents_list = get_incidents_batch_by_time_request(params)
    assert len(incidents_list) == 5


def test_fetch_incidents_with_same_created_time(mocker):
    """
     Given
     - a dict of params given to the function which is gathered originally from demisto.params()
        The dict includes the relevant params for the fetch e.g. fetch_delta, fetch_limit, created_after, state and
         last_fetched_id.
     - response of the api
     When
     - when a fetch occurs and the last fetched incident has exactly the same time of the next incident.
     Then
     - validate that only one of the incidents appear as to the fetch limit.
     - validate that the next incident whose time is exactly the same is brought in the next fetch loop.
     ( e.g. 3057 and 3058)
     """
    expected_ids_to_fetch_first = [3055, 3056, 3057]
    expected_ids_to_fetch_second = [3058, 3059, 3060]

    params = {
        'fetch_delta': '2 hours',
        'fetch_limit': '3',
        'created_after': '2021-03-30T10:44:24Z',
        'state': 'closed'
    }

    mocker.patch('ProofpointThreatResponse.get_incidents_request', return_value=FETCH_RESPONSE)
    new_fetched_first = get_incidents_batch_by_time_request(params)
    for incident in new_fetched_first:
        assert incident.get('id') in expected_ids_to_fetch_first

    params = {
        'fetch_delta': '2 hour',
        'fetch_limit': '3',
        'created_after': '2021-03-30T11:21:24Z',
        'last_fetched_id': '3057',
        'state': 'closed'
    }
    new_fetched_second = get_incidents_batch_by_time_request(params)
    for incident in new_fetched_second:
        assert incident.get('id') in expected_ids_to_fetch_second


def test_get_new_incidents(mocker):
    """
     Given
     - a dict of request_params to the api.
     - The last fetched incident id.
     When
     - Get new incidents is called during the fetch process.
     Then
     - validate that the number of expected incidents return.
     - validate that all of the returned incident have a bigger id then the last fetched incident.
     """
    last_incident_fetched = 3057
    request_params = {
        'state': 'closed',
        'created_after': '2021-03-30T10:21:24Z',
        'created_before': '2021-03-31T11:21:24Z',
    }
    mocker.patch('ProofpointThreatResponse.get_incidents_request', return_value=FETCH_RESPONSE)
    new_incidnets = get_new_incidents(request_params, last_incident_fetched)
    assert len(new_incidnets) == 14
    for incident in new_incidnets:
        assert incident.get('id') > 3057


def test_get_time_delta():
    """
     Given
     - input to the get_time_delta function which is valid and invalid
     When
     - run the get_time_delta function.
     Then
     - validate that on invalid input such as days or no units relevant errors are raised.
     - validate that on valid inputs the return value is as expected.
     """
    time_delta = get_time_delta('1 minute')
    assert str(time_delta) == '0:01:00'
    time_delta = get_time_delta('2 hours')
    assert str(time_delta) == '2:00:00'
    try:
        get_time_delta('2')
    except Exception as ex:
        assert 'The fetch_delta is invalid. Please make sure to insert both the number and the unit of the fetch delta.' in str(
            ex)
    try:
        get_time_delta('2 days')
    except Exception as ex:
        assert 'The unit of fetch_delta is invalid. Possible values are "minutes" or "hours' in str(ex)


def test_get_incident_command(mocker, requests_mock):
    """
    Given:
    - Incident ID 3064 to retrieve

    When:
    - Running get-incident command

    Then:
    - Ensure expected fields ('attachments', 'sender_vap', 'recipient_vap') are populated to the context data
    """
    base_url = 'https://server_url/'
    requests_mock.get(f'{base_url}api/incidents/3064.json', json=FETCH_RESPONSE[0])
    mocker.patch.object(demisto, 'results')
    mocker.patch('ProofpointThreatResponse.BASE_URL', base_url)
    mocker.patch.object(demisto, 'args', return_value={
        'incident_id': '3064'
    })
    get_incident_command()
    results = demisto.results.call_args[0][0]
    emails = results['EntryContext']['ProofPointTRAP.Incident(val.id === obj.id)'][0]['events'][0]['emails'][0].keys()
    assert {'attachments', 'sender_vap', 'recipient_vap'}.issubset(set(emails))


def test_get_incident_command_expand_events_false(mocker, requests_mock):
    """
    Given:
    - Incident ID 3064 to retrieve
    - The expand_events argument set to false

    When:
    - Running get-incident command

    Then:
    - Ensure events field is not returned
    - Ensure event_ids field is populated as expected
    """
    base_url = 'https://server_url/'
    with open('./test_data/incident_expand_events_false.json', 'r') as f:
        incident = json.loads(f.read())
    requests_mock.get(f'{base_url}api/incidents/3064.json?expand_events=false', json=incident)
    mocker.patch.object(demisto, 'results')
    mocker.patch('ProofpointThreatResponse.BASE_URL', base_url)
    mocker.patch.object(demisto, 'args', return_value={
        'incident_id': '3064',
        'expand_events': 'false',
    })
    get_incident_command()
    results = demisto.results.call_args[0][0]
    incident_result = results['EntryContext']['ProofPointTRAP.Incident(val.id === obj.id)'][0]
    assert not incident_result['events']
    assert incident_result['event_ids']


def test_close_incident_command(mocker, requests_mock):
    """
    Given:
    - Incident ID 3064 to close

    When:
    - Running close-incident command

    Then:
    - Ensure output is success message
    """
    base_url = 'https://server_url/'
    requests_mock.post(f'{base_url}api/incidents/3064/close.json')
    mocker.patch.object(demisto, 'results')
    mocker.patch('ProofpointThreatResponse.BASE_URL', base_url)
    mocker.patch.object(demisto, 'args', return_value={
        'incident_id': '3064',
        "summary": "summary",
        "details": "details"
    })
    close_incident_command()
    results = demisto.results.call_args[0][0]
    assert 'success' in results['HumanReadable']
