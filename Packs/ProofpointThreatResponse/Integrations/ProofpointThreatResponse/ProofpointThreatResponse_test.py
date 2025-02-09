import copy

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
                                      close_incident_command,
                                      search_quarantine, list_incidents_command, search_indicator_command)

MOCK_INCIDENT_1 = {
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
MOCK_INCIDENT_2 = copy.deepcopy(MOCK_INCIDENT_1)
MOCK_INCIDENT_2['events'][0]['emails'][0]['messageDeliveryTime'] = 'messageDeliveryTime'

INCIDENT_FIELD_CONTEXT = {
    "Attack_Vector": "Email",
    "Classification": "Spam",
    "Severity": "Critical",
    "Abuse_Disposition": "Unknown"
}

INCIDENT_FIELD_INPUT = [
    (MOCK_INCIDENT_1, INCIDENT_FIELD_CONTEXT)
]


def get_fetch_data():
    with open('./test_data/raw_response.json') as f:
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
    (MOCK_INCIDENT_1['events'][0], EMAIL_RESULT)
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
    result = pass_sources_list_filter(MOCK_INCIDENT_1, sources_list)
    assert result == expected_answer


ABUSE_DISPOSITION_INPUT = [
    (["Unknown"], True),
    ([], True),
    (["No such value"], False),
    (["No such value", "Unknown"], True)
]


@pytest.mark.parametrize('abuse_dispotion_values, expected_answer', ABUSE_DISPOSITION_INPUT)
def test_pass_abuse_disposition_filter(abuse_dispotion_values, expected_answer):
    result = pass_abuse_disposition_filter(MOCK_INCIDENT_1, abuse_dispotion_values)
    assert result == expected_answer


DEMISTO_PARAMS = [({'event_sources': "No such source, Proofpoint TAP", 'abuse_disposition': "No such value, Unknown"},
                   [MOCK_INCIDENT_1]), ({'event_sources': "", 'abuse_disposition': ""}, [MOCK_INCIDENT_1]),
                  ({'event_sources': "No such source", 'abuse_disposition': "No such value, Unknown"}, []),
                  ({'event_sources': "No such source, Proofpoint TAP", 'abuse_disposition': "No such value"}, []),
                  ({'event_sources': "No such source", 'abuse_disposition': "No such value"}, [])]


@pytest.mark.parametrize('demisto_params, expected_answer', DEMISTO_PARAMS)
def test_filter_incidents(mocker, demisto_params, expected_answer):
    mocker.patch.object(demisto, 'params', return_value=demisto_params)
    filtered_incidents = filter_incidents([MOCK_INCIDENT_1])
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
    with open('./test_data/incident_expand_events_false.json') as f:
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


def test_search_quarantine_command(mocker, requests_mock):
    """
    Given:
    - Message ID, Recipient and Delivery Time (Email recived time)

    When:
    - Running search-quarantine command

    Then:
    - Ensure output is success message (at least one success).
    """
    base_url = 'https://server_url/'
    with open('./test_data/incidents.json') as f:
        incident = json.loads(f.read())
    requests_mock.get(f'{base_url}api/incidents', json=incident)
    mocker.patch('ProofpointThreatResponse.BASE_URL', base_url)
    mocker.patch.object(demisto, 'args', return_value={
        'message_id': "<XYZ_EAbcd-@test.test.com>",
        "recipient": "sabrina.test@test.com",
        "time": "2021-03-30T11:17:39Z"
    })
    res = search_quarantine()
    quarantines_res = [x.get('quarantine').get('status') for x in res.outputs]
    assert 'successful' in quarantines_res


def test_search_quarantine_command_with_str_messageDeliveryTime(mocker, requests_mock):
    """
    Given:
    - Message ID, Recipient and Delivery Time (Email recived time)

    When:
    - Running search-quarantine command

    Then:
    - Ensure output is success message (at least one success).
    """
    base_url = 'https://server_url/'
    with open('./test_data/incident_str_messageDeliveryTime.json') as f:
        incident = json.loads(f.read())
    requests_mock.get(f'{base_url}api/incidents', json=incident)
    mocker.patch('ProofpointThreatResponse.BASE_URL', base_url)
    mocker.patch('ProofpointThreatResponse.get_incidents_batch_by_time_request', return_value=incident)

    mocker.patch.object(demisto, 'args', return_value={
        'message_id': "<ABCD1234@cpus>",
        "recipient": "sabrina.test@test.com",
        "time": "2021-03-30T11:17:39Z"
    })
    res = search_quarantine()

    assert res.outputs_prefix == '<ABCD1234@cpus> Message ID found in TRAP alerts, ' \
        'but not in the quarantine list meaning that email has not be quarantined.'


def test_list_incidents_command(mocker, requests_mock):
    """
    Given:
    - 2 Incidents in the list, with different 'messageDeliveryTime' fields

    When:
    - Running list-incidents command

    Then:
    - Ensure output generated successfully without errors.
    """
    base_url = 'https://server_url/'
    requests_mock.get(f'{base_url}api/incidents', json=[MOCK_INCIDENT_1, MOCK_INCIDENT_2])
    mocker.patch('ProofpointThreatResponse.BASE_URL', base_url)
    mocker.patch.object(demisto, 'args', return_value={'limit': 2})
    results = mocker.patch.object(demisto, 'results')
    list_incidents_command()
    incidents = results.call_args[0][0]['Contents']
    assert len(incidents) == 2


@pytest.mark.parametrize('list_id_to_search, filter_to_apply,  indicators_to_return, expected_result', [
    ('1', '1.1.1.1', [{"host": {"host": "1.1.1.1"}}, {"host": {"host": "2.2.2.2"}}], [{"host": {"host": "1.1.1.1"}}]),
    ('1', '', [{"host": {"host": "1.1.1.1"}}, {"host": {"host": "2.2.2.2"}}],
     [{"host": {"host": "1.1.1.1"}}, {"host": {"host": "2.2.2.2"}}]),
    ('1', '', [{}], []),
])
def test_search_indicator_command(mocker, requests_mock, list_id_to_search, filter_to_apply, indicators_to_return,
                                  expected_result):
    """
    Given:
        - Case A: List id = 1, and filter is 1.1.1.1
        - Case B: List id = 1, no filter is given.
        - Case C: List id = 1, no filter is given.

    When:
        - Case A: 2 indicators [1.1.1.1, 2.2.2.2] are returned from API.
        - Case B: 2 indicators [1.1.1.1, 2.2.2.2] are returned from API.
        - Case C: No indicators are returned from API.

    Then:
        - Case A: Ensure the list is filtered and only the 1.1.1.1 indicator is returned.
        - Case B: Ensure the list is not filtered and both 1.1.1.1 and 2.2.2.2 are returned.
        - Case C: Ensure the logic is working, and an empty list is returnd
    """
    base_url = 'https://server_url/'
    requests_mock.get(f'{base_url}api/lists/{list_id_to_search}/members.json', json=indicators_to_return)
    mocker.patch('ProofpointThreatResponse.BASE_URL', base_url)
    mocker.patch.object(demisto, 'args', return_value={'list-id': list_id_to_search, 'filter': filter_to_apply})
    results = mocker.patch.object(demisto, 'results')
    search_indicator_command()
    indicators = results.call_args[0][0]['indicators']
    assert indicators == expected_result


def test_search_quarantine_command_mismatch_time(mocker, requests_mock):
    """
    Given:
    - Message ID, Recipient and Delivery Time (Email recived time)

    When:
    - Running search-quarantine command

    Then:
    - test fails on time mismatch
    """
    base_url = 'https://server_url/'
    with open('./test_data/incident_str_messageDeliveryTime.json') as f:
        incident = json.loads(f.read())
    requests_mock.get(f'{base_url}api/incidents', json=incident)
    mocker.patch('ProofpointThreatResponse.BASE_URL', base_url)
    mocker.patch('ProofpointThreatResponse.get_incidents_batch_by_time_request', return_value=incident)

    mocker.patch.object(demisto, 'args', return_value={
        'message_id': "<ABCD1234@cpus>",
        "recipient": "sabrina.test@test.com",
        "time": "2021-04-30T11:17:39Z"
    })
    res = search_quarantine()

    assert res.readable_output == ("<ABCD1234@cpus> Message ID found in TRAP alerts, but timestamp between email delivery time "
                                    "and time given as argument doesn't match")
    

def test_search_quarantine_command_with_incident_far_from_alert_time_fail(mocker, requests_mock):
    """
    Given:
    - Message ID, Recipient and Delivery Time (Email recived time)

    When:
    - Running search-quarantine command

    Then:
    - test fails on time mismatch
    """
    base_url = 'https://server_url/'
    with open('./test_data/incident_email_manually_quarantined.json') as f:
        incident = json.loads(f.read())
    requests_mock.get(f'{base_url}api/incidents', json=incident)
    mocker.patch('ProofpointThreatResponse.BASE_URL', base_url)
    mocker.patch('ProofpointThreatResponse.get_incidents_batch_by_time_request', return_value=incident)

    mocker.patch.object(demisto, 'args', return_value={
        'message_id': "<ABCD1234@cpus>",
        "recipient": "sabrina.test@test.com",
        "time": "2021-04-30T11:17:39Z"
    })
    res = search_quarantine()

    assert res.readable_output == ('<ABCD1234@cpus> Message ID matches to 1 emails quarantined, but time between alert received '
                                   'and the quarantine starting exceeded the quarantine_limit provided')


def test_search_quarantine_command_with_incident_far_from_alert_time_succeed(mocker, requests_mock):
    """
    Given:
    - Message ID, Recipient and Delivery Time (Email recived time)

    When:
    - Running search-quarantine command

    Then:
    - test succeed
    """
    base_url = 'https://server_url/'
    with open('./test_data/incident_email_manually_quarantined.json') as f:
        incident = json.loads(f.read())
    requests_mock.get(f'{base_url}api/incidents', json=incident)
    mocker.patch('ProofpointThreatResponse.BASE_URL', base_url)
    mocker.patch('ProofpointThreatResponse.get_incidents_batch_by_time_request', return_value=incident)

    mocker.patch.object(demisto, 'args', return_value={
        'message_id': "<ABCD1234@cpus>",
        "recipient": "sabrina.test@test.com",
        "time": "2021-04-30T11:17:39Z",
        "quarantine_limit": "2665996"
        
    })
    res = search_quarantine()

    assert res.readable_output == ("### Quarantine Result\n|alert|incident|quarantine|\n|---|---|---|\n| id: 9225<br>time: "
                                   "2021-03-30T11:44:24Z | id: 3065<br>time: 2021-03-30T11:44:24Z | messageId: <ABCD1234@cpu"
                                   "s><br>recipient: sabrina.test@test.com<br>startTime: 2021-04-30T08:17:39Z |\n")