import pytest  # noqa: N999
from SiemApiModule import *  # noqa # pylint: disable=unused-wildcard-import


from Packs.Mimecast.Integrations.MimecastEventCollector.MimecastEventCollector import *
from Packs.Mimecast.Integrations.MimecastEventCollector.test_data.data import WITH_OUT_DUP_TEST, WITH_DUP_TEST, \
    EMPTY_EVENTS_LIST, FILTER_SAME_TIME_EVEMTS, AUDIT_LOG_RESPONSE, AUDIT_LOG_AFTER_PROCESS, \
    SIEM_LOG_PROCESS_EVENT, SIEM_RESULT_MULTIPLE_EVENTS_PROCESS, SIEM_RESPONSE_MULTIPLE_EVENTS

mimecast_options = MimecastOptions(**{
    'app_id': "XXX",
    'app_key': "XXX",
    'uri': "/api/audit/get-siem-logs",
    'email_address': 'XXX.mime.integration.com',
    'access_key': 'XXX',
    'secret_key': 'XXX',
    'after': '7 days',
    'base_url': 'https://us-api.mimecast.com',
    'verify': False
})

empty_first_request = IntegrationHTTPRequest(method=Method.GET, url='http://bla.com', headers={})
client = MimecastClient(empty_first_request, mimecast_options)
siem_event_handler = MimecastGetSiemEvents(client, mimecast_options)
audit_event_handler = MimecastGetAuditEvents(client, mimecast_options)


def test_handle_last_run_entrance(mocker):
    mocker.patch.object(demisto, 'getLastRun', return_value={})
    local_siem_event_handler = MimecastGetSiemEvents(client, mimecast_options)
    assert audit_event_handler.start_time == ''
    handle_last_run_entrance('7 days', audit_event_handler, local_siem_event_handler)
    assert audit_event_handler.start_time != ''
    assert local_siem_event_handler.token == ''
    assert local_siem_event_handler.events_from_prev_run == []


def test_process_audit_data():
    """
    Given:
        - a dict representing the Resopnse.text of the audit event
    When:
        - processing the audit log
    Then:
        - collect all the events in the data section, add a xsiem_classifier, and set page_token for next run if exists
    """
    assert audit_event_handler.process_audit_response(AUDIT_LOG_RESPONSE) == AUDIT_LOG_AFTER_PROCESS
    assert audit_event_handler.page_token == '1234'


@pytest.mark.parametrize('audit_response, res',
                         [(FILTER_SAME_TIME_EVEMTS.get('audit_response'), FILTER_SAME_TIME_EVEMTS.get('res'))])
def test_filter_same_time_events(audit_response, res):
    time = "2022-05-31T12:50:33+0000"
    data = audit_response.get('data', [])
    same_time_events = []
    for event in data:
        if event.get('eventTime', '') == time:
            same_time_events.append(event)
    assert same_time_events == res


@pytest.mark.parametrize('audit_events, last_run_potential_dup, res', [
    (WITH_OUT_DUP_TEST.get('audit_events'), WITH_OUT_DUP_TEST.get('last_run_potential_dup'),
     WITH_OUT_DUP_TEST.get('audit_events')),
    (WITH_DUP_TEST.get('audit_events'), WITH_DUP_TEST.get('last_run_potential_dup'), WITH_DUP_TEST.get('res')),
    (EMPTY_EVENTS_LIST.get('audit_events'), EMPTY_EVENTS_LIST.get('last_run_potential_dup'),
     EMPTY_EVENTS_LIST.get('res'))
])
def test_dedup_audit_events(audit_events, last_run_potential_dup, res):
    assert dedup_audit_events(audit_events, last_run_potential_dup) == res


def test_handle_last_run_entrance_with_prev_run(mocker):
    """
    Given:
        - A non empty last run object.

    When:
        - We enter the MimecastEventCollector main

    Then:
        - check that the fields of the last run are passed correctly to the event handler objects.
    """
    mocker.patch.object(demisto, 'getLastRun', return_value={SIEM_LAST_RUN: 'token1',
                                                             SIEM_EVENTS_FROM_LAST_RUN: ['event1', 'event2'],
                                                             AUDIT_EVENT_DEDUP_LIST: ['id1', 'id2'],
                                                             AUDIT_LAST_RUN: '2011-12-03T10:15:30+0000'},
                        )
    handle_last_run_entrance('3 days', audit_event_handler, siem_event_handler)
    assert siem_event_handler.token == 'token1'
    assert siem_event_handler.events_from_prev_run == ['event1', 'event2']
    assert audit_event_handler.start_time == '2011-12-03T10:15:30+0000'


@pytest.mark.parametrize('time_to_convert, res', [('2011-12-03T10:15:30+00:00', '2011-12-03T10:15:30+0000'),
                                                  ('2011-12-03T10:15:30+03:00', '2011-12-03T10:15:30+0300')])
def test_to_audit_time_format(time_to_convert, res):
    """
    Given:
        - An iso 8601 time format

    When:
        - Before Sending the request to the audit events end point

    Then:
        - Convert the time format to fit the mimecast API format
    """
    assert audit_event_handler.to_audit_time_format(time_to_convert) == res


def test_process_siem_data():
    """
    Given:
        - The Siem response after calling the mimecast api

    When:
        - We process the response

    Then:
        - Return a flattened event list with some additional info data
    """
    after_process = siem_event_handler.process_siem_events(SIEM_RESPONSE_MULTIPLE_EVENTS)
    assert after_process == SIEM_RESULT_MULTIPLE_EVENTS_PROCESS


@pytest.mark.parametrize('event, res',
                         [({'IP': '1.2.3.4', 'Dir': 'Outbound', 'Rcpt': 'bla'},
                           {'IP': ['1.2.3.4'], 'Dir': 'Outbound', 'Rcpt': ['bla']}),
                          ({'a': 'b', 'c': 'd'}, {'a': 'b', 'c': 'd'}),
                          ({'Rcpt': ['bla']}, {'Rcpt': ['bla']}),
                          ({}, {})])
def test_convert_field_to_xdm_type(event, res):
    """
    Given:
        - A siem event with
    When:
        - one of the fields in the event dict is 'IP', 'SourceIP', 'Recipient'
    Then:
        - convert the specified fields to be of type list and do not modify the other fields
    """
    event_handler = MimecastGetSiemEvents(client, mimecast_options)
    event_handler.convert_field_to_xdm_type(event)
    assert event == res


@pytest.mark.parametrize('audit_event_list, audit_next_run, res', [(
    [{'eventTime': '2022-05-29T10:43:25+0000', 'id': '234'}], '2022-05-29T10:43:25+0000', ['234']),
    ([{'eventTime': '2022-05-29T10:43:25+0000', 'id': '234'}], '', []),
    ([], '2022-05-29T10:43:25+0000', []),
    ([{'eventTime': '2022-05-29T10:43:25+0000', 'id': '234'}, {'eventTime': '2022-05-29T10:43:25+0000', 'id': '567'},
      {'eventTime': '2022-04-29T10:43:25+0000', 'id': '888'}],
     '2022-05-29T10:43:25+0000', ['234', '567'])])
def test_prepare_potential_audit_duplicates_for_next_run(audit_event_list, audit_next_run, res):
    """
    Given:
        - A list of audit events s.t. the latest events are in the start of the list, an audit next run
    When:
        - Preparing the duplicates list for next run if events would be brought twice
    Then:
        - return a list with the Id of all the events that happened at the same time like audit_next_run
    """
    assert prepare_potential_audit_duplicates_for_next_run(audit_event_list, audit_next_run) == res


def test_process_siem_events():
    """
    Given:
        - a siem log response after it was extracted as json
    When:
        - The siem log is bieng processed
    Then:
        - return a flat list with all the information.
        (some fields my convert to a list in the convert_field_to_xdm_type method)
    """
    for test_case in SIEM_LOG_PROCESS_EVENT:
        siem_response = test_case.get('siem_data_response')
        after_process = test_case.get('after_process')
        assert siem_event_handler.process_siem_events(siem_response) == after_process


@pytest.mark.parametrize('audit_events, res', [([{'eventTime': '1'}, {'eventTime': '2'}, {'eventTime': '3'}], '1'),
                                               ([], '')])
def test_set_audit_next_run(audit_events, res):
    assert set_audit_next_run(audit_events) == res


def test_siem_custom_run(mocker):
    """
    Given:
         - A list of events_from_prev_run
    When:
        - The events_from_prev_run is bigger the SIEM_LOG_LIMIT
    Then:
        - assert that the stored returned are the events from last run and that the events_from_prev_run has been modified
    """
    mock_events_from_prev_run: list = list(range(500))
    mocker.patch.object(MimecastGetSiemEvents, '_iter_events', return_value=[])
    siem_event_handler.events_from_prev_run = mock_events_from_prev_run
    assert siem_event_handler.run() == mock_events_from_prev_run
    assert siem_event_handler.events_from_prev_run == []


def test_siem_custom_run2(mocker):
    """
    Given:
        - A list of events from last run
    When:
        - calling the run function
    Then:
        - Verify all the events from prev run are stored correctly.
    """
    mocker.patch.object(MimecastGetSiemEvents, '_iter_events', return_value=[])
    mock_events_from_prev_run: list = list(range(200))
    siem_event_handler.events_from_prev_run = mock_events_from_prev_run
    assert siem_event_handler.run() == mock_events_from_prev_run[:SIEM_LOG_LIMIT]
    assert siem_event_handler.events_from_prev_run == []


def test_siem_custom_run3(mocker):
    """
    Given:
        - A list of events from last run
    When:
        - The events_from_prev_run is smaller then SIEM_LOG_LIMIT and events are returned from iter events
    Then:
        - Check the events are stored correctly
    """
    # This is a list of list so the iter_events loop will take into acount as one batch of events.
    iter_events_mock_return_val = [list(range(600, 900))]
    mocker.patch.object(MimecastGetSiemEvents, '_iter_events', return_value=iter_events_mock_return_val)
    events_from_prev_run = list(range(200))
    siem_event_handler.events_from_prev_run = events_from_prev_run

    stored = siem_event_handler.run()

    assert stored == events_from_prev_run + iter_events_mock_return_val[0]
    assert siem_event_handler.events_from_prev_run == []


def test_prepare_siem_request_body():
    siem_event_handler.token = ''
    post_body = {'data': [{'type': 'MTA', 'compress': True, 'fileFormat': 'json'}]}
    assert json.dumps(post_body) == siem_event_handler.prepare_siem_request_body()

    siem_event_handler.token = '1234'
    post_body = {'data': [{'type': 'MTA', 'compress': True, 'fileFormat': 'json', 'token': '1234'}]}
    assert json.dumps(post_body) == siem_event_handler.prepare_siem_request_body()


def test_audit_events_next_run_with_new_events():
    """
    Given:
        - Audit event with new events
    When:
        - handling the new events and preparing data for next run.
    Then:
        - Verify De dup event list, next run time, potential duplicate events list.
    """
    last_run_object = {
        SIEM_LAST_RUN: "",
        SIEM_EVENTS_FROM_LAST_RUN: [],
        AUDIT_EVENT_DEDUP_LIST: ["1"],
        AUDIT_LAST_RUN: "2011-12-03T10:15:30+0000",
    }
    audit_events = [
        {"eventTime": "2011-12-03T10:15:32+0000", "id": "4"},
        {"eventTime": "2011-12-03T10:15:31+0000", "id": "3"},
        {"eventTime": "2011-12-03T10:15:30+0000", "id": "1"},
    ]
    res_audit_events = [
        {"eventTime": "2011-12-03T10:15:32+0000", "id": "4"},
        {"eventTime": "2011-12-03T10:15:31+0000", "id": "3"},
    ]

    res_potential_duplicate_events = ['4']
    audit_event_handler = MimecastGetAuditEvents(client, mimecast_options)

    audit_events, audit_next_run, duplicates_audit = audit_events_last_run(
        audit_event_handler, audit_events, last_run_object
    )
    assert duplicates_audit == res_potential_duplicate_events
    assert audit_events == res_audit_events
    assert audit_next_run == "2011-12-03T10:15:32+0000"


def test_audit_events_next_run_without_new_events():
    """
    Given:
        - Audit event with no new events.
    When:
        - handling the audit events.
    Then:
        - Verify De dup event list, next run time, potential duplicate events list.
    """
    last_run_object = {
        SIEM_LAST_RUN: "",
        SIEM_EVENTS_FROM_LAST_RUN: [],
        AUDIT_EVENT_DEDUP_LIST: ["1"],
        AUDIT_LAST_RUN: "2011-12-03T10:15:30+0000",
    }
    audit_events = [
        {"eventTime": "2011-12-03T10:15:30+0000", "id": "1"},
    ]
    res_audit_events = []
    res_potential_duplicate_events = []
    audit_event_handler = MimecastGetAuditEvents(client, mimecast_options)
    audit_event_handler.end_time = '2024-24-24T00:00:00+0000'

    audit_events, audit_next_run, duplicates_audit = audit_events_last_run(
        audit_event_handler, audit_events, last_run_object
    )
    assert duplicates_audit == res_potential_duplicate_events
    assert audit_events == res_audit_events
    assert audit_next_run == '2024-24-24T00:00:00+0000'


def test_siem_events_last_run_with_new_events():
    last_run_object = {
        SIEM_LAST_RUN: "token2",
        SIEM_EVENTS_FROM_LAST_RUN: [],
        AUDIT_EVENT_DEDUP_LIST: [],
        AUDIT_LAST_RUN: "",
    }
    siem_event_handler = MimecastGetSiemEvents(client, mimecast_options)
    siem_event_handler.token = 'token99'
    siem_event_handler.events_from_prev_run = ['evnet1', 'event2']
    siem_next_run = siem_events_last_run(siem_event_handler, last_run_object)

    # When the token is set on the current run, use the new token.
    assert siem_next_run == 'token99'


def test_siem_events_last_run_without_new_events():
    last_run_object = {
        SIEM_LAST_RUN: "token2",
        SIEM_EVENTS_FROM_LAST_RUN: ['siem_event1'],
        AUDIT_EVENT_DEDUP_LIST: [],
        AUDIT_LAST_RUN: "2011-12-03T10:15:30+0000",
    }
    siem_event_handler = MimecastGetSiemEvents(client, mimecast_options)
    siem_event_handler.events_from_prev_run = []
    siem_next_run = siem_events_last_run(siem_event_handler, last_run_object)

    # When no new events arrive use the previous token set on the past run.
    assert siem_next_run == 'token2'
