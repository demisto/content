import pytest
import demistomock  # noqa # pylint: disable=unused-wildcard-import
from SiemApiModule import *  # noqa # pylint: disable=unused-wildcard-import

from MimecastEventCollector import *
from test_data.test_data import WITH_OUT_DUP_TEST, WITH_DUP_TEST, EMPTY_EVENTS_LIST, FILTER_SAME_TIME_EVEMTS, \
    AUDIT_LOG_RESPONSE, AUDIT_LOG_AFTER_PROCESS, SIEM_LOG_PROCESS_EVENT, SIEM_RESULT_MULTIPLE_EVENTS_PROCESS, \
    SIEM_RESPONSE_MULTIPLE_EVENTS

mimecast_options = MimecastOptions(**{
    'app_id': "XXX",
    'app_key': "XXX",
    'uri': "/api/audit/get-siem-logs",
    'email_address': 'XXX.mime.integration.com',
    'access_key': 'XXX',
    'secret_key': 'XXX',
    'after': '7 days',
    'base_url': 'https://us-api.mimecast.com'
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
    assert AUDIT_LOG_AFTER_PROCESS == audit_event_handler.process_audit_response(AUDIT_LOG_RESPONSE)
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
    from MimecastEventCollector import dedup_audit_events
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


def test_handle_last_run_exit_with_values(mocker):
    """
    Given:
        - events have been fetched this run and changes have been (need to update LastRun)
    When:
        - calling handle_last_run_exit to set the LastRun object for next run
    Then:
        check that the SetLastRun is set (called) with the correct values.
    """
    mocker.patch.object(demisto, 'getLastRun', return_value={SIEM_LAST_RUN: 'token1',
                                                             SIEM_EVENTS_FROM_LAST_RUN: ['event1', 'event2'],
                                                             AUDIT_EVENT_DEDUP_LIST: ['id1', 'id2'],
                                                             AUDIT_LAST_RUN: '2011-12-03T10:15:30+0000'},
                        )
    mocker.patch('MimecastEventCollector.dedup_audit_events', return_value=[])
    mocker.patch('MimecastEventCollector.prepare_potential_audit_duplicates_for_next_run', return_value=['id3', 'id4'])
    mocker.patch('MimecastEventCollector.set_audit_next_run', return_value='2525')
    local_siem_event_handler = MimecastGetSiemEvents(client, mimecast_options)
    local_siem_event_handler.token = 'new token'
    local_siem_event_handler.events_from_prev_run = ['event3', 'event4']

    next_run_obj = handle_last_run_exit(local_siem_event_handler, ['audit event1', 'audit event2', 'audit event3'])

    assert {SIEM_LAST_RUN: 'new token',
            SIEM_EVENTS_FROM_LAST_RUN: ['event3', 'event4'],
            AUDIT_LAST_RUN: '2525',
            AUDIT_EVENT_DEDUP_LIST: ['id3', 'id4']} == next_run_obj


def test_handle_last_run_exit_without_values(mocker):
    """
    Given:
        - The last run object does not need to change after this run
    When:
        - calling handle_last_run_exit to set the LastRun object for next run
    Then:
        - check that the SetLastRun is set (called) with the correct values.
    """
    mocker.patch.object(demisto, 'getLastRun', return_value={SIEM_LAST_RUN: 'token1',
                                                             SIEM_EVENTS_FROM_LAST_RUN: ['event1', 'event2'],
                                                             AUDIT_EVENT_DEDUP_LIST: ['id1', 'id2'],
                                                             AUDIT_LAST_RUN: '2011-12-03T10:15:30+0000'},
                        )
    audit_event_list = ['audit event1', 'audit event2', 'audit event3']
    mocker.patch('MimecastEventCollector.dedup_audit_events', return_value=audit_event_list)
    mocker.patch('MimecastEventCollector.prepare_potential_audit_duplicates_for_next_run', return_value=[])
    mocker.patch('MimecastEventCollector.set_audit_next_run', return_value='')
    local_siem_event_handler = MimecastGetSiemEvents(client, mimecast_options)

    next_run_obj = handle_last_run_exit(local_siem_event_handler, audit_event_list)

    assert {SIEM_LAST_RUN: 'token1',
            SIEM_EVENTS_FROM_LAST_RUN: ['event1', 'event2'],
            AUDIT_LAST_RUN: '2011-12-03T10:15:30+0000',
            AUDIT_EVENT_DEDUP_LIST: ['id1', 'id2']} == next_run_obj


def test_siem_custom_run():
    """
    Given:
         - A list of events_from_prev_run
    When:
        - The events_from_prev_run is bigger the SIEM_LOG_LIMIT
    Then:
        - assert that the stored returned are the events from last run and that the events_from_prev_run has been modified
    """
    mock_events_from_prev_run: list = [i for i in range(500)]
    siem_event_handler.events_from_prev_run = mock_events_from_prev_run
    assert siem_event_handler.run() == mock_events_from_prev_run[:SIEM_LOG_LIMIT]
    assert siem_event_handler.events_from_prev_run == mock_events_from_prev_run[SIEM_LOG_LIMIT:]


def test_siem_custom_run2(mocker):
    """
    Given:
        - A list of events from last run
    When:
        - The events_from_prev_run is smaller than SIEM_LOG_LIMIT
    Then:
        - Checke the events are stored correctly
    """
    mocker.patch.object(MimecastGetSiemEvents, '_iter_events', return_value=[])
    mock_events_from_prev_run: list = [i for i in range(200)]
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
    iter_events_mock_return_val = [[i for i in range(600, 900)]]
    mocker.patch.object(MimecastGetSiemEvents, '_iter_events', return_value=iter_events_mock_return_val)
    mock_events_from_prev_run: list = [i for i in range(200)]
    siem_event_handler.events_from_prev_run = mock_events_from_prev_run.copy()

    stored = siem_event_handler.run()

    len_from_last_run = len(mock_events_from_prev_run)
    len_from_iter_events = SIEM_LOG_LIMIT - len_from_last_run

    assert stored == mock_events_from_prev_run + iter_events_mock_return_val[0][:len_from_iter_events]
    assert siem_event_handler.events_from_prev_run == iter_events_mock_return_val[0][len_from_iter_events:]


def test_prepare_siem_request_body():
    siem_event_handler.token = ''
    post_body = {'data': [{'type': 'MTA', 'compress': True, 'fileFormat': 'json'}]}
    assert json.dumps(post_body) == siem_event_handler.prepare_siem_request_body()

    siem_event_handler.token = '1234'
    post_body = {'data': [{'type': 'MTA', 'compress': True, 'fileFormat': 'json', 'token': '1234'}]}
    assert json.dumps(post_body) == siem_event_handler.prepare_siem_request_body()
