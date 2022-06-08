import io
import os
from zipfile import ZipFile
import tempfile
import json

import pytest
import re

import demistomock
from SiemApiModule import *
from MimecastEventCollector import MimecastGetSiemEvents, MimecastGetAuditEvents, MimecastOptions, MimecastClient, \
    handle_last_run_exit, handle_last_run_entrance
from test_data.test_data import WITH_OUT_DUP_TEST, WITH_DUP_TEST, EMPTY_EVENTS_LIST, FILTER_SAME_TIME_EVEMTS, \
    AUDIT_LOG_RESPONSE, AUDIT_LOG_AFTER_PROCESS

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


def test_unpacking_virtual_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f'\ntemp dir path: {tmpdir}\n')
        print(f'files in tmpdir: {os.listdir(tmpdir)}\n')
        with ZipFile('test_data/Archive.zip', 'r') as zip_ref:
            zip_ref.extractall(tmpdir)
            extracted_logs_list = []
            for file in os.listdir(tmpdir):
                with open(os.path.join(tmpdir, file)) as json_res:
                    extracted_logs_list.append(json.load(json_res))
            print(f'files after extraction {os.listdir(tmpdir)}')


def test_tmpdir():
    temp_dir = tempfile.TemporaryDirectory()
    print('\n\n', temp_dir.name)
    # use temp_dir, and when done:
    temp_dir.cleanup()


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


@pytest.mark.parametrize('lst1, lst2 ,res', [
    ([1, 2, 3], [4, 5, 6], [1, 2, 3, 4, 5, 6]),
    ([1, 2, 3], ['a', 'b'], [1, 2, 3, 'a', 'b']),
    ([], [], []),
    ([{'g': 'g'}], [5], [{'g': 'g'}, 5]),
    (['t'] , [], ['t'])
])
def test_gather_events(lst1, lst2, res):
    from MimecastEventCollector import gather_events
    assert gather_events(lst1, lst2) == res


def test_handle_last_run_entrance():
    test = demistomock.getLastRun()
    assert audit_event_handler.start_time == ''
    handle_last_run_entrance('7 days', audit_event_handler, siem_event_handler)
    assert audit_event_handler.start_time != ''


@pytest.mark.parametrize('time_to_convert, res', [('2011-12-03T10:15:30+00:00', '2011-12-03T10:15:30+0000'),
                                                  ('2011-12-03T10:15:30+03:00', '2011-12-03T10:15:30+0300')])
def test_to_audit_time_format(time_to_convert, res):
    assert audit_event_handler.to_audit_time_format(time_to_convert) == res


def test_process_siem_data():
    with open('test_data/siem_response_multiple_events.json') as f:
        siem_response = json.load(f)
    with open('test_data/siem_result_multiple_events_process.json') as f:
        res = json.load(f)

    after_process = siem_event_handler.process_siem_events(siem_response)
    assert after_process == res

