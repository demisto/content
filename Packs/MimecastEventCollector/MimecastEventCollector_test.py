import io
import os
from zipfile import ZipFile
import tempfile
import json

import pytest
import re

from test_data.test_data import WITH_OUT_DUP_TEST, WITH_DUP_TEST, EMPTY_EVENTS_LIST, FILTER_SAME_TIME_EVEMTS


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
    with open('test_data/audit_logs.json') as f:
        data = json.load(f).get('data', [])
        event_list = []
        for event in data:
            event_list.append(event)
        print(event_list)


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
